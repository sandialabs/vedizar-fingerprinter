"""Runs Grassmarlin fingerprinting againts packet-* data in Elasticsearch
   And then writes results back into elasticsearch
"""

import argparse
import traceback
import datetime
import json
import logging
import multiprocessing as mp
import os
import pathlib
import subprocess
import time
from glob import glob
from time import sleep

from elasticsearch import Elasticsearch

import config
from dhcp import run_dhcp_fingerprinting
from gm_fingerprinting import (
    get_edges,
    get_unique_filters,
    load_lookup_tables,
    run_gm_fingerprinting,
)
from smb import run_browser_fingerprinting

DOCS_TO_INDEX = []


logging.basicConfig(level=logging.INFO)


def main():
    """Runs fingperints over pcaps in a given directory"""
    parser = argparse.ArgumentParser(
        description="Reads in pcaps "
        "and extracts fingerprints, which get saved back into Elasticsearch."
    )
    parser.add_argument(
        "--pcapdir",
        type=str,
        default=config.PCAP_DIR,
        help=f"directory to read pcaps from. default is {config.PCAP_DIR}",
    )
    parser.add_argument(
        "--fingerprintidx",
        type=str,
        default=config.INDEX,
        help=f"index to write fingerprints back to. Default is {config.INDEX}",
    )
    parser.add_argument(
        "--period",
        type=int,
        default=300,
        help="time (in seconds) to sleep between runs. "
        + "Set to -1 to run once and exit. Default is 300 seconds.",
    )
    parser.add_argument(
        "-n",
        "--njobs",
        default=3,
        type=int,
        help="Number of parallel processes to use. -1 mean use all available CPU's. Default is 3.",
    )
    parser.add_argument(
        "--es-url",
        default="http://localhost:9200",
        type=str,
        help="Elasticsearch URL for writing back fingerprints. default is http://localhost:9200",
    )
    parser.add_argument(
        "--hostname",
        action="store_true",
        default=False,
        help="run hostname fingerprinting",
    )
    parser.add_argument(
        "--grassmarlin",
        action="store_true",
        default=False,
        help="run grassmarlin library fingerprinting",
    )
    args = parser.parse_args()
    config.PCAP_DIR = args.pcapdir
    config.INDEX = args.fingerprintidx
    config.ES_CLIENT = Elasticsearch(args.es_url, request_timeout=60)

    # wait for ES ready
    healthy = False
    while not healthy:
        health = config.ES_CLIENT.health_report().body["status"]
        if health in ["green", "yellow"]:
            healthy = True
        else:
            print("ES not ready yet. waiting...")
            sleep(5)
    # grab all fingerprint files
    files = glob(f"{config.SCRIPT_DIR}/grassmarlin/GM3/data/fingerprint/json/*.json")

    logging.info(files)
    # deduplicate filters to minimize the amount
    # of times we have to parse the pcap files
    unique_filters = get_unique_filters(files)

    logging.info("Starting fingerprinting on all current data...")
    load_lookup_tables()

    while True:
        logging.info("Running on any new data...")
        pcaps = glob(f"{config.PCAP_DIR}/**/*.pcap", recursive=True)
        pcaps.extend(glob(f"{config.PCAP_DIR}/**/*.pcapng", recursive=True))

        if not os.path.exists(f"{config.PCAP_DIR}/{config.STATE_FILE}"):
            with open(
                f"{config.PCAP_DIR}/{config.STATE_FILE}", "w", encoding="utf8"
            ) as already_ingested_file:
                # we just want to create the file and the move on
                pass

        # get set of already ingested files
        with open(
            f"{config.PCAP_DIR}/{config.STATE_FILE}", "r", encoding="utf8"
        ) as already_ingested_file:
            already_ingested = already_ingested_file.readlines()
            already_ingested = [l.strip() for l in already_ingested]

        # get list of files we still need to ingest
        to_ingest = list(set(pcaps) - set(already_ingested))

        for pcap in to_ingest:
            start = time.time()
            pcap = str(pathlib.Path(pcap).resolve())
            logging.info(pcap)
            # get which subfolders this pcap was in so we can use it as a tag
            # but don't include any root folders
            root_folders = [
                p.name for p in pathlib.Path(config.PCAP_DIR).resolve().parents
            ]
            folders = [p.name for p in pathlib.Path(pcap).resolve().parents]
            subfolders = folders[: -len(root_folders) - 1]
            pcap_name = pathlib.Path(pcap).name
            try:
                # get timestamp of first packet as the timestamp of the pcap
                proc = subprocess.run(
                    ["tshark", "-r", pcap, "-Tek", "-c", "1"],
                    check=True,
                    capture_output=True,
                    encoding="utf8",
                )
                # -Tek output for 1 packet will be 2 json lines
                # but we don't need the first
                first_packet = json.loads(proc.stdout.split("\n")[1])
                pcap_date = datetime.datetime.fromtimestamp(
                    int(first_packet["timestamp"]) / 1000
                )
            except (IndexError, subprocess.CalledProcessError):
                logging.warning(traceback.format_exc())
                logging.warning("skipping %s, it appears to be emtpy.", pcap)
                with open(
                    f"{config.PCAP_DIR}/{config.STATE_FILE}", "a", encoding="utf8"
                ) as already_ingested_file:
                    already_ingested_file.write(pcap)
                    already_ingested_file.write("\n")
                continue

            # read non-sync packets into memory
            tcpdump_cmd = [
                "tcpdump",
                "-r",
                pcap,
                "-w",
                "-",
                "(!tcp || ((tcp[tcpflags]&0x6) == 0))",
            ]

            try:
                proc = subprocess.run(tcpdump_cmd, capture_output=True, check=True)
            except subprocess.CalledProcessError:
                logging.warning(proc.stderr)
                logging.warning(proc.stdout)
                logging.warning(traceback.format_exc())
                logging.warning("%s could not be parsed, skipping...", pcap)
                with open(
                    f"{config.PCAP_DIR}/{config.STATE_FILE}", "a", encoding="utf8"
                ) as already_ingested_file:
                    already_ingested_file.write(pcap)
                    already_ingested_file.write("\n")
                continue

            # put pcap data in shared memory for parallel reading in multiple processing
            config.SHARED_PCAP_DATA = mp.Array("c", proc.stdout, lock=False)
            if len(config.SHARED_PCAP_DATA) > 0:
                with mp.Pool(args.njobs) as mp_pool:
                    shared_filtered_data = dict()

                    procs = []

                    if args.hostname:
                        procs.append(
                            mp_pool.apply_async(
                                run_browser_fingerprinting,
                                (pcap_name, pcap_date, subfolders),
                            )
                        )
                        procs.append(
                            mp_pool.apply_async(
                                run_dhcp_fingerprinting,
                                (pcap_name, pcap_date, subfolders),
                            )
                        )

                    if args.grassmarlin:
                        # run grassmarlin fingerprint library in parallel
                        get_edge_args = [(v, k[1]) for k, v in unique_filters.items()]
                        edge_proc = mp_pool.starmap_async(get_edges, get_edge_args, 1)

                        # poll other processes and exit early if they failed
                        while not edge_proc.ready():
                            for proc in procs:
                                if proc.ready():
                                    proc.get()
                        edge_sets = edge_proc.get()
                        for edge_filter, edge_list in edge_sets:
                            shared_filtered_data[edge_filter] = edge_list

                        procs.append(
                            mp_pool.starmap_async(
                                run_gm_fingerprinting,
                                (
                                    (
                                        file,
                                        pcap_name,
                                        pcap_date,
                                        shared_filtered_data,
                                        subfolders,
                                    )
                                    for file in files
                                ),
                                10,
                            )
                        )
                    # poll all processes and exit early if any of them fail
                    while not all([p.ready() for p in procs]):
                        for p in procs:
                            if p.ready():
                                p.get()

            with open(
                f"{config.PCAP_DIR}/{config.STATE_FILE}", "a", encoding="utf8"
            ) as already_ingested_file:
                already_ingested_file.write(pcap)
                already_ingested_file.write("\n")
            logging.info("Took %s seconds to run.", time.time() - start)
        logging.info("Fingerprinting done.")
        if args.period == -1:
            return
        sleep(args.period)


if __name__ == "__main__":
    main()
