"""Runs Grassmarlin fingerprinting againts packet-* data in Elasticsearch
   And then writes results back into elasticsearch
"""
import datetime
from hashlib import md5
import logging
import subprocess
import time
import csv
import os
import argparse
from time import sleep
from pathlib import Path
from collections import OrderedDict
from glob import glob
from copy import deepcopy
import json
import binascii
import struct
import re
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk, BulkIndexError
from elasticsearch_dsl import Q, A, Search


es = Elasticsearch(
    hosts=[os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")], timeout=60
)
SCRIPT_DIR = Path(__file__).parents[0]
INDEX = os.environ.get("FINGERPRINT_IDX", "fingerprints")
PCAP_DIR = "/opt/pcaps/"
STATE_FILE = "gm_fingerprints_ingested"
logging.basicConfig(level=logging.WARNING)
DOCS_TO_INDEX = []

BACNET_LOOKUP = {}
ENIP_VENDOR_LOOKUP = {}
ENIP_DEVICE_LOOKUP = {}


def load_lookup_tables():
    """Load lookup data from csv files"""
    with open(f"{SCRIPT_DIR}/BACnetVendors.csv", encoding="utf8") as lookups:
        reader = csv.reader(lookups)
        _ = next(reader)
        for row in reader:
            BACNET_LOOKUP[int(row[0])] = row[1]
    with open(f"{SCRIPT_DIR}/enipDevice.csv", encoding="utf8") as lookups:
        reader = csv.reader(lookups)
        _ = next(reader)
        for row in reader:
            ENIP_DEVICE_LOOKUP[int(row[0])] = row[1]
    with open(f"{SCRIPT_DIR}/enipVendors.csv", encoding="utf8") as lookups:
        reader = csv.reader(lookups)
        _ = next(reader)
        for row in reader:
            ENIP_VENDOR_LOOKUP[int(row[0])] = row[1]


def get_position(payload: bytes, position: str, cursor: dict) -> int:
    """returns absolute position in payload relative to position
    keyword or value and cursor
    """
    if position == "START_OF_PAYLOAD":
        return 0
    if position == "END_OF_PAYLOAD":
        return len(payload)
    if position == "CURSOR_START":
        return cursor["START"]
    if position == "CURSOR_MAIN":
        return cursor["MAIN"]
    if position == "CURSOR_END":
        return cursor["END"]

    return int(position)


# translations from fingerprint field names to ECS field names
field_mappings = {
    "OS": ["host", "os", "name"],
    "id": ["host", "id"],
    "Windows Version": ["host", "os", "version"],
    "Host Name": ["host", "name"],
    "Category": ["host", "role"],
    "Product": ["host", "description", "product"],
    "Role": ["host", "role"],
    "Protocol": ["host", "service", "protocol"],
    "Service": ["host", "role"],
    "ICSProtocol": ["host", "service", "protocol"],
    "ICSCommand": ["host", "service", "protocol"],
    "DiscoveryProtocol": ["host", "service", "protocol"],
    "device_class": ["host", "role"],
    "Microsoft Server Product": ["host", "description", "product"],
    "Micosoft Server Product": ["host", "description", "product"],
    "Micrsoft Server Product": ["host", "description", "product"],
    "WonderwareProtocol": ["host", "service", "protocol"],
    "MicrosoftProtocol": ["host", "service", "protocol"],
    "S7Communication": ["host", "service", "protocol"],
    "Authentication": ["host", "service", "protocol"],
    "Unit": ["host", "description", "modbus_unit"],
    "Rockwell": ["host", "service", "protocol"],
    "Siemens": ["host", "service", "protocol"],
    "Domain/Workgroup": ["host", "domain"],
    "ENIP Device Type": ["host", "description", "type"],
    "ENIP Vendor": ["host", "description", "vendor"],
    "ENIP Product Code": ["host", "description", "product"],
    "ENIP Serial Number": ["host", "description", "serialnum"],
    "InternetStandardProtocol": ["host", "service", "protocol"],
    "Message Protocol": ["host", "service", "protocol"],
    "Name Resolution Protocol": ["host", "service", "protocol"],
    "Model": ["host", "description", "model"],
    "RequestID": ["host", "description", "snmp_request_id"],
    "CommunityID": ["host", "description", "snmp_community_id"],
}

# pylint: disable=too-many-arguments


def process_return(
    ret_content: dict, payload: bytes, src: str, dest: str, cursor: dict, fpname: str
):
    """
    handle return block in fingerprint payload
    Writes results to ES
    """
    global DOCS_TO_INDEX
    source_or_dest = ret_content.get("@Direction", "SOURCE")
    # confidence = ret_content.get("@Confidence", None)
    enrichment = deepcopy(ret_content.get("Details", {}))
    if "Detail" in enrichment.keys():
        detail = enrichment.pop("Detail")
        enrichment[detail["@Name"]] = detail["#text"]
        logging.debug(enrichment)

    if "Extract" in ret_content.keys() and payload:
        extract = ret_content["Extract"]
        extract = apply_extract(payload, cursor, enrichment, extract)

    if source_or_dest == "DESTINATION":
        entity = dest
    else:  # source is default
        entity = src
    doc = {"host": {"ip": entity}, "agent": {"id": "GM_FINGERPRINTS", "type": fpname}}
    for key, val in enrichment.items():
        translate_keys(doc, key, val)
    # save entities back to ES
    doc_id = md5(json.dumps(doc).encode("utf8")).digest()
    doc["@timestamp"] = datetime.datetime.now().isoformat()
    DOCS_TO_INDEX.append(
        {
            "_op_type": "create",
            "_index": INDEX,
            "_id": str(binascii.b2a_hex(doc_id), encoding="ascii"),
            "_source": doc,
        }
    )
    # bulk ingest every 1000 documents
    if len(DOCS_TO_INDEX) == 1000:
        print("ingesting batch of 1,000 fingerprints...", flush=True)
        try:
            bulk(es, DOCS_TO_INDEX)
        except BulkIndexError:
            pass
        DOCS_TO_INDEX = []


def translate_keys(doc, key, val):
    """Adds the translated version of key:val to doc"""
    new_keys = field_mappings.get(key, [key])
    sub_doc = doc
    for new_key in new_keys[:-1]:
        if new_key in sub_doc:
            sub_doc = sub_doc[new_key]
        else:
            sub_doc[new_key] = {}
            sub_doc = sub_doc[new_key]
    sub_doc[new_keys[-1]] = val


# pylint: disable=too-many-branches
def apply_extract(payload, cursor, enrichment, extracts):
    """returns dictionary of extracted values from payload"""
    if not isinstance(extracts, list):
        extracts = [extracts]
    for extract in extracts:
        post = extract.get("Post", {})
        convert = None
        lookup = None
        if post:
            convert = post.get("@Convert", None)
            lookup = post.get("@Lookup", None)
        endian = extract.get("@Endian", "BIG")
        field_name = extract["@Name"]
        from_pos = extract["@From"]
        from_pos = get_position(payload, from_pos, cursor)
        to_pos = extract["@To"]
        to_pos = get_position(payload, to_pos, cursor)
        max_len = int(extract.get("@MaxLength", 65535))
        if from_pos + max_len < to_pos:
            to_pos = from_pos + max_len
        val = payload[from_pos:to_pos]
        if endian == "LITTLE":
            val = struct.pack("<s", val)
        if convert == "HEX":
            val = str(binascii.b2a_hex(val, sep=":"), encoding="ascii")
        elif convert == "INTEGER":
            val = int(val)
        elif convert == "RAW_BYTES":
            val = str(binascii.b2a_hex(val, sep=":"), encoding="ascii")
        elif convert == "STRING":
            val = str(val.replace(b"\x00", b""), encoding="ascii")
        elif lookup == "BACNET":
            val = BACNET_LOOKUP[int.from_bytes(val, "big")]
        elif lookup == "ENIPDEVICE":
            val = ENIP_DEVICE_LOOKUP[int.from_bytes(val, "big")]
        elif lookup == "ENIPVENDOR":
            val = ENIP_VENDOR_LOOKUP[int.from_bytes(val, "big")]
        else:
            val = str(binascii.b2a_hex(val, sep=":"), encoding="ascii")
        enrichment[field_name] = val
    return enrichment


# pylint: disable=too-many-branches
def apply_match(match: dict, payload: bytes, cursor: dict) -> bool:
    """
    Handles match block in fingerprint payload
    """
    matched = False
    offset = get_position(payload, match["@Offset"], cursor)
    depth = int(match.get("@Depth", 0))
    if match.get("@Relative", "false").lower() == "true":
        offset += cursor["MAIN"]

    if depth > 0:
        length = min(depth, len(payload) - offset)
    else:
        length = len(payload) - offset
    if "Pattern" in match:
        try:
            payload_str = str(payload[offset : offset + length], encoding="utf8")
            if match.get("@NoCase", False):
                expr = re.compile(match["Pattern"], re.IGNORECASE)
            else:
                expr = re.compile(match["Pattern"])
            matcher = expr.match(payload_str)
            if matcher:
                if match["@MoveCursors"]:
                    cursor["START"] = matcher.start
                    cursor["END"] = matcher.end
                cursor["MAIN"] = matcher.end
                matched = True
        except UnicodeDecodeError:
            pass

    elif "Content" in match:
        content = match["Content"]["#text"]
        content_type = match["Content"]["@Type"]
        if content_type == "HEX":
            content = binascii.a2b_hex(content)
        else:
            raise ValueError("Unknown content type: ", content_type)
        location = payload.find(content, offset, offset + length)
        if location != -1:
            if match["@MoveCursors"]:
                cursor["START"] = location
                cursor["END"] = location + len(content)
            cursor["MAIN"] = location
            matched = True
    return matched


def apply_bytejump(bytejump: dict, payload: bytes, cursor: dict):
    """
    Handles byte jump block in fingerprint payload.
    Useful for jumping a number of bytes based on
    a "length" field in the data.
    """
    offset = bytejump["@Offset"]
    offset = int(offset)
    if len(payload) <= offset:
        return
    _bytes = int(bytejump["@Bytes"])
    if _bytes > 0:
        location = payload[offset : offset + _bytes]
    if bytejump["@Endian"] == "LITTLE":
        location = int(struct.pack("<s", location))
    else:
        location = int.from_bytes(location, "big")
    location += int(bytejump["@PostOffset"])
    if len(payload) <= location:
        return

    if bytejump["@Relative"]:
        cursor["MAIN"] += location
    else:
        cursor["MAIN"] = location


def apply_anchor(anchor: dict, payload: bytes, cursor: dict):
    """
    Sets the cursor positions based on the given anchor
    """
    offset = anchor["@Offset"]
    if anchor["@Relative"]:
        offset = cursor["MAIN"]
    elif anchor["@Position"] == "START_OF_PAYLOAD":
        pass
    elif anchor["@Position"] == "END_OF_PAYLOAD":
        offset = len(payload) + offset
    elif anchor["@Position"] == "CURSOR_START":
        offset = cursor["START"] + offset
    elif anchor["@Position"] == "CURSOR_MAIN":
        offset = cursor["MAIN"] + offset
    elif anchor["@Position"] == "CURSOR_END":
        offset = cursor["END"] + offset

    cursor[anchor["@Cursor"]] = offset


# pylint: disable=too-many-arguments


def exec_ops(
    fpname: str, oplist: OrderedDict, payload: bytes, src: str, dest: str, cursor: dict
):
    """
    Parses payload operations
    """
    for opname, opvalue in oplist.items():
        if opname == "Always":
            process_return(opvalue["Return"], payload, src, dest, cursor, fpname)
        elif opname == "Return":
            process_return(opvalue, payload, src, dest, cursor, fpname)
        elif payload is not None:
            if opname == "Match":
                if apply_match(opvalue, payload, cursor):
                    if "AndThen" in opvalue:
                        exec_ops(fpname, opvalue["AndThen"], payload, src, dest, cursor)
            elif opname == "ByteTest":
                # TODO
                pass
            elif opname == "ByteJump":
                apply_bytejump(opvalue, payload, cursor)
                if "AndThen" in opvalue:
                    exec_ops(fpname, opvalue["AndThen"], payload, src, dest, cursor)
            elif opname == "IsDataAt":
                # TODO
                pass
            elif opname == "Anchor":
                apply_anchor(payload, opvalue, cursor)


def run_fingerprinting(files, pcap):
    """Run fingerprints from the given files on packets
    that have been ingested since the given timestamp.
    """
    global DOCS_TO_INDEX
    for _f in files:
        print(f"Processing {_f}...", flush=True)
        with open(_f, "r", encoding="utf8") as fprint_file:
            fingerprint = json.load(fprint_file, object_pairs_hook=OrderedDict)
        filters = fingerprint["Fingerprint"]["Filter"]
        payloads = fingerprint["Fingerprint"]["Payload"]
        fpname = fingerprint["Fingerprint"]["Header"]["Name"]
        if not isinstance(payloads, list):
            payloads = [payloads]
        if not isinstance(filters, list):
            filters = [filters]

        # run the filter query and key results to @For key
        for _filter in filters:
            filter_id = _filter["@For"]
            for k in _filter.keys():
                assert k in [
                    "@For",
                    "display_filter",
                    "@Name",
                ], "improperly handled filter"
            # query['query']['bool']['filter'].append({'exists': {'field': 'payload'}})
            # edges = scan(es, query={"query": _filter["query"]},
            #  index="packets*", _source_includes=[
            #              'source.ip', 'destination.ip', 'payload'])

            # Get all unique (src, dest, payload) values
            edges = get_edges(_filter, pcap)

            # process all matches
            for edge in edges:
                cursor = {"START": 0, "MAIN": 0, "END": 0}
                # src = edge['source']['ip']
                # dst = edge['destination']['ip']
                data = None
                if "payload" in edge.keys():
                    data = edge["payload"]
                    if len(data) % 2 == 1:
                        data = "0" + data
                    data = binascii.a2b_hex(data.strip())

                # for each resulting doc
                # tie fingerprint pyaload data to entity by @For key
                for _payload in payloads:
                    # find the payload that matches the figerprint key
                    key = _payload["@For"]
                    if key != filter_id:
                        continue
                    exec_ops(
                        fpname,
                        _payload,
                        data,
                        edge["SOURCE"],
                        edge["DESTINATION"],
                        cursor,
                    )
    # ingest any remaining fingerprints
    print(f"ingesting batch of {len(DOCS_TO_INDEX)} fingerprints...", flush=True)
    try:
        bulk(es, DOCS_TO_INDEX)
    except BulkIndexError:
        pass
    DOCS_TO_INDEX = []


def get_edges(fprint_filter: OrderedDict, pcap: str):
    """matches filter to ES documents and returns all matching edges"""

    edges = []
    # get all matches that are either not tcp or if tcp, are not SYN packets
    cmd = [
        "tshark",
        "-r",
        pcap,
        "-n",
        "-2",
        "-R",
        f"({fprint_filter['display_filter']}) && (!tcp || tcp.flags.syn == 0)",
        "-Tek",
        "-e",
        "tcp.payload",
        "-e",
        "udp.stream",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
    ]
    try:
        start = time.time()
        proc = subprocess.run(cmd, capture_output=True, check=True)
        print(time.time() - start)
    except subprocess.CalledProcessError as e:
        print(e.stderr)
        raise e
    result_lines = proc.stdout.decode("utf8").split("\n")
    result_lines = result_lines[1::2]

    for pkt in result_lines:
        pkt = json.loads(pkt)
        edge = {
            "SOURCE": pkt["layers"]["ip_src"],
            "DESTINATION": pkt["layers"]["ip_dst"],
        }
        if isinstance(edge['SOURCE'], list):
            edge['SOURCE'] = edge['SOURCE'][0]
        if isinstance(edge['DESTINATION'], list):
            edge['DESTINATION'] = edge['DESTINATION'][0]
        try:
            payload = pkt["layers"]["tcp_payload"]
            if isinstance(payload, list):
                payload = payload[0]
            edge["payload"] = payload
        except KeyError:
            try:
                payload = pkt["layers"]["udp_stream"]
                if isinstance(payload, list):
                    payload = payload[0]
                edge["payload"] = payload

            except KeyError:
                pass

        edges.append(edge)
    return edges


def main():
    global PCAP_DIR
    global INDEX
    global STATE_FILE
    parser = argparse.ArgumentParser(
        description="Reads in pcaps "
        "and extracts fingerprints, which get saved back into Elasticsearch."
    )
    parser.add_argument(
        "--pcapdir", type=str, default=PCAP_DIR, help="directory to read pcaps from"
    )
    parser.add_argument(
        "--fingerprintidx",
        type=str,
        default=INDEX,
        help="index to write fingerprints back to",
    )
    parser.add_argument(
        "--period",
        type=int,
        default=300,
        help="time (in seconds) to sleep between runs. Set to 0 to run once and exit.",
    )
    args = parser.parse_args()
    PCAP_DIR = args.pcapdir
    INDEX = args.fingerprintidx
    """Matches fingerprints to ES data an saves results back to ES"""
    # for each fingerprint file
    print("Environment variables you can set to configure this script:", flush=True)
    print(
        "ELASTICSEARCH_URL: URL of ES database to connect to, like 'http://localhost:9200'",
        flush=True,
    )
    print(
        "PACKETS_IDX: index/indices to pull packet data from, like 'packets-*'",
        flush=True,
    )
    print(
        "FINGERPRINTS_IDX: index to store data back to, like 'fingerprints'", flush=True
    )
    files = glob(f"{SCRIPT_DIR}/*.json")
    pcaps = glob(f"{PCAP_DIR}/**.pcap", recursive=True)
    if not os.path.exists(f"{PCAP_DIR}/{STATE_FILE}"):
        with open(f"{PCAP_DIR}/{STATE_FILE}", "w") as already_ingested_file:
            pass

    with open(f"{PCAP_DIR}/{STATE_FILE}", "r") as already_ingested_file:
        already_ingested = already_ingested_file.readlines()
        already_ingested = [l.strip() for l in already_ingested]

    to_ingest = list(set(pcaps) - set(already_ingested))
    print(files, flush=True)
    print("Starting fingerprinting on all current data...", flush=True)
    load_lookup_tables()
    since_timestamp = datetime.datetime.now().isoformat()
    for pcap in to_ingest:
        print(pcap, flush=True)
        run_fingerprinting(files, pcap)
        with open(f"{PCAP_DIR}/{STATE_FILE}", "a") as already_ingested_file:
            already_ingested_file.write(pcap)
            already_ingested_file.write("\n")

    print("Fingerprinting done.", flush=True)
    while True:
        sleep(args.period)
        print(f"Running again on any new data since {since_timestamp}", flush=True)
        new_timestamp = datetime.datetime.now().isoformat()
        pcaps = glob(f"{PCAP_DIR}/**.pcap*", recursive=True)

        if not os.path.exists(f"{PCAP_DIR}/{STATE_FILE}"):
            with open(f"{PCAP_DIR}/{STATE_FILE}", "w") as already_ingested_file:
                pass

        with open(f"{PCAP_DIR}/{STATE_FILE}", "r") as already_ingested_file:
            already_ingested = already_ingested_file.readlines()
            already_ingested = [l.strip() for l in already_ingested]

        to_ingest = list(set(pcaps) - set(already_ingested))
        for pcap in to_ingest:
            print(pcap, flush=True)
            run_fingerprinting(files, pcap)
            with open(f"{PCAP_DIR}/{STATE_FILE}", "a") as already_ingested_file:
                already_ingested_file.write(pcap)
                already_ingested_file.write("\n")
        since_timestamp = new_timestamp
        print("Fingerprinting done.", flush=True)


if __name__ == "__main__":
    main()
