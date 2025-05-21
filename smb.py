"""Fingerprinting from SMB protocol"""

import binascii
import json
import logging
import subprocess
from hashlib import md5

from elasticsearch.helpers import BulkIndexError, bulk

import config

logging.basicConfig(level=logging.INFO)

# from wireshark source https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-smb-browse.c
server_bits = [
    "Workstation",
    "Server",
    "SQL Server",
    "Domain Controller",
    "Backup Controller",
    "Time Source",
    "Apple Server",
    "Novell Server",
    "Domain Member Server",
    "Print Queue Server",
    "Dialin Server",
    "Xenix Server",
    "NT Workstation",
    "Windows for Workgroups",
    "NT Server",
    "Potential Browser",
    "Backup Browser",
    "Master Browser",
    "Domain Master Browser",
    "OSF",
    "VMS",
    "Windows 95 or above",
    "DFS server",
    "Local List Only",
    "Domain Enum",
]


def run_browser_fingerprinting(pcap, pcap_date, tags):
    logging.info("Processing custom SMB fingerprint...")

    tshark_cmd = [
        "tshark",
        "-M",
        "100000",
        "-r",
        "-",
        "-n",
        "-Y",
        "(browser)",
        "-Tek",
    ]
    try:
        proc = subprocess.run(
            tshark_cmd, capture_output=True, check=True, input=config.SHARED_PCAP_DATA
        )
    except subprocess.CalledProcessError as excp:
        logging.exception(excp.stderr)
        raise excp
    result_lines = proc.stdout.decode("utf8").split("\n")
    result_lines = result_lines[1::2]
    formatted = []
    for data in result_lines:
        data = json.loads(data)
        fingerprint = {
            "host": {},
            "agent": {"id": "VEDIZAR"},
            "pcap": pcap,
            "tags": tags,
        }

        # Isolate important browser features
        try:
            fingerprint["host"]["name"] = data["layers"]["browser"][
                "browser_browser_response_computer_name"
            ]
        except KeyError:
            try:
                fingerprint["host"]["name"] = data["layers"]["nbdgm"][
                    "nbdgm_nbdgm_source_name"
                ]
            except KeyError:
                pass

        # remove <xx> from end of name
        if (
            fingerprint["host"]["name"][-1] == ">"
            and fingerprint["host"]["name"][-4] == "<"
        ):
            fingerprint["host"]["name"] = fingerprint["host"]["name"][:-4]

        try:
            fingerprint["host"]["ip"] = data["layers"]["nbdgm"]["nbdgm_nbdgm_src_ip"]
        except KeyError:
            pass
        try:
            fingerprint["host"]["os"] = {
                "name": data["layers"]["browser"]["browser_browser_windows_version"]
            }
        except KeyError:
            pass
        try:
            server_type = int(
                data["layers"]["browser"]["browser_browser_server_type"], base=16
            )
            server_types = []
            for idx, flag in enumerate(server_bits):
                if (server_type >> idx) & 0x1:
                    server_types.append(flag)
            fingerprint["host"]["role"] = server_types
        except KeyError:
            pass
        doc_id = md5(json.dumps(fingerprint).encode("utf8")).digest()
        doc_id = str(binascii.b2a_hex(doc_id), encoding="ascii")

        fingerprint["@timestamp"] = pcap_date.isoformat()
        formatted.append(
            {
                "_index": f"{config.INDEX}-{pcap_date.year:04}.{pcap_date.month:02}",
                "_op_type": "create",
                "_id": doc_id,
                "_source": fingerprint,
            }
        )

    ####### EXPORT browse_feat to elasticsearch ######
    logging.info("ingesting %s custom fingerprints...", len(formatted))
    try:
        bulk(client=config.ES_CLIENT, actions=formatted)
    except BulkIndexError as excp:
        logging.exception(excp)
        pass
