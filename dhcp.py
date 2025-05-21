"""Fingerprinting from DHCP protocol"""

import binascii
import datetime
import json
import logging
import subprocess
import time
from hashlib import md5

from elasticsearch.helpers import BulkIndexError, bulk

import config

logging.basicConfig(level=logging.INFO)


def run_dhcp_fingerprinting(pcap, pcap_date, tags):
    logging.info("Processing custom DHCP fingerprint..")

    tshark_cmd = [
        "tshark",
        "-M",
        "100000",
        "-r",
        "-",
        "-n",
        "-Y",
        "(dhcp)",
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
    formatted = {}
    for data in result_lines:
        data = json.loads(data)
        fingerprint = {
            "host": {},
            "agent": {"id": "VEDIZAR"},
            "pcap": pcap,
            "tags": tags,
        }

        # Important dhcp features based on each dhcp message type
        try:
            fingerprint["host"]["domain"] = data["layers"]["dhcp"][
                "dhcp_dhcp_option_domain_name"
            ]
        except KeyError:
            pass
        try:
            fingerprint["host"]["name"] = data["layers"]["dhcp"][
                "dhcp_dhcp_option_hostname"
            ]
        except KeyError:
            pass

        try:
            fingerprint["host"]["mac"] = data["layers"]["dhcp"]["dhcp_dhcp_hw_mac_addr"]
        except KeyError:
            pass

        try:
            if data["layers"]["dhcp"]["dhcp_dhcp_ip_client"] != "0.0.0.0":
                fingerprint["host"]["ip"] = data["layers"]["dhcp"][
                    "dhcp_dhcp_ip_client"
                ]

        except ValueError:
            pass

        # try:
        #    fingerprint["host"]["requested_ip_address"] = data["layers"]["dhcp"]["dhcp_dhcp_option_requested_ip_address"]
        # except KeyError:
        #    pass

        doc_id = md5(json.dumps(fingerprint).encode("utf8")).digest()
        doc_id = str(binascii.b2a_hex(doc_id), encoding="ascii")

        fingerprint["@timestamp"] = pcap_date.isoformat()
        formatted[doc_id] = {
            "_index": f"{config.INDEX}-{pcap_date.year:04}.{pcap_date.month:02}",
            "_op_type": "create",
            "_id": doc_id,
            "_source": fingerprint,
        }

    ####### EXPORT dhcp features to elasticsearch ######
    logging.info("ingesting %s custom fingerprints...", len(formatted))
    try:
        bulk(client=config.ES_CLIENT, actions=formatted.values())
    except BulkIndexError as excp:
        logging.exception(excp)
        pass
