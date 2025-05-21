"""Runs Grassmarlin fingerprinting againts packet-* data in Elasticsearch
   And then writes results back into elasticsearch
"""
import logging
from pathlib import Path

from elasticsearch import Elasticsearch

ES_CLIENT = Elasticsearch("http://localhost:9200", request_timeout=60)
INDEX = "fingerprints"
PCAP_DIR = "/opt/pcaps"
STATE_FILE = "gm_fingerprints_ingested"
logging.basicConfig(level=logging.WARNING)

SHARED_PCAP_DATA = None

SCRIPT_DIR = Path(__file__).parents[0]
