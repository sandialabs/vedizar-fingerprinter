# Automatic Passive Fingerprinter

This tool leverages Grassmarlin's Fingerprinting library (https://github.com/nsacyber/GRASSMARLIN) to automatically fingerprint IP addresses in .pcap files
instead of having to load them into Grassmarlin's GUI. In addition, it provides a few additional fingerprints
based on Tshark's packet parsing. It saves the result into Elasticsearch.

# Requirements

- python >= 3.8
- tcpdump
- Tshark
- running Elasticsearch instance, by default at http://localhost:9200


# Install Instructions:

pip install -r requirements.txt

# docker build instructions

docker build -t fingerprinter:latest .

# Run instructions

To analyze all pcaps in `/opt/pcaps` every 300 seconds, and save fingerprints to Elasticsearch at http://localhost:9200
- with python: `python3 run_fingerprinter.py --pcapdir=/opt/pcaps --period 300 --es-url="http://localhost:9200"`
- with docker: `docker run -v /opt/pcaps:/opt/pcaps fingerprinter:latest --pcapdir=/opt/pcaps --period 300 --es-url="http://elasticsearch:9200"`
  - for docker, you must mount in the directory containing pcaps into the container, and be sure to point to the appropriate elasticsearch URL.

