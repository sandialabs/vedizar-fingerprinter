
FROM ubuntu:22.04


RUN apt update && \
DEBIAN_FRONTEND=noninteractive apt install -y python3 python3-pip tshark tcpdump git python3-tk git build-essential && \
rm -rf /var/lib/apt/lists/* && \
apt clean all && \
python3 -m pip install
--no-cache-dir \
-U pip
COPY ./.git/ /.git
COPY requirements.txt /
RUN pip install
--no-cache-dir -r /requirements.txt
COPY grassmarlin/GM3/data/fingerprint/json/*.json  /grassmarlin/GM3/data/fingerprint/json/
COPY grassmarlin/GM3/data/fingerprint/json/*.csv   /grassmarlin/GM3/data/fingerprint/json/
COPY grassmarlin/GM3/data/fingerprint/json/LICENSE.md /.

WORKDIR /

COPY *.py /

ENTRYPOINT ["python3", "/run_fingerprinters.py"]
CMD [ "--es-url", "http://elasticsearch:9200", "--pcapdir", "/opt/pcaps", "--os", "--hostname"]

