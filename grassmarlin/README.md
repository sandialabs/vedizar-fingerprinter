# SNL customizations
* in the `GM3/data/finterprint` folder, added a `json` folder
* the `.json` files are directory converted from the .xml fingerpints
* the `*_es.json` files have been further modified to make the filteres ES queries by `GM3/data/fingerprint/json/to_es.py`
* `GM3/data/fingerprint/json/fingerprint_packets.py` runs the `*_es.json` fingerprints agains the `packets-*` data in Elasticsearch, and writes the results back to the `fingerprints` index.

# GRASSMARLIN

GRASSMARLIN provides IP network situational awareness of industrial control systems (ICS) and Supervisory Control and Data Acquisition (SCADA) networks to support network security. Passively map, and visually display, an ICS/SCADA network topology while safely conducting device discovery, accounting, and reporting on these critical cyber-physical systems.

## Documentation

GrassMarlin v3.2 User Guide:
* [Download PDF](https://github.com/iadgov/GRASSMARLIN/raw/master/GRASSMARLIN%20User%20Guide.pdf)
* [View PDF on GitHub](https://github.com/iadgov/GRASSMARLIN/blob/master/GRASSMARLIN%20User%20Guide.pdf)

A [presentation on GRASSMARLIN](http:github.com/iadgov/GRASSMARLIN/blob/master/GRASSMARLIN_Briefing_20170210.pptx) is also available.

## Release

Download the [latest release](https://github.com/iadgov/GRASSMARLIN/releases/latest).

File hashes are located in [FileHash.md](./FileHash.md).

## License

See [LICENSE.md](./LICENSE.md).

## Disclaimer

See [DISCLAIMER.md](./DISCLAIMER.md).

