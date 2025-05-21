#first converted xml to json with cat file.xml | xq . > file.json
#then manually find & replace field names with ECS field names
#then convert filters to ES filter queries with this script
import json
import glob


files = glob.glob("*.json")

for _f in files:
    with open(_f, "r") as f:
       fprint=json.load(f)
    filter = fprint['Fingerprint']["Filter"]
    if isinstance(filter, dict):
        filter = [filter]
    for _filter in filter: 
        to_query = []
        to_pop = []
        for key, val in _filter.items():
            if not key.startswith("@"):
                to_query.append({"term": {key :val}}) 
                to_pop.append(key)
        for key in to_pop:
            _filter.pop(key)
        _filter["query"] = {"bool": {"filter": to_query}}

    with open(_f.replace(".json", "_es.json"), "w") as f:
        json.dump(fprint, f, indent=2)
        print(fprint)
