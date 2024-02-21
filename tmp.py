import json


with open("./scanner/static/bbot/New/2024_01_24_141414/output.ndjson", "r") as r:
    data = []
    for line in r:
        data.append(json.loads(line))

    x = set()
    for d in data:
        # print(d["tags"])
        if d["type"] != "HTTP_RESPONSE":
            continue
        try:
            print(d["data"]["title"])
        except:
            pass
        print(d["data"]["port"], getattr(d["data"], "title", None))

        x.add(d["type"])

    print(x)
