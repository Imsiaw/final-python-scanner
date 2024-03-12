import json


with open("./scanner/static/bbot/Balatarin/2024_02_24_141414/output.ndjson", "r") as r:
    data = []
    for line in r:
        data.append(json.loads(line))

    x = set()
    for d in data:
        # print(d["tags"])
        if d["type"] == "URL_UNVERIFIED":
            x.add(d["id"])
        # if d["id"] == "URL_UNVERIFIED:38deb877dd723b2adca628c6ed69c13530fddfd2":
        #     print(d["data"])
        #     print(d["source"])

        # if d["id"] == "URL:38deb877dd723b2adca628c6ed69c13530fddfd2":
        #     print(d["source"])
        if d["type"] == "URL":
            url = d["data"]
            if len(url.split("/")[-1].split(".")) != 1:
                print(f'{url.split("/")[-1].split(".")} {d["id"]}')
            continue
        # try:
        #     print(d["data"]["title"])
        # except:
        #     pass
        # print(d["data"]["port"], getattr(d["data"], "title", None))

        # x.add(d["type"])
