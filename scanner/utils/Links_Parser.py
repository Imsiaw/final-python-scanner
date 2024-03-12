from utils.Parser_constants import ALLOWED_FILES, SEPARATOR
import json
import sys
from uuid import uuid4


# -------------------------------------------------------------------------

sys.setrecursionlimit(100000000 * 20)


# -------------------------------------------------------------------------


class Links_Parser:

    def __init__(self):
        self.ndjson_data = []
        self.links = {}

    def read_ndjson(self, path: str):
        data = []
        with open(path, "r") as reader:
            for line in reader:
                data.append(json.loads(line))
        self.ndjson_data = data
        return data

    def separate_links(self):
        for nd_item in self.ndjson_data:

            if nd_item["type"] == "HTTP_RESPONSE":
                http_response_url = nd_item["data"]["url"]
                hash_port = nd_item["data"]["port"]
                last_pathname = http_response_url.split("/")[-1]
                file_name = "N/A"
                for ex in ALLOWED_FILES:
                    if last_pathname.endswith(ex):
                        file_name = last_pathname

                self.links[http_response_url] = {
                    "Marker": "",
                    "Changes": "",
                    "Port": hash_port,
                    "Hash": nd_item["data"]["hash"]["body_md5"],
                    "Filename": file_name,
                    "Url": http_response_url.replace(f":{hash_port}", ""),
                    "PUrl": http_response_url,
                    "Diff": "N/A",
                    "UID": uuid4().__str__(),
                }

        print(len(self.links))

        for hash in self.links:
            hash_data = self.links[hash]

            for nd_item in self.ndjson_data:
                hash_port = hash_data["Port"]
                hash_url = hash.replace(f":{hash_port}", "")

                if nd_item["type"] == "WEBSCREENSHOT":
                    screenshot_url = nd_item["data"].get("url", "")
                    if screenshot_url == hash_url:
                        hash_data["Screenshot"] = nd_item["data"].get("filename", "N/A")

                if nd_item["type"] == "FINDING":
                    finding_url: str = nd_item["data"].get("url", "")

                    if finding_url == hash_url:
                        cur_data = nd_item["data"].get("description", "N/A")
                        if hash_data.get("Finding", None) is None:
                            hash_data["Finding"] = []
                        hash_data["Finding"].append(cur_data)

            if hash_data.get("Finding", None) is not None:
                hash_data["Finding"] = SEPARATOR.join(hash_data["Finding"])
            if hash_data.get("Screenshot", None) is None:
                hash_data["Screenshot"] = "N/A"

        with open("do2.json", "w") as ww:
            json.dump(self.links, ww)

    def parse_to_links(self, path: str):
        self.read_ndjson(path)
        self.separate_links()

        return [*self.links.values()]
