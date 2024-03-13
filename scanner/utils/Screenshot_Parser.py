from config.config import (
    bbot_dir_path,
    bbot_project_ndjson,
    hostnames_table_filename,
    links_table_filename,
)
from utils.Links_Parser import Links_Parser
from utils.Hostname_Parser import Hostname_parser
import os
import json


# -------------------------------------------------------------------------

sc_path = os.path.abspath(__file__)

project_base_path = os.path.abspath(os.path.join(sc_path, "../../.."))

bbot_dir_path = os.path.join(project_base_path, bbot_dir_path)


# -------------------------------------------------------------------------


class Screenshot_Parser:

    def __init__(self):

        self.links = []
        self.hostnames = []
        self.screenshots = []

    def check_dependencies(self, path):
        links_path = os.path.join(bbot_dir_path, path, links_table_filename)
        hostnames_path = os.path.join(bbot_dir_path, path, hostnames_table_filename)
        ndjson_path = os.path.join(bbot_dir_path, path, bbot_project_ndjson)

        if os.path.exists(links_path) is False:
            parser = Links_Parser()
            self.links = parser.parse_to_links(ndjson_path)
            with open(links_path, "w") as w:
                json.dump(self.links, w)
        else:
            with open(links_path, "r") as r:
                self.links = json.load(r)

        if os.path.exists(hostnames_path) is False:
            parser = Hostname_parser()
            self.hostnames = parser.parse_to_host_names(ndjson_path)
            with open(hostnames_path, "w") as w:
                json.dump(self.hostnames, w)
        else:
            with open(hostnames_path, "r") as r:
                self.hostnames = json.load(r)

    def merge_dependencies(self):

        for hostname in self.hostnames:
            self.screenshots.append(
                {
                    "Marker": hostname["Marker"],
                    "Changes": hostname["Changes"],
                    "Target": hostname["Hostname"],
                    "Screenshot": hostname["Screenshot"],
                    "Port": hostname["Port"],
                    "Type": "hostname",
                    "UID": hostname["UID"],
                }
            )

        for link in self.links:
            self.screenshots.append(
                {
                    "Marker": link["Marker"],
                    "Changes": link["Changes"],
                    "Target": link["Url"],
                    "Screenshot": link["Screenshot"],
                    "Port": link["Port"],
                    "Type": "link",
                    "UID": link["UID"],
                }
            )

    def parse_to_screenshots(self, path):
        self.check_dependencies(path)
        self.merge_dependencies()
        return self.screenshots
