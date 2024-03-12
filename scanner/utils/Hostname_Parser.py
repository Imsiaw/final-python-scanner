from utils.Parser_constants import DNS_GEN_MODULES, PROTOCOL_MAPPER
from utils.Parser_merger import Merger
import json
import sys
from uuid import uuid4


# -------------------------------------------------------------------------

sys.setrecursionlimit(100000000 * 20)


# -------------------------------------------------------------------------


class Hostname_parser:

    def __init__(self):
        self.ndjson_data = []
        self.domains = {}
        self.hostnames = []

    def read_ndjson(self, path: str):
        data = []
        with open(path, "r") as reader:
            for line in reader:
                data.append(json.loads(line))
        self.ndjson_data = data
        return data

    def separate_domains(self):
        for line in self.ndjson_data:
            if line["type"] == "DNS_NAME":

                if line["module"] in DNS_GEN_MODULES:
                    if line["scope_distance"] != 0:
                        continue
                    if self.domains.get(line["data"], None) is None:
                        self.domains[line["data"]] = {
                            "id": line["id"],
                            "tags": line["tags"],
                            "resolved_hosts": line["resolved_hosts"],
                        }
                    else:
                        self.domains[line["data"]] = {
                            "id": line["id"],
                            "tags": line["tags"],
                            "resolved_hosts": line["resolved_hosts"],
                        }
        return self.domains

    def attach_sub_events(self):
        for domain in self.domains:
            domain_data = self.domains[domain]
            domain_id = domain_data["id"]

            if domain_data.get("extra", None) is None:
                domain_data["extra"] = []

            for nd_item in self.ndjson_data:
                if (nd_item["type"] == "DNS_NAME" and nd_item["id"] == domain_id) or (
                    nd_item["type"] == "DNS_NAME" and nd_item["source"] == domain_id
                ):
                    if nd_item["module"] not in DNS_GEN_MODULES:
                        if domain_data.get("extra", None) is None:

                            domain_data["extra"] = []
                            domain_data["extra"].append(nd_item)
                        else:
                            domain_data["extra"].append(nd_item)

    def rec_find_sub_events(self, id, domain_extra, preId):

        for nd_item in self.ndjson_data:
            if (
                nd_item["type"] != "DNS_NAME"
                and nd_item["type"] != "SCAN"
                and nd_item["type"] != "DNS_NAME_UNRESOLVED"
                and nd_item["type"] != "URL_UNVERIFIED"
                and nd_item["type"] != "EMAIL_ADDRESS"
            ):
                if nd_item["source"] == id:
                    if nd_item["id"] != preId:
                        domain_extra.append(nd_item)
                        self.rec_find_sub_events(
                            nd_item["id"],
                            domain_extra,
                            id,
                        )

    def find_sub_events(self):
        for domain in self.domains:
            domain_extra = []
            domain_data = self.domains[domain]
            domain_id = domain_data["id"]
            self.rec_find_sub_events(domain_id, domain_extra, "")
            domain_data["info"] = domain_extra

    def attach_ports(self):
        merger = Merger()
        for d in self.domains:
            domain_data = self.domains[d]
            provider = merger.find_provider(domain_data["tags"])
            ns = "N/A"
            mx = "N/A"
            if domain_data.get("extra", None) is not None:

                nameservers = [
                    ns for ns in domain_data["extra"] if ns["module"] == "NS"
                ]
                ns = merger.merge_nameservers(nameservers)

                mxs = [mx for mx in domain_data["extra"] if mx["module"] == "MX"]
                mx = merger.merge_mx(mxs)

                soas = [soa for soa in domain_data["extra"] if soa["module"] == "SOA"]
                soa = merger.merge_soa(soas)

                txts = [txt for txt in domain_data["extra"] if txt["module"] == "TXT"]
                txt = merger.merge_txt(txts)

                cnames = [
                    cname
                    for cname in domain_data["extra"]
                    if cname["module"] == "CNAME"
                ]
                cname = merger.merge_cname(cnames)

                findings = [
                    finding
                    for finding in domain_data["info"]
                    if finding["type"] == "FINDING"
                ]
                finding = merger.get_finding(findings)

                ss = [
                    i.get("resolved_hosts", "")
                    for i in domain_data["info"]
                    if i["type"] == "URL"
                ]

                ss = [i for i2 in ss for i in i2]
                ipv4s = [*domain_data["resolved_hosts"], *ss]
                ipv4 = merger.merge_ipv4_v2(ipv4s)

                ss2 = [
                    i.get("resolved_hosts", "")
                    for i in domain_data["info"]
                    if i["type"] == "URL"
                ]
                ss2 = [i for i2 in ss2 for i in i2]
                ipv4s = [*domain_data["resolved_hosts"], *ss2]

                ipv6 = merger.merge_ipv6_v2(ipv4s)

                ntcp = [
                    tcp for tcp in domain_data["info"] if tcp["type"] == "OPEN_TCP_PORT"
                ]
                tcps = {}

                for t in ntcp:
                    tcps[t["data"]] = t

                tcps = list(tcps.values())
                if len(tcps) == 0:
                    final_d = {
                        "Marker": "",
                        "Changes": "",
                        "Owner": provider,
                        "Findings": finding,
                        "Hostname": d,
                        "A": ipv4,
                        "AAAA": ipv6,
                        "WAF": "N/A",
                        "CNAME": cname,
                        "Title": "N/A",
                        "MX": mx,
                        "NS": ns,
                        "Port": "N/A",
                        "Protocol": "N/A",
                        "Screenshot": "N/A",
                        "Severity": "N/A",
                        "SOA": soa,
                        "Status Code": "N/A",
                        "Location": "N/A",
                        "Technology": "N/A",
                        "TXT": txt,
                        "Vulnerability": "N/A",
                        "UID": uuid4().__str__(),
                    }
                    self.hostnames.append(final_d)

                for tcp in tcps:
                    port = "N/A"
                    protocol = "N/A"
                    screenshot = "N/A"
                    severity = "N/A"
                    vulnerability = "N/A"
                    technology = "N/A"
                    http_title = "N/A"
                    location = "N/A"
                    WAF = "N/A"
                    status = "N/A"

                    for i in domain_data["info"]:

                        if i["source"] == tcp["id"] and i["type"] == "PROTOCOL":
                            port = f'{i["data"]["port"]}'
                            protocol = i["data"]["protocol"]

                        if i["source"] == tcp["id"] and i["type"] == "URL":

                            wafs = [
                                waf
                                for waf in domain_data["info"]
                                if waf["source"] == i["id"] and waf["type"] == "WAF"
                            ]
                            WAF = merger.merge_waf(wafs)

                            screenshots = [
                                sc
                                for sc in domain_data["info"]
                                if sc["source"] == i["id"]
                                and sc["type"] == "WEBSCREENSHOT"
                            ]
                            screenshot = merger.merge_screenshot(screenshots)

                            vulnerabilities = [
                                vs
                                for vs in domain_data["info"]
                                if vs["source"] == i["id"]
                                and vs["type"] == "VULNERABILITY"
                            ]

                            vulnerability = merger.merge_vs(vulnerabilities)

                            severities = [
                                sv
                                for sv in domain_data["info"]
                                if sv["source"] == i["id"]
                                and sv["type"] == "VULNERABILITY"
                            ]

                            severity = merger.merge_severity(severities)

                            http_titles = [
                                sv
                                for sv in domain_data["info"]
                                if sv["source"] == i["id"]
                                and sv["type"] == "HTTP_RESPONSE"
                            ]

                            http_title = merger.merge_http_title(http_titles)

                            locations = [
                                l
                                for l in domain_data["info"]
                                if l["source"] == i["id"]
                                and l["type"] == "HTTP_RESPONSE"
                            ]

                            location = merger.merge_http_location(locations)

                            http_status = [
                                hs
                                for hs in domain_data["info"]
                                if hs["source"] == i["id"]
                                and hs["type"] == "HTTP_RESPONSE"
                            ]

                            status = merger.merge_http_status(http_status)

                            technologies = [
                                hs
                                for hs in domain_data["info"]
                                if hs["type"] == "TECHNOLOGY"
                            ]

                            if len(technologies) != 0:
                                technology = technologies[0]["data"].get(
                                    "technology", "N/A"
                                )

                    if port == "N/A" or protocol == "N/A":
                        port = tcp["data"].split(":")[1]
                        protocol = PROTOCOL_MAPPER.get(port, "None")

                    final_d = {
                        "Marker": "",
                        "Changes": "",
                        "Owner": provider,
                        "Findings": finding,
                        "Hostname": d,
                        "A": ipv4,
                        "AAAA": ipv6,
                        "WAF": WAF,
                        "CNAME": cname,
                        "Title": http_title,
                        "MX": mx,
                        "NS": ns,
                        "Port": port,
                        "Protocol": protocol,
                        "Screenshot": screenshot,
                        "Severity": severity,
                        "SOA": soa,
                        "Status Code": status,
                        "Location": location,
                        "Technology": technology,
                        "TXT": txt,
                        "Vulnerability": vulnerability,
                        "UID": uuid4().__str__(),
                    }
                    self.hostnames.append(final_d)
        return self.remove_equals()

    def remove_equals(self):
        unique = {}

        for hostname in self.hostnames:
            key = f'{hostname["Hostname"]}||{hostname["Port"]}'
            unique[key] = hostname
        self.hostnames = [*unique.values()]
        return [*unique.values()]

    def parse_to_host_names(self, path: str):
        self.read_ndjson(path)
        self.separate_domains()
        self.attach_sub_events()
        self.find_sub_events()
        self.attach_ports()
        return self.hostnames
