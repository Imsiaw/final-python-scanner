import json
import sys
from uuid import uuid4

sys.setrecursionlimit(100000000)

input_path = "./scanner/static/bbot/New/2024_01_24_141414/output.ndjson"

PROTOCOL_MAPPER = {"80": "HTTP", "443": "HTTPS", "21": "FTP", "444": "TCP/UDP"}


ndjson_data = []

dns_gen_modules = [
    "TARGET",
    "anubisdb",
    "speculate",
    "zoomeye",
    "wayback",
    "virustotal",
    "viewdns",
    "urlscan",
    "threatminer",
    "sublist3r",
    "subdomaincenter",
    "sitedossier",
    "shodan_dns",
    "securitytrails",
    "riddler",
    "rapiddns",
    "passivetotal",
    "otx",
    "nsec",
    "myssl",
    "massdns",
    "leakix",
    "internetdb",
    "hunterio",
    "hackertarget",
    "fullhunt",
    "dnsdumpster",
    "dnscommonsrv",
    "digitorus",
    "crt",
    "crobat",
    "columbus",
    "chaos",
    "certspotter",
    "censys",
    "c99",
    "builtwith",
    "binaryedge",
    "bevigil",
    "azure_tenant",
    "anubisdb",
    "vhost",
    "sslcert",
    "oauth",
    "ntlm",
    "dnszonetransfer",
]

domains = {}

with open(input_path, "r") as r:

    for line in r:
        ndjson_data.append(json.loads(line))

    for d in ndjson_data:
        if d["type"] == "DNS_NAME":

            if d["module"] in dns_gen_modules:
                if d["scope_distance"] != 0:
                    continue
                if domains.get(d["data"], None) is None:
                    domains[d["data"]] = {"id": d["id"], "tags": d["tags"]}
                else:
                    domains[d["data"]] = {"id": d["id"], "tags": d["tags"]}

    #  Link the dns_name data to a subdomains
    for domain in domains:
        domain_data = domains[domain]
        domain_id = domain_data["id"]

        for nd_item in ndjson_data:
            if (nd_item["type"] == "DNS_NAME" and nd_item["id"] == domain_id) or (
                nd_item["type"] == "DNS_NAME" and nd_item["source"] == domain_id
            ):
                if nd_item["module"] not in dns_gen_modules:
                    module = nd_item["module"]
                    resolved_hosts = nd_item["resolved_hosts"]
                    data = nd_item["data"]
                    d = {
                        "module": module,
                        "resolved_hosts": resolved_hosts,
                        "data": data,
                    }
                    if domain_data.get("extra", None) is None:

                        domain_data["extra"] = []
                        domain_data["extra"].append(nd_item)
                    else:
                        domain_data["extra"].append(nd_item)

    def rec(id, domain_extra):
        for nd_item in ndjson_data:
            if (
                nd_item["type"] != "DNS_NAME"
                and nd_item["type"] != "DNS_NAME_UNRESOLVED"
                and nd_item["type"] != "URL_UNVERIFIED"
                and nd_item["type"] != "EMAIL_ADDRESS"
            ):
                if nd_item["source"] == id:
                    # print(nd_item["type"])

                    d = {
                        "type": nd_item["type"],
                        "data": nd_item["data"],
                        "resolved_hosts": nd_item.get("resolved_hosts", []),
                        "module": nd_item["module"],
                    }
                    domain_extra.append(nd_item)
                    rec(nd_item["id"], domain_extra)

    for domain in domains:
        domain_extra = []
        domain_data = domains[domain]
        domain_id = domain_data["id"]
        rec(domain_id, domain_extra)
        domain_data["info"] = domain_extra

    with open("d2.json", "w") as w:
        json.dump(domains, w)
