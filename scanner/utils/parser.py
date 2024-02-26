import json
import sys
from uuid import uuid4
import ipaddress

sys.setrecursionlimit(100000000)

input_path = "./scanner/static/bbot/New/2024_01_24_141414/output.ndjson"

PROTOCOL_MAPPER = {"80": "HTTP", "443": "HTTPS", "21": "FTP", "444": "TCP/UDP"}

SEPARATOR = "\n"


def is_ip(d, version=None):
    """
    Checks if the given string or object represents a valid IP address.

    Args:
        d (str or ipaddress.IPvXAddress): The IP address to check.
        version (int, optional): The IP version to validate (4 or 6). Default is None.

    Returns:
        bool: True if the string or object is a valid IP address, False otherwise.

    Examples:
        >>> is_ip('192.168.1.1')
        True
        >>> is_ip('bad::c0de', version=6)
        True
        >>> is_ip('bad::c0de', version=4)
        False
        >>> is_ip('evilcorp.com')
        False
    """
    if isinstance(d, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        if version is None or version == d.version:
            return True
    try:
        ip = ipaddress.ip_address(d)
        if version is None or ip.version == version:
            return True
    except Exception:
        pass
    return False


def find_provider(arr: list):
    provider = [p for p in arr if p.startswith("cdn-") or p.startswith("cloud-")]
    try:
        return provider[0]
    except IndexError:
        return "N/A"


def merge_nameservers(arr: list):
    nameservers = [ns["data"] for ns in arr]
    return "N/A" if len(nameservers) == 0 else SEPARATOR.join(nameservers)


def merge_mx(arr: list):
    mxs = [mx["data"] for mx in arr]
    return "N/A" if len(mxs) == 0 else SEPARATOR.join(mxs)


def merge_soa(arr: list):
    soas = [spa["data"] for spa in arr]
    return "N/A" if len(soas) == 0 else SEPARATOR.join(soas)


def merge_txt(arr: list):
    txts = [txt["data"] for txt in arr]
    return "N/A" if len(txts) == 0 else SEPARATOR.join(txts)


def merge_cname(arr: list):
    cnames = [cname["data"] for cname in arr]
    return "N/A" if len(cnames) == 0 else SEPARATOR.join(cnames)


def get_finding(arr: list):
    finding = [f["data"].get("description", "N/A") for f in arr]
    return "N/A" if len(finding) == 0 else SEPARATOR.join(finding)


def merge_ipv4(arr: list):
    ipv4_list = [ipv4.get("resolved_hosts") for ipv4 in arr if "resolved_hosts" in ipv4]
    flat_list = list(set([x for xs in ipv4_list for x in xs]))
    ipv4 = [ip for ip in flat_list if is_ip(ip, 4)]

    return "N/A" if len(ipv4) == 0 else SEPARATOR.join(ipv4)


def merge_ipv4_v2(arr: list):
    ipv4_list = [ipv4.get("resolved_hosts") for ipv4 in arr if "resolved_hosts" in ipv4]

    flat_list = list(set([x for xs in ipv4_list for x in xs]))
    ipv4 = [ip for ip in flat_list if is_ip(ip, 4)]

    return "N/A" if len(ipv4) == 0 else SEPARATOR.join(ipv4)


def merge_ipv6(arr: list):
    ipv4_list = [ipv4.get("resolved_hosts") for ipv4 in arr if "resolved_hosts" in ipv4]
    flat_list = list(set([x for xs in ipv4_list for x in xs]))
    ipv4 = [ip for ip in flat_list if is_ip(ip, 6)]

    return "N/A" if len(ipv4) == 0 else SEPARATOR.join(ipv4)


def merge_ipv6_v2(arr: list):
    ipv4_list = [ipv4.get("resolved_hosts") for ipv4 in arr if "resolved_hosts" in ipv4]
    flat_list = list(set([x for xs in ipv4_list for x in xs]))
    ipv4 = [ip for ip in flat_list if is_ip(ip, 6)]

    return "N/A" if len(ipv4) == 0 else SEPARATOR.join(ipv4)


def merge_waf(arr: list):
    wafs = [waf["data"]["WAF"] for waf in arr]
    return "N/A" if len(wafs) == 0 else SEPARATOR.join(wafs)


def merge_screenshot(arr: list):
    screenshots = [sc["data"]["filename"] for sc in arr]
    # return "N/A" if len(screenshots) == 0 else ",".join(screenshots)
    return "N/A" if len(screenshots) == 0 else screenshots[0]


def merge_vs(arr: list):
    vulnerabilities = [vs["data"]["description"] for vs in arr]
    return "N/A" if len(vulnerabilities) == 0 else SEPARATOR.join(vulnerabilities)


def merge_severity(arr: list):
    severities = [sv["data"]["severity"] for sv in arr]
    return "N/A" if len(severities) == 0 else SEPARATOR.join(severities)


def merge_http_title(arr: list):
    http_titles = [ht["data"].get("title", "N/A") for ht in arr]
    return "N/A" if len(http_titles) == 0 else SEPARATOR.join(http_titles)


def merge_http_location(arr: list):
    locations = [l["data"].get("location", "N/A") for l in arr]
    return "N/A" if len(locations) == 0 else locations[0]


def merge_http_status(arr: list):

    http_status = [hs["data"].get("status_code", "N/A") for hs in arr]
    # return "N/A" if len(http_status) == 0 else ",".join(http_status)
    return "N/A" if len(http_status) == 0 else f"{http_status[0]}"


def read_ndjson(path):

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

    with open(path, "r") as r:

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
        with open("do.json", "w") as ww:
            json.dump(domains, ww)

        for domain in domains:
            domain_data = domains[domain]
            domain_id = domain_data["id"]

            if domain_data.get("extra", None) is None:
                domain_data["extra"] = []

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

        # with open("d2.json", "w") as w:
        #     json.dump(domains, w)

    with open("do2.json", "w") as ww:
        json.dump(domains, ww)
    ports = []

    for d in domains:

        domain_data = domains[d]

        provider = find_provider(domain_data["tags"])
        ns = "N/A"
        mx = "N/A"
        if domain_data.get("extra", None) is not None:

            nameservers = [ns for ns in domain_data["extra"] if ns["module"] == "NS"]
            ns = merge_nameservers(nameservers)

            mxs = [mx for mx in domain_data["extra"] if mx["module"] == "MX"]
            mx = merge_mx(mxs)

            soas = [soa for soa in domain_data["extra"] if soa["module"] == "SOA"]
            soa = merge_soa(soas)

            txts = [txt for txt in domain_data["extra"] if txt["module"] == "TXT"]
            txt = merge_txt(txts)

            cnames = [
                cname for cname in domain_data["extra"] if cname["module"] == "CNAME"
            ]
            cname = merge_cname(cnames)

            findings = [
                finding
                for finding in domain_data["info"]
                if finding["type"] == "FINDING"
            ]
            finding = get_finding(findings)

            # ipv4s = [ipv4 for ipv4 in domain_data["info"]]
            # if domain_data.get("extra", None) is not None:
            #     i = [ipv4 for ipv4 in domain_data["extra"]]
            #     ipv4s = [*ipv4s, *i]

            # ipv4 = merge_ipv4(ipv4s)

            ipv4s = [ipv4 for ipv4 in domain_data["info"] if ipv4["module"] == "A"]

            ipv4 = merge_ipv4_v2(ipv4s)

            # ipv6s = [ipv6 for ipv6 in domain_data["info"]]
            # if domain_data.get("extra", None) is not None:
            #     i = [ipv6 for ipv6 in domain_data["extra"]]
            #     ipv6s = [*ipv6s, *i]

            # ipv6 = merge_ipv6(ipv6s)

            ipv6s = [ipv6 for ipv6 in domain_data["info"] if ipv6["module"] == "AAAA"]

            ipv6 = merge_ipv6_v2(ipv6s)

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
                ports.append(final_d)

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
                        WAF = merge_waf(wafs)

                        screenshots = [
                            sc
                            for sc in domain_data["info"]
                            if sc["source"] == i["id"] and sc["type"] == "WEBSCREENSHOT"
                        ]
                        screenshot = merge_screenshot(screenshots)

                        vulnerabilities = [
                            vs
                            for vs in domain_data["info"]
                            if vs["source"] == i["id"] and vs["type"] == "VULNERABILITY"
                        ]

                        vulnerability = merge_vs(vulnerabilities)

                        severities = [
                            sv
                            for sv in domain_data["info"]
                            if sv["source"] == i["id"] and sv["type"] == "VULNERABILITY"
                        ]

                        severity = merge_severity(severities)

                        http_titles = [
                            sv
                            for sv in domain_data["info"]
                            if sv["source"] == i["id"] and sv["type"] == "HTTP_RESPONSE"
                        ]

                        http_title = merge_http_title(http_titles)

                        locations = [
                            l
                            for l in domain_data["info"]
                            if l["source"] == i["id"] and l["type"] == "HTTP_RESPONSE"
                        ]

                        location = merge_http_location(locations)

                        http_status = [
                            hs
                            for hs in domain_data["info"]
                            if hs["source"] == i["id"] and hs["type"] == "HTTP_RESPONSE"
                        ]

                        status = merge_http_status(http_status)

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
                ports.append(final_d)
    return ports
    # with open("final.json", "w") as w:
    #     json.dump(ports, w)
