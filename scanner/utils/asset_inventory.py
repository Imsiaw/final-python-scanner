import csv
import json
import ipaddress
from contextlib import suppress
import tldextract

severity_map = {
    "INFO": 0,
    0: "N/A",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
    "N/A": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def split_domain(hostname):
    """
    Splits the hostname into its subdomain and registered domain components.

    Args:
        hostname (str): The full hostname to be split.

    Returns:
        tuple: A tuple containing the subdomain and registered domain.

    Examples:
        >>> split_domain("www.internal.evilcorp.co.uk")
        ("www.internal", "evilcorp.co.uk")

    Notes:
        - Utilizes the `tldextract` function to first break down the hostname.
    """
    if is_ip(hostname):
        return ("", hostname)
    parsed = tldextract.extract(hostname)
    subdomain = parsed.subdomain
    domain = parsed.registered_domain
    if not domain:
        split = hostname.split(".")
        subdomain = ".".join(split[:-2])
        domain = ".".join(split[-2:])
    return (subdomain, domain)


def make_ip_type(s):
    """
    Convert a string to its corresponding IP address or network type.

    This function attempts to convert the input string `s` into either an IPv4 or IPv6 address object,
    or an IPv4 or IPv6 network object. If none of these conversions are possible, the original string is returned.

    Args:
        s (str): The input string to be converted.

    Returns:
        Union[IPv4Address, IPv6Address, IPv4Network, IPv6Network, str]: The converted object or original string.

    Examples:
        >>> make_ip_type("dead::beef")
        IPv6Address('dead::beef')

        >>> make_ip_type("192.168.1.0/24")
        IPv4Network('192.168.1.0/24')

        >>> make_ip_type("evilcorp.com")
        'evilcorp.com'
    """
    # IP address
    with suppress(Exception):
        return ipaddress.ip_address(str(s).strip())
    # IP network
    with suppress(Exception):
        return ipaddress.ip_network(str(s).strip(), strict=False)
    return s


def is_port(p):
    """
    Checks if the given string represents a valid port number.

    Args:
        p (str or int): The port number to check.

    Returns:
        bool: True if the port number is valid, False otherwise.

    Examples:
        >>> is_port('80')
        True
        >>> is_port('70000')
        False
    """

    p = str(p)
    return p and p.isdigit() and 0 <= int(p) <= 65535


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


def make_ip_type(s):
    """
    Convert a string to its corresponding IP address or network type.

    This function attempts to convert the input string `s` into either an IPv4 or IPv6 address object,
    or an IPv4 or IPv6 network object. If none of these conversions are possible, the original string is returned.

    Args:
        s (str): The input string to be converted.

    Returns:
        Union[IPv4Address, IPv6Address, IPv4Network, IPv6Network, str]: The converted object or original string.

    Examples:
        >>> make_ip_type("dead::beef")
        IPv6Address('dead::beef')

        >>> make_ip_type("192.168.1.0/24")
        IPv4Network('192.168.1.0/24')

        >>> make_ip_type("evilcorp.com")
        'evilcorp.com'
    """
    # IP address
    with suppress(Exception):
        return ipaddress.ip_address(str(s).strip())
    # IP network
    with suppress(Exception):
        return ipaddress.ip_network(str(s).strip(), strict=False)
    return s


def _make_hostkey(host, ips):
    """
    We handle public and private IPs differently
    If the IPs are public, we dedupe by host
    If they're private, we dedupe by the IPs themselves
    """
    ips = _make_ip_list(ips)
    is_private = ips and all(is_ip(i) and i.is_private for i in ips)
    if is_private:
        return ",".join(sorted([str(i) for i in ips]))
    return str(host)


def _make_hostkey1(host, port):
    return host + port


def _make_ip_list(ips):
    if isinstance(ips, str):
        ips = [i.strip() for i in ips.split(",")]
    ips = [make_ip_type(i) for i in ips if i and is_ip(i)]
    return ips


class asset_inventory:
    watched_events = [
        "OPEN_TCP_PORT",
        "WEBSCREENSHOT",
        "PROTOCOL",
        "DNS_NAME",
        "URL",
        "FINDING",
        "VULNERABILITY",
        "TECHNOLOGY",
        "IP_ADDRESS",
        "WAF",
        "HTTP_RESPONSE",
    ]
    produced_events = ["IP_ADDRESS", "OPEN_TCP_PORT"]
    meta = {"description": "Output to an asset inventory style flattened CSV file"}
    options = {"output_file": "", "use_previous": False, "summary_netmask": 16}
    options_desc = {
        "output_file": "Set a custom output file",
        "use_previous": "Emit previous asset inventory as new events (use in conjunction with -n <old_scan_name>)",
        "summary_netmask": "Subnet mask to use when summarizing IP addresses at end of scan",
    }

    header_row = [
        "Host",
        "Provider",
        "IP(s)",
        "Status",
        "Open Ports",
        "Risk Rating",
        "Findings",
        "Description",
    ]

    def setup(self):
        self.assets = {}
        self.ids = {}
        self.use_previous = False
        self.summary_netmask = 16
        self.emitted_contents = False
        self._ran_hooks = False
        self.rows = []
        self.events = {}
        self.events_count = {}

    def open(self, filename):
        self.setup()
        data = []
        print("Opening file: {}".format(filename))
        with open(filename, "r") as f:
            for line in f:
                event = json.loads(line)
                event["host"] = ""
                event["port"] = ""
                if isinstance(event["data"], dict):
                    if "host" in event["data"]:
                        event["host"] = event["data"]["host"]
                        event["host1"] = event["data"]["host"]
                    if "port" in event["data"]:
                        event["port"] = event["data"]["port"]
                else:
                    event["host1"] = event["data"]
                    event["host"] = event["data"]

                if event["type"] == "WEBSCREENSHOT":
                    event["host"] = event["data"]["url"]
                if event["type"] == "WAF":
                    event["host"] = event["data"]["host"]
                if event["type"] == "TECHNOLOGY":
                    event["host"] = event["data"]["host"]

                if event["host"].startswith("http://"):
                    event["host"] = event["host"].replace("http://", "")
                    event["host"] = event["host"].replace("/", "")
                    event["port"] = "80"
                if event["host"].startswith("https://"):
                    event["host"] = event["host"].replace("https://", "")
                    event["host"] = event["host"].replace("/", "")
                    event["port"] = "443"

                temp = event["host"].split(":")
                if len(temp) > 1:
                    # if temp[-1] == "443" or temp[-1] == "80" or temp[-1] == "2083":
                    #     # if event['port'] == "":
                    #     event['host'] = ''.join(temp[:-1])
                    #     event['port'] = temp[-1]
                    if temp[-1].isdigit():
                        # if event['port'] == "":
                        event["host"] = "".join(temp[:-1])
                        event["port"] = temp[-1]

                data.append(event)
                if event["id"] not in self.events_count:
                    self.events_count[event["id"]] = 1
                else:
                    self.events_count[event["id"]] = self.events_count[event["id"]] + 1
                # print("here")
                if event["id"] not in self.events:
                    self.events[event["id"]] = []
                self.events[event["id"]].append(event)
        print("finished reading")
        sum = 0
        cnt = 0
        for num in self.events_count.values():
            cnt += 1
            sum += num
        print(sum)
        print(cnt)
        print(len(data))
        for event in data:
            self.handle_event(event)
        self.report()
        return

    def filter_event(self, event):
        if "_internal" in event:
            return False, "event is internal"
        if event["type"] not in self.watched_events:
            return False, "event type is not in watched_events"
        # if not self.scan.in_scope(event):
        #     return False, "event is not in scope"
        if "unresolved" in event["tags"]:
            return False, "event is unresolved"
        return True, ""

    def handle_event(self, event):
        if (self.filter_event(event))[0]:
            # hostkey = event['host'] + str(event['port'])
            # print(hostkey)
            hostkey = _make_hostkey(event["host"], event["resolved_hosts"])
            hostkey = hostkey + str(event["port"])
            id = event["id"]
            # print(id)
            # if event['source'].startswith("DNS_NAME:"):
            # id = event['source']
            if id not in self.ids:
                self.ids[id] = []

            if (
                event["module"] == "TXT"
                or event["module"] == "azure_tenant"
                or event["module"] == "leakix"
                or event["module"] == "sslcert"
                or event["module"] == "CNAME"
                or event["module"] == "SOA"
                or event["module"] == "MX"
                or event["module"] == "NS"
            ):
                if event["source"] not in self.ids:
                    # print(event['source'])
                    if event["source"].startswith("DNS_NAME:"):
                        # print("DNS_NAME")
                        # self.handle_event(self.events[event['source']])
                        for e in self.events[event["source"]]:
                            self.handle_event(e)
                        # print(self.ids[event['source']])
                        for host in self.ids[event["source"]]:
                            self.assets[host].update_asset(event)
                    else:
                        print("unknown error in .ndjson file")
                        # self.assets[self.ids[event['source']]].absorb_event(event)
                else:
                    # print("pass")
                    # self.assets[hostkey] = Asset(hostkey, event['port'], event['id'])
                    # self.assets[self.ids[event['source']]].update_asset(event)
                    for host in self.ids[event["source"]]:
                        self.assets[host].update_asset(event)

            elif hostkey not in self.assets:
                # print("creating----------" + hostkey)
                # self.assets[hostkey] = Asset(event['host'], event['port'])
                if event["scope_distance"] == 0:
                    self.assets[hostkey] = Asset(hostkey, event["port"], event["id"])
                    self.assets[hostkey].absorb_event(event)
                    self.ids[id].append(hostkey)

            else:
                # print("updating----------" + hostkey)
                self.assets[hostkey].absorb_event(event)

    def report(self):
        stats = dict()
        totals = dict()

        def increment_stat(stat, value):
            try:
                totals[stat] += 1
            except KeyError:
                totals[stat] = 1
            if not stat in stats:
                stats[stat] = {}
            try:
                stats[stat][value] += 1
            except KeyError:
                stats[stat][value] = 1

        def sort_key(asset):
            host = str(asset.host)
            is_digit = False
            with suppress(IndexError):
                is_digit = host[0].isdigit()
            return (is_digit, host)

        for asset in sorted(self.assets.values(), key=sort_key):
            findings_and_vulns = asset.findings.union(asset.vulnerabilities)
            ports = getattr(asset, "ports", set())
            ports = [str(p) for p in sorted([int(p) for p in asset.ports])]
            ips = sorted([str(i) for i in getattr(asset, "ip_addresses", [])])
            host = getattr(asset, "host", "")
            a = ""
            aaaa = ""
            # host = make_ip_type(getattr(asset, "host1", ""))
            if host and isinstance(host, str):
                _, domain = split_domain(host)
                if domain:
                    increment_stat("Domains", domain)
                else:
                    continue
            else:
                continue
            for ip in ips:
                # print(str(ip))
                if ipaddress.ip_address(str(ip)).version == 4:
                    a = a + str(ip) + "    "
                if ipaddress.ip_address(str(ip)).version == 6:
                    aaaa = aaaa + str(ip) + "    "
                net = ipaddress.ip_network(f"{ip}/{self.summary_netmask}", strict=False)
                increment_stat("IP Addresses", str(net))
            for port in ports:
                increment_stat("Open Ports", port)
            row = {
                "Host": host,
                "Provider": getattr(asset, "provider", ""),
                "IP(s)": "\n".join(ips),
                "Status": "Active" if asset.ports else "N/A",
                "Open Ports": "\n".join(ports),
                "Risk Rating": severity_map[getattr(asset, "risk_rating", "")],
                "Findings": "\n".join(findings_and_vulns),
                "Description": "\n".join(
                    str(x) for x in getattr(asset, "technologies", set())
                ),
            }
            protocols = getattr(asset, "protocols", set())
            screenshot = getattr(asset, "screenshot", "N/A")
            technologies = getattr(asset, "technologies", set())
            waf = getattr(asset, "waf", set())
            if asset.host == "powerhub.energy.tesla.com":
                print("HELLO", asset.host, asset.vulnerabilities, asset.protocols)
            row1 = {
                "Hostname": host,
                "port": "\n".join(ports),
                "protocol": "\n".join(protocols),
                "status": getattr(asset, "status", "N/A"),
                "screenshot": screenshot,
                "Findings": "\n".join(findings_and_vulns),
                "severity": "N/A" if asset.severity == "" else asset.severity,
                "WAF": "\n".join(waf),
                "http-title": getattr(asset, "httpTitle", "N/A"),
                "CDN": getattr(asset, "provider", ""),
                "technology": "\n".join(technologies),
                "vulnerability": (
                    "N/A" if asset.vulnerabilities == "" else asset.vulnerabilities
                ),
                "IPV4": a,
                "IPV6": aaaa,
                # "IP(s)": ",".join(ips),
                "cname": getattr(asset, "cname", "N/A"),
                "mx": getattr(asset, "mx", "N/A"),
                "ns": getattr(asset, "ns", "N/A"),
                "txt": getattr(asset, "txt", "N/A"),
                "soa": getattr(asset, "soa", "N/A"),
            }
            row.update(asset.custom_fields)
            self.rows.append(row1)


class Asset:
    def __init__(self, host, port, id):
        self.host = host
        self.id = id
        self.host1 = ""
        self.ip_addresses = set()
        self.ports = set()
        self.port = port
        self.findings = set()
        self.vulnerabilities = ""
        self.status = "UNKNOWN"
        self.risk_rating = 0
        self.provider = ""
        self.screenshot = ""
        self.technology = set()
        self.severity = ""
        self.httpTitle = ""
        self.waf = set()
        self.a = ""
        self.mx = ""
        self.ns = ""
        self.txt = ""
        self.soa = ""
        self.aaaa = ""
        self.cname = ""
        self.technologies = set()
        self.protocols = set()
        self.custom_fields = {}

    def update_asset(self, event):
        # if event['module'] == "A":
        #     self.a = event['data']
        # if event['module'] == "AAAA":
        #     self.aaaa = event['data']

        if event["module"] == "CNAME":
            self.cname = self.cname + event["data"] + "   "
        if event["module"] == "MX":
            self.mx = self.mx + event["data"] + "   "
        if event["module"] == "NS":
            self.ns = self.ns + event["data"] + "   "
        if event["module"] == "TXT":
            self.txt = self.txt + event["data"] + "   "
        if event["module"] == "SOA":
            self.soa = self.soa + event["data"] + "   "

    def absorb_event(self, event):
        if event.get("host1") is not None:
            self.host1 = event["host1"]
        if not is_ip(event["host"]):
            self.host = event["host"]

        # if self.ip_addresses != set(_make_ip_list(event['resolved_hosts'])) and self.ip_addresses != set() and set(_make_ip_list(event['resolved_hosts'])) != set():
        # print(self.ip_addresses)
        # print(set(_make_ip_list(event['resolved_hosts'])))
        # print("------------------------")

        self.ip_addresses = self.ip_addresses.union(
            set(_make_ip_list(event["resolved_hosts"]))
        )
        if event["port"]:
            # print(self.host + " : " + event['port'])
            self.ports.add(str(event["port"]))

        if event["type"] == "PROTOCOL":
            self.protocols.add(event["data"]["protocol"])

        elif event["type"] == "WEBSCREENSHOT":
            # print(self.host)
            self.screenshot = event["data"]["filename"]
        elif event["type"] == "WAF":
            # print(self.host)
            waf = ""
            if "WAF" in event["data"]:
                waf = event["data"]["WAF"]
            self.waf.add(waf)

        elif event["type"] == "FINDING":
            location = ""
            if "url" in event["data"]:
                location = event["data"]["url"]
            elif "host" in event["data"]:
                location = event["data"]["host"]
            if location:
                description = ""
                if "description" in event["data"]:
                    description = event["data"]["description"]
                self.findings.add(f"{location}:{description}")

        elif event["type"] == "VULNERABILITY":
            # print(event["type"], event["data"])
            location = ""
            if "url" in event["data"]:
                location = event["data"]["url"]
            elif "host" in event["data"]:
                location = event["data"]["host"]
            if location:

                description = "N/A"
                if "description" in event["data"]:
                    description = event["data"]["description"]
                severity = "N/A"
                if "severity" in event["data"]:
                    severity = event["data"]["severity"]
                if event["host"] == "powerhub.energy.tesla.com":
                    print(severity, description, self.ports)
                # print(severity, description)
                self.findings.add(f"{location}:{description}:{severity}")
                self.severity = severity

                self.vulnerabilities = description
                severity_int = severity_map.get(severity, 0)
                if severity_int > self.risk_rating:
                    self.risk_rating = severity_int

        elif event["type"] == "TECHNOLOGY":
            technology = ""
            if "technology" in event["data"]:
                technology = event["data"]["technology"]
            self.technologies.add(technology)

        elif event["type"] == "HTTP_RESPONSE":
            try:

                title = event["data"]["title"]
                self.httpTitle = title
            except:
                self.httpTitle = "N/A"

        for tag in event["tags"]:
            if tag.startswith("cdn-") or tag.startswith("cloud-"):
                self.provider = tag
                continue
            elif tag.startswith("status-"):
                self.status = tag[7:]
                continue
            # elif tag.startswith("http-title-"):
            #     self.httpTitle = tag[11:]
            #     continue

    @property
    def hostkey(self):
        return _make_hostkey(self.host, self.port)
