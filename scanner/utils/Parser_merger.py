from utils.Parser_constants import SEPARATOR
from utils.ip_utils import is_ip

# -------------------------------------------------------------------------


class Merger:

    def find_provider(self, arr: list):
        provider = [p for p in arr if p.startswith("cdn-") or p.startswith("cloud-")]
        try:
            return provider[0]
        except IndexError:
            return "N/A"

    # --------------------------------------------------------------------

    def merge_nameservers(self, arr: list):
        nameservers = [ns["data"] for ns in arr]
        return "N/A" if len(nameservers) == 0 else SEPARATOR.join(nameservers)

    # --------------------------------------------------------------------

    def merge_mx(self, arr: list):
        mxs = [mx["data"] for mx in arr]
        return "N/A" if len(mxs) == 0 else SEPARATOR.join(mxs)

    # --------------------------------------------------------------------

    def merge_soa(self, arr: list):
        soas = [spa["data"] for spa in arr]
        return "N/A" if len(soas) == 0 else SEPARATOR.join(soas)

    # --------------------------------------------------------------------

    def merge_txt(self, arr: list):
        txts = [txt["data"] for txt in arr]
        return "N/A" if len(txts) == 0 else SEPARATOR.join(txts)

    # --------------------------------------------------------------------

    def merge_cname(self, arr: list):
        cnames = [cname["data"] for cname in arr]
        return "N/A" if len(cnames) == 0 else SEPARATOR.join(cnames)

    # --------------------------------------------------------------------

    def get_finding(self, arr: list):
        finding = [f["data"].get("description", "N/A") for f in arr]
        return "N/A" if len(finding) == 0 else SEPARATOR.join(finding)

    # --------------------------------------------------------------------

    def merge_ipv4(self, arr: list):
        ipv4_list = [
            ipv4.get("resolved_hosts") for ipv4 in arr if "resolved_hosts" in ipv4
        ]
        flat_list = list(set([x for xs in ipv4_list for x in xs]))
        ipv4 = [ip for ip in flat_list if is_ip(ip, 4)]

        return "N/A" if len(ipv4) == 0 else SEPARATOR.join(ipv4)

    # --------------------------------------------------------------------

    def merge_ipv4_v2(self, arr: list):
        flat_list = list(set(arr))
        ipv4 = [ip for ip in flat_list if is_ip(ip, 4)]

        return "N/A" if len(ipv4) == 0 else SEPARATOR.join(ipv4)

    # --------------------------------------------------------------------

    def merge_ipv6(self, arr: list):
        ipv4_list = [
            ipv4.get("resolved_hosts") for ipv4 in arr if "resolved_hosts" in ipv4
        ]
        flat_list = list(set([x for xs in ipv4_list for x in xs]))
        ipv4 = [ip for ip in flat_list if is_ip(ip, 6)]

        return "N/A" if len(ipv4) == 0 else SEPARATOR.join(ipv4)

    # --------------------------------------------------------------------

    def merge_ipv6_v2(self, arr: list):

        flat_list = list(set(arr))
        ipv4 = [ip for ip in flat_list if is_ip(ip, 6)]

        return "N/A" if len(ipv4) == 0 else SEPARATOR.join(ipv4)

    # --------------------------------------------------------------------

    def merge_waf(self, arr: list):
        wafs = [waf["data"]["WAF"] for waf in arr]
        return "N/A" if len(wafs) == 0 else SEPARATOR.join(wafs)

    # --------------------------------------------------------------------

    def merge_screenshot(self, arr: list):
        screenshots = [sc["data"]["filename"] for sc in arr]
        # return "N/A" if len(screenshots) == 0 else ",".join(screenshots)
        return "N/A" if len(screenshots) == 0 else screenshots[0]

    # --------------------------------------------------------------------

    def merge_vs(self, arr: list):
        vulnerabilities = [vs["data"]["description"] for vs in arr]
        return "N/A" if len(vulnerabilities) == 0 else SEPARATOR.join(vulnerabilities)

    # --------------------------------------------------------------------

    def merge_severity(self, arr: list):
        severities = [sv["data"]["severity"] for sv in arr]
        return "N/A" if len(severities) == 0 else SEPARATOR.join(severities)

    # --------------------------------------------------------------------

    def merge_http_title(self, arr: list):
        http_titles = [ht["data"].get("title", "N/A") for ht in arr]
        return "N/A" if len(http_titles) == 0 else SEPARATOR.join(http_titles)

    # --------------------------------------------------------------------

    def merge_http_location(self, arr: list):
        locations = [l["data"].get("location", "N/A") for l in arr]
        return "N/A" if len(locations) == 0 else locations[0]

    # --------------------------------------------------------------------

    def merge_http_status(self, arr: list):

        http_status = [hs["data"].get("status_code", "N/A") for hs in arr]
        # return "N/A" if len(http_status) == 0 else ",".join(http_status)
        return "N/A" if len(http_status) == 0 else f"{http_status[0]}"
