class Format_Inventory:

    def merge_duplicated(self, obj):
        m = {}
        for d in obj:

            try:
                m[d["Hostname"]].append(d)
            except:
                m[d["Hostname"]] = [d]

            # print(d)
        data = []
        for mitem in m:
            if len(m[mitem]) > 1:
                mergedItem = {}
                for index, item in enumerate(m[mitem]):
                    if index == 0:
                        mergedItem = {**item}
                        continue
                    mergedItem = {
                        "CDN": item["CDN"],
                        "Findings": item["Findings"],
                        "Hostname": item["Hostname"],
                        "IPV4": item["IPV4"],
                        "IPV6": item["IPV6"],
                        "WAF": f"{mergedItem['WAF']},{item['WAF']}",
                        "cname": item["cname"],
                        "http-title": f"{mergedItem['http-title']},{item['http-title']}",
                        "mx": f"{mergedItem['mx']},{item['mx']}",
                        "ns": f"{mergedItem['ns']},{item['ns']}",
                        "port": f"{mergedItem['port']},{item['port']}",
                        "protocol": f"{mergedItem['protocol']},{item['protocol']}",
                        "screenshot": item["screenshot"],
                        "severity": f"{mergedItem['severity']},{item['severity']}",
                        "soa": item["soa"],
                        "status": f"{mergedItem['status']},{item['status']}",
                        "technology": item["technology"],
                        "txt": item["txt"],
                        "vulnerability": f"{mergedItem['vulnerability']},{item['vulnerability']}",
                    }
                data.append(mergedItem)
            else:
                data.append(m[mitem][0])
        return obj


format_inventory = Format_Inventory()
