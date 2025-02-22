import time

import requests

from WebDatabase.documents import IPDomainDocument


class AlienVault(object):
    def __init__(self):
        pass

    @staticmethod
    def list_subdomains(domain):
        UA = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
        headers = {
            "User-Agent": UA,
            "Cache-Control": "max-age=0"
        }
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        items = requests.get(url, headers=headers, timeout=3, verify=False, allow_redirects=False).json()
        results = []
        for item in items["passive_dns"]:
            if item["hostname"].endswith(f".{domain}"): \
                    results.append(item["hostname"])
        return list(set(results))

    @staticmethod
    def list_subdomains_dataset(main_domain):
        UA = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
        headers = {
            "User-Agent": UA,
            "Cache-Control": "max-age=0"
        }
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{main_domain}/passive_dns"
        items = requests.get(url, headers=headers, timeout=3, verify=False, allow_redirects=False).json()
        results = []
        for item in items["passive_dns"]:
            if item["hostname"].endswith(f".{main_domain}"):
                results.append(item["hostname"])
        domains = list(set(results))
        obj_list = []
        for domain in domains:
            ipdomain_object = IPDomainDocument()
            ipdomain_object.ipdomain = domain
            ipdomain_object.source = "AlienVault"
            ipdomain_object.update_time = int(time.time())
            obj_list.append(ipdomain_object)

        return obj_list
