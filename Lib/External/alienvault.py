import requests


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
