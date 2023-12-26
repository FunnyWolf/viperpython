import json
import os

import tldextract
from django.conf import settings

from Lib.xcache import Xcache
from WebDatabase.Handle.dnsrecord import DNSRecord


class CDNCheck(object):

    @staticmethod
    def check(cname):
        try:
            extractresult = tldextract.extract(cname)
        except Exception as _:
            return None
        domain = extractresult.registered_domain
        cdn_config = Xcache.get_web_cdn_dict()
        if not cdn_config:
            cdn_config = CDNCheck.init_cdn_dict_data()

        if domain in cdn_config:
            record = cdn_config.get(domain)
            record['domain'] = domain
            return record

    @staticmethod
    def check_by_ipdomain(domain):
        records = DNSRecord.get_cname_by_ipdomain(domain)
        for cname in records:
            result = CDNCheck.check(cname)
            if result:
                return result
        # get dns record manual
        return None

    @staticmethod
    def init_cdn_dict_data():
        dbFile = os.path.join(settings.BASE_DIR, 'STATICFILES', 'STATIC', 'cdn.json')
        config = json.load(open(dbFile, 'r'))
        Xcache.set_web_cdn_dict(config)
        return config
