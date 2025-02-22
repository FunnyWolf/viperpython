import json
import os
import time

import tldextract
from django.conf import settings

from Lib.api import get_dns_cname
from Lib.xcache import Xcache
from WebDatabase.Interface.dataset import DataSet
from WebDatabase.documents import DNSRecordDocument, CDNDocument


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
    def check_by_domain(domain, dataset: DataSet) -> DataSet:
        cnames = get_dns_cname(domain)
        if not cnames:
            cdn_object = CDNDocument()
            cdn_object.ipdomain = domain

            cdn_object.flag = False

            cdn_object.source = 'CDNCheck'
            cdn_object.update_time = int(time.time())

            dataset.cdnList.append(cdn_object)
            return dataset

        dnsrecord_obj = DNSRecordDocument()
        dnsrecord_obj.ipdomain = domain
        dnsrecord_obj.type = "CNAME"
        dnsrecord_obj.value = cnames
        dnsrecord_obj.update_time = int(time.time())
        dnsrecord_obj.source = 'Manual'
        dataset.dnsrecordList.append(dnsrecord_obj)

        for cname in cnames:
            result = CDNCheck.check(cname)
            if result:
                cdn_object = CDNDocument()
                cdn_object.ipdomain = domain

                cdn_object.flag = True
                cdn_object.domain = result.get('domain')
                cdn_object.name = result.get('name')
                cdn_object.link = result.get('link')

                cdn_object.source = 'CDNCheck'
                cdn_object.update_time = int(time.time())
                cdn_object.data = result

                dataset.cdnList.append(cdn_object)
                break
        else:
            cdn_object = CDNDocument()
            cdn_object.ipdomain = domain

            cdn_object.flag = False

            cdn_object.source = 'CDNCheck'
            cdn_object.update_time = int(time.time())

            dataset.cdnList.append(cdn_object)

        return dataset

    @staticmethod
    def check_by_dataset(dataset: DataSet) -> DataSet:

        for dnsrecord_obj in dataset.dnsrecordList:
            dnsrecord_obj: DNSRecordDocument
            if dnsrecord_obj.type != 'CNAME':
                continue

            for cname in dnsrecord_obj.value:
                result = CDNCheck.check(cname)
                if result:
                    cdn_object = CDNDocument()
                    cdn_object.ipdomain = dnsrecord_obj.ipdomain

                    cdn_object.flag = True
                    cdn_object.domain = result.get('domain')
                    cdn_object.name = result.get('name')
                    cdn_object.link = result.get('link')

                    cdn_object.source = 'CDNCheck'
                    cdn_object.update_time = int(time.time())
                    cdn_object.data = result

                    dataset.cdnList.append(cdn_object)
                    break
            else:
                cdn_object = CDNDocument()
                cdn_object.ipdomain = dnsrecord_obj.ipdomain

                cdn_object.flag = False

                cdn_object.source = 'CDNCheck'
                cdn_object.update_time = int(time.time())

                dataset.cdnList.append(cdn_object)

        return dataset

    @staticmethod
    def init_cdn_dict_data():
        dbFile = os.path.join(settings.BASE_DIR, 'STATICFILES', 'STATIC', 'cdn.json')
        config = json.load(open(dbFile, 'r'))
        Xcache.set_web_cdn_dict(config)
        return config
