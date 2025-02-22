# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from elasticsearch_dsl import Search, Q

from Lib.api import data_return, is_ipaddress
from Lib.configs import IPDomain_MSG_ZH, IPDomain_MSG_EN, ES_MAX_COUNT
from Lib.log import logger
from WebDatabase.Handle.cdn import CDN
from WebDatabase.Handle.cert import Cert
from WebDatabase.Handle.component import Component
from WebDatabase.Handle.dnsrecord import DNSRecord
from WebDatabase.Handle.httpbase import HttpBase
from WebDatabase.Handle.httpfavicon import HttpFavicon
from WebDatabase.Handle.location import Location
from WebDatabase.Handle.port import Port
from WebDatabase.Handle.screenshot import Screenshot
from WebDatabase.Handle.service import Service
from WebDatabase.Handle.vulnerability import Vulnerability
from WebDatabase.Handle.waf import WAF
from WebDatabase.documents import CDNDocument, IPDomainDocument, WAFDocument, ComponentDocument, PortDocument, ServiceDocument, DNSRecordDocument, \
    LocationDocument, HttpBaseDocument, HttpFaviconDocument, ScreenshotDocument, VulnerabilityDocument


class IPDomain(object):

    @staticmethod
    def get_by_ipdomain(ipdomain):
        doc = IPDomainDocument(ipdomain=ipdomain)
        return doc.get_dict()

    @staticmethod
    def get_project_id_by_ipdomain(ipdomain):
        try:
            doc = IPDomainDocument(ipdomain=ipdomain).get_doc()
        except Exception as e:
            return None
        if doc is None:
            return None
        else:
            return doc.project_id

    @staticmethod
    def list(project_id=None, pagination=None, ipdomain_s=None, port_s=None, cdn_flag_s=None, waf_flag_s=None, alive_flag=None,
             services_s=[], components_s=[]):

        # ipdomain query
        ipdomain_must_filter_list = [
            Q('term', project_id=project_id),
        ]
        if ipdomain_s is not None:
            ipdomain_must_filter_list.append(Q('wildcard', ipdomain=f'*{ipdomain_s}*'))

        if cdn_flag_s is not None:
            if cdn_flag_s == "unknown":
                s = Search(index=CDNDocument.Index.name)
            else:
                s = Search(index=CDNDocument.Index.name).query('term', flag=cdn_flag_s)
            s = s.extra(size=ES_MAX_COUNT)
            response = s.execute()
            ipdomains_cdn = [hit.ipdomain for hit in response]

            ipdomain_must_filter_list.append(Q('terms', ipdomain=ipdomains_cdn))

        # https://stackoverflow.com/questions/56651142/elasticsearch-dsl-filter-then-aggregate-in-python
        bool_query = Q('bool', must=ipdomain_must_filter_list)
        s = Search(index=IPDomainDocument.Index.name).query(bool_query)
        s = s.extra(size=ES_MAX_COUNT)
        response = s.execute()
        ipdomains = [hit.ipdomain for hit in response]

        # port filter
        port_must_filter_list = [
            Q('terms', ipdomain=ipdomains)
        ]
        if port_s is not None:
            port_must_filter_list.append(Q('term', port=port_s))

        if alive_flag is not None:
            port_must_filter_list.append(Q('term', alive=alive_flag))

        if waf_flag_s is not None:
            if waf_flag_s == "unknown":
                s = Search(index=WAFDocument.Index.name)
            else:
                s = Search(index=WAFDocument.Index.name).query('term', flag=waf_flag_s)
            s = s.extra(size=ES_MAX_COUNT)
            response = s.execute()
            doc_id_waf = [hit.meta.id for hit in response]

            port_must_filter_list.append(Q('terms', _id=doc_id_waf))

        if services_s:
            s = Search(index=ServiceDocument.Index.name).query('terms', service=services_s)
            s = s.extra(size=ES_MAX_COUNT)
            response = s.execute()
            doc_id_services = [hit.meta.id for hit in response]

            port_must_filter_list.append(Q('terms', _id=doc_id_services))

        if components_s:
            s = Search(index=ComponentDocument.Index.name).query('terms', product_name=components_s)
            s = s.extra(size=ES_MAX_COUNT)
            response = s.execute()
            doc_id_components = [hit.ipdomain_port for hit in response]
            port_must_filter_list.append(Q('terms', _id=doc_id_components))

        bool_query = Q('bool', must=port_must_filter_list)

        s = Search(index=PortDocument.Index.name).query(bool_query)

        # pagination
        if pagination is None:
            pagination = {'current': 1, 'pageSize': 10}

        start = (pagination['current'] - 1) * pagination['pageSize']
        end = pagination['current'] * pagination['pageSize']

        s = s.extra(from_=start, size=pagination['pageSize'])
        response = s.execute()

        pagination["total"] = s.count()

        ipdomain_port_list = []
        for hit in response:
            ipdomain_port_list.append((hit.ipdomain, hit.port))

        ipdomains_result = []
        for ipdomain_port_tuple in ipdomain_port_list:

            ipdomain = ipdomain_port_tuple[0]
            port = ipdomain_port_tuple[1]

            ipdomain_record = IPDomain.get_by_ipdomain(ipdomain)
            if ipdomain_record is None:
                continue

            # ip
            if is_ipaddress(ipdomain):
                ip = ipdomain
            else:
                ip = DNSRecord.get_domain_first_ip(ipdomain)
            ipdomain_record["ip"] = ip

            # location
            location = Location.get_by_ipdomain(ipdomain)
            ipdomain_record["location"] = location

            # dnsrecord
            dnsrecord = DNSRecord.list_by_ipdomain(ipdomain)
            ipdomain_record["dnsrecord"] = dnsrecord

            # cdn
            ipdomain_record["cdn"] = CDN.get_by_ipdomain(ipdomain=ipdomain)

            port_base = Port.get_by_ipdomain_port(ipdomain, port)

            one_record = {}
            one_record.update(ipdomain_record)
            one_record.update(port_base)

            # service
            one_record['service'] = Service.get_by_ipdomain_port(ipdomain, port)

            # components
            one_record["component"] = Component.list_by_ipdomain_port(ipdomain, port)

            # cert
            one_record["cert"] = Cert.get_by_ipdomain_port(ipdomain=ipdomain, port=port)

            # screenshot
            one_record["screenshot"] = Screenshot.get_by_ipdomain_port(ipdomain, port)

            # vulnerabilitys
            one_record["vulnerability"] = Vulnerability.list_by_ipdomain_port(ipdomain=ipdomain, port=port)

            if one_record['service']:
                service_name = one_record['service'].get("service")
                if service_name.startswith("http"):
                    httpbase = HttpBase.get_by_ipdomain_port(ipdomain, port)
                    if httpbase is not None:
                        httpbase['url'] = Port.group_url_by_ipdomain_record(ipdomain, port, service_name)

                    one_record["http_base"] = httpbase

                    one_record["http_favicon"] = HttpFavicon.get_by_ipdomain_port(ipdomain, port)

                    # waf
                    one_record["waf"] = WAF.get_by_ipdomain_port(ipdomain, port)

            # add
            ipdomains_result.append(one_record)

        return ipdomains_result, pagination

    @staticmethod
    def update_project_id(project_id=None, ipdomain=None):
        IPDomainDocument(project_id=project_id, ipdomain=ipdomain).save()
        return True

    @staticmethod
    def delete_by_project(project_id=None):
        try:
            s = Search(index=IPDomainDocument.Index.name).query('term', project_id=project_id)
            s = s.extra(size=ES_MAX_COUNT)
            response = s.execute()
            ipdomains = [hit.ipdomain for hit in response]
            IPDomain.delete_by_ipdomain_list(ipdomains)
            return True
        except Exception as E:
            logger.exception(E)
            return False

    @staticmethod
    def destory(ipdomain=None):
        try:
            flag = IPDomain.delete_by_ipdomain_list([ipdomain])
            context = data_return(204, {}, IPDomain_MSG_ZH.get(204), IPDomain_MSG_EN.get(204))
        except Exception as E:
            logger.exception(E)
            context = data_return(304, {}, IPDomain_MSG_ZH.get(304), IPDomain_MSG_EN.get(304))
        return context

    @staticmethod
    def delete_by_ipdomain_list(ipdomain_list: list):

        response = Search(index=PortDocument.Index.name).query('terms', ipdomain=ipdomain_list).delete()
        response = Search(index=CDNDocument.Index.name).query('terms', ipdomain=ipdomain_list).delete()
        response = Search(index=WAFDocument.Index.name).query('terms', ipdomain=ipdomain_list).delete()
        response = Search(index=ServiceDocument.Index.name).query('terms', ipdomain=ipdomain_list).delete()
        response = Search(index=ComponentDocument.Index.name).query('terms', ipdomain=ipdomain_list).delete()
        response = Search(index=DNSRecordDocument.Index.name).query('terms', ipdomain=ipdomain_list).delete()
        response = Search(index=LocationDocument.Index.name).query('terms', ipdomain=ipdomain_list).delete()
        response = Search(index=HttpBaseDocument.Index.name).query('terms', ipdomain=ipdomain_list).delete()
        response = Search(index=HttpFaviconDocument.Index.name).query('terms', ipdomain=ipdomain_list).delete()
        response = Search(index=ScreenshotDocument.Index.name).query('terms', ipdomain=ipdomain_list).delete()
        response = Search(index=VulnerabilityDocument.Index.name).query('terms', ipdomain=ipdomain_list).delete()
        response = Search(index=IPDomainDocument.Index.name).query('terms', ipdomain=ipdomain_list).delete()
        return True
