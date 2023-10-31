# -*- coding: utf-8 -*-
# @File  : heartbeat.py
# @Date  : 2021/2/27
# @Desc  :
from Lib.xcache import Xcache
from WebDatabase.Handle.cdn import CDN
from WebDatabase.Handle.cert import Cert
from WebDatabase.Handle.component import Component
from WebDatabase.Handle.dnsrecord import DNSRecord
from WebDatabase.Handle.domainicp import DomainICP
from WebDatabase.Handle.httpbase import HttpBase
from WebDatabase.Handle.httpfavicon import HttpFavicon
from WebDatabase.Handle.ipdomain import IPDomain
from WebDatabase.Handle.location import Location
from WebDatabase.Handle.portservice import PortService
from WebDatabase.Handle.screenshot import Screenshot


class WebSync(object):
    def __init__(self):
        pass

    @staticmethod
    def get_ipdomains():

        ipdomains_result = []

        ipdomain_list = IPDomain.list_all()
        for one_ipdomain_record in ipdomain_list:

            ipdomain = one_ipdomain_record.get("ipdomain")

            # location
            location = Location.get_by_ipdomain(ipdomain)

            # domainicp
            domainicp = DomainICP.get_by_ipdomain(ipdomain)

            dnsrecord = DNSRecord.get_by_ipdomain(ipdomain)

            # ports
            portservice_list = PortService.list_by_ipdomain(ipdomain)
            for portservice in portservice_list:
                service = portservice.get('service')
                port = portservice.get('port')

                one_record = {}
                one_record.update(one_ipdomain_record)
                one_record.update(portservice)

                one_record["location"] = location
                one_record["domainicp"] = domainicp
                one_record["dnsrecord"] = dnsrecord

                component_list = Component.list_by_ipdomain_port(ipdomain, port)
                one_record["component_list"] = component_list

                cert = Cert.get_by_ipdomain_port(ipdomain, port)
                one_record["cert"] = cert

                screenshot = Screenshot.get_by_ipdomain_port(ipdomain, port)
                one_record["screenshot"] = screenshot

                if service.startswith("http"):
                    one_record_http = {}

                    httpbase = HttpBase.get_by_ipdomain_port(ipdomain, port)
                    one_record_http["httpbase"] = httpbase

                    httpfavicon = HttpFavicon.get_by_ipdomain_port(ipdomain, port)
                    one_record_http["httpfavicon"] = httpfavicon

                    cdn = CDN.get_by_ipdomain_port(ipdomain, port)
                    one_record_http["cdn"] = cdn

                    one_record['http'] = one_record_http

                ipdomains_result.append(one_record)

        return ipdomains_result

    @staticmethod
    def get_result():
        result = {}

        ipdomains_result = WebSync.get_ipdomains()
        cache_ipdomains_result = Xcache.get_websync_cache_ipdomains()
        if cache_ipdomains_result == ipdomains_result:
            result["ipdomains_update"] = False
            result["ipdomains"] = ipdomains_result
        else:
            Xcache.set_websync_cache_ipdomains(ipdomains_result)
            result["ipdomains_update"] = True
            result["ipdomains"] = ipdomains_result

        result = {
            'ipdomains_update': True,
            'ipdomains': ipdomains_result,
        }

        return result

    @staticmethod
    def init_result():
        ipdomains_result = WebSync.get_ipdomains()
        Xcache.set_websync_cache_ipdomains(ipdomains_result)

        result = {
            'ipdomains_update': True,
            'ipdomains': ipdomains_result,
        }
        return result

    @staticmethod
    def first_result():

        cache_ipdomains_result = Xcache.get_websync_cache_ipdomains()
        result = {
            'ipdomains_update': True,
            'ipdomains': cache_ipdomains_result,
        }

        return result
