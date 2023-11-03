# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from Lib.api import data_return
from Lib.configs import IPDomain_MSG_ZH, IPDomain_MSG_EN
from Lib.log import logger
from WebDatabase.Handle.cdn import CDN
from WebDatabase.Handle.cert import Cert
from WebDatabase.Handle.component import Component
from WebDatabase.Handle.dnsrecord import DNSRecord
from WebDatabase.Handle.domainicp import DomainICP
from WebDatabase.Handle.httpbase import HttpBase
from WebDatabase.Handle.httpfavicon import HttpFavicon
from WebDatabase.Handle.location import Location
from WebDatabase.Handle.portservice import PortService
from WebDatabase.Handle.screenshot import Screenshot
from WebDatabase.models import IPDomainModel
from WebDatabase.serializers import IPDomainSerializer


class IPDomain(object):

    @staticmethod
    def list(project_id=None, pagination=None):
        if pagination is None:
            pagination = {'current': 1, 'pageSize': 10}

        start = (pagination['current'] - 1) * pagination['pageSize']
        end = pagination['current'] * pagination['pageSize']

        filter_models = IPDomainModel.objects.filter(project_id=project_id)

        pagination["total"] = filter_models.count()

        ipdomain_models = filter_models.order_by('-update_time')[start:end]

        ipdomain_list = IPDomainSerializer(ipdomain_models, many=True).data
        ipdomains_result = []
        for one_ipdomain_record in ipdomain_list:

            ipdomain = one_ipdomain_record.get("ipdomain")

            # location
            location = Location.get_by_ipdomain(ipdomain)

            # domainicp
            domainicp = DomainICP.get_by_ipdomain(ipdomain)

            dnsrecord = DNSRecord.list_by_ipdomain(ipdomain)

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
        return ipdomains_result, pagination

    @staticmethod
    def list_all():
        models = IPDomainModel.objects.all()
        result = IPDomainSerializer(models, many=True).data
        return result

    @staticmethod
    def update_project_id(project_id=None, ipdomain=None):
        update_count = IPDomainModel.objects.filter(ipdomain=ipdomain).update(project_id=project_id)
        return {"count": update_count}

    @staticmethod
    def update_or_create(project_id=None,
                         ipdomain=None, webbase_dict={}):

        default_dict = {
            'project_id': project_id,
        }
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = IPDomainModel.objects.update_or_create(ipdomain=ipdomain,
                                                                defaults=default_dict)

        return created

    @staticmethod
    def destory(ipdomain=None):
        try:
            IPDomainModel.objects.filter(ipdomain=ipdomain).delete()
            context = data_return(204, {}, IPDomain_MSG_ZH.get(204), IPDomain_MSG_EN.get(204))
        except Exception as E:
            logger.error(E)
            context = data_return(304, {}, IPDomain_MSG_ZH.get(304), IPDomain_MSG_EN.get(304))
        return context
