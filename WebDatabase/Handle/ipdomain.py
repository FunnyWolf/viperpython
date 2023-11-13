# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from django.db import transaction

from Lib.api import data_return, is_ipaddress
from Lib.configs import IPDomain_MSG_ZH, IPDomain_MSG_EN
from Lib.log import logger
from WebDatabase.Handle.dnsrecord import DNSRecord
from WebDatabase.Handle.domainicp import DomainICP
from WebDatabase.Handle.location import Location
from WebDatabase.Handle.portservice import PortService
from WebDatabase.models import IPDomainModel
from WebDatabase.serializers import IPDomainSerializer


class IPDomain(object):

    @staticmethod
    def list(project_id=None, pagination=None, ipdomain=None, port=None):
        # pagination
        if pagination is None:
            pagination = {'current': 1, 'pageSize': 10}

        start = (pagination['current'] - 1) * pagination['pageSize']
        end = pagination['current'] * pagination['pageSize']

        filter_models = IPDomainModel.objects.filter(project_id=project_id)

        # search params start
        if ipdomain:
            filter_models = filter_models.filter(ipdomain__icontains=ipdomain)

        # search params end

        pagination["total"] = filter_models.count()

        ipdomain_models = filter_models.order_by('-update_time')[start:end]

        ipdomain_list = IPDomainSerializer(ipdomain_models, many=True).data
        ipdomains_result = []
        for ipdomain_record in ipdomain_list:

            ipdomain = ipdomain_record.get("ipdomain")

            # ip
            if is_ipaddress(ipdomain):
                ip = ipdomain
            else:
                ip = DNSRecord.get_domain_ip(ipdomain)
            ipdomain_record["ip"] = ip

            # location
            location = Location.get_by_ipdomain(ipdomain)
            ipdomain_record["location"] = location

            # domainicp
            domainicp = DomainICP.get_by_ipdomain(ipdomain)
            ipdomain_record["domainicp"] = domainicp

            # dnsrecord
            dnsrecord = DNSRecord.list_by_ipdomain(ipdomain)
            ipdomain_record["dnsrecord"] = dnsrecord

            # ports
            portservice_list = PortService.list_by_ipdomain(ipdomain, port)

            if not portservice_list and (port is None):  # ipdomain 没有端口信息且没有过滤端口
                one_record = {}
                one_record.update(ipdomain_record)

                ipdomains_result.append(one_record)
            else:
                for portservice in portservice_list:
                    port = portservice.get('port')
                    port_record = PortService.get_info_by_ipdomain_port(ipdomain, port)

                    one_record = {}
                    one_record.update(ipdomain_record)
                    one_record.update(port_record)

                    ipdomains_result.append(one_record)
        return ipdomains_result, pagination

    @staticmethod
    def list_all():
        models = IPDomainModel.objects.all()
        result = IPDomainSerializer(models, many=True).data
        return result

    @staticmethod
    def update_project_id(project_id=None, ipdomain=None):
        with transaction.atomic():
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
        with transaction.atomic():
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
