# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from Lib.api import data_return, is_ipaddress
from Lib.configs import IPDomain_MSG_ZH, IPDomain_MSG_EN
from Lib.log import logger
from WebDatabase.Handle.cdn import CDN
from WebDatabase.Handle.dnsrecord import DNSRecord
from WebDatabase.Handle.domainicp import DomainICP
from WebDatabase.Handle.location import Location
from WebDatabase.Handle.port import Port
from WebDatabase.models import IPDomainModel, CDNModel, PortModel, WAFModel, ServiceModel
from WebDatabase.serializers import IPDomainSerializer


class IPDomain(object):

    @staticmethod
    def get_list_common(list1, list2):
        # list1 = [{'name': 'a', 'age': 20}, {'name': 'b', 'age': 30}, {'name': 'c', 'age': 25}]
        # list2 = [{'name': 'b', 'age': 30}, {'name': 'c', 'age': 25}, {'name': 'd', 'age': 35}]

        intersect = [i for i in set(list1) & set(list2)]
        return intersect

    @staticmethod
    def list_by_ipdomain(ipdomain):
        model = IPDomainModel.objects.filter(ipdomain=ipdomain).first()
        if not model:
            return None
        result = IPDomainSerializer(model).data
        return result

    @staticmethod
    def list(project_id=None, pagination=None, ipdomain_s=None, port_s=None, cdn_flag_s=None, waf_flag_s=None,
             service_s=None):

        # port_s = 443
        # cdn_flag_s = True
        # waf_flag_s = True
        # service_s = "http"

        # ipdomain filter
        filter_models = IPDomainModel.objects.filter(project_id=project_id).order_by('-update_time')

        if ipdomain_s is not None:
            filter_models = filter_models.filter(ipdomain__icontains=ipdomain_s)

        ipdomain_list = filter_models.values_list("ipdomain", flat=True)

        if cdn_flag_s is not None:
            ipdomain_list = CDNModel.objects.filter(ipdomain__in=ipdomain_list).filter(flag=cdn_flag_s).values_list(
                "ipdomain", flat=True)

        # port filter
        if port_s is not None:
            ipdomain_port_list = PortModel.objects.filter(ipdomain__in=ipdomain_list).filter(port=port_s).values_list(
                "ipdomain", "port")
        else:
            ipdomain_port_list = PortModel.objects.filter(ipdomain__in=ipdomain_list).values_list("ipdomain", "port")

        if waf_flag_s is not None:
            tmp_list = WAFModel.objects.filter(ipdomain__in=ipdomain_list).filter(
                flag=waf_flag_s).values_list("ipdomain", "port")
            ipdomain_port_list = IPDomain.get_list_common(tmp_list, ipdomain_port_list)

        if service_s is not None:
            tmp_list = ServiceModel.objects.filter(ipdomain__in=ipdomain_list).filter(
                service__icontains=service_s).values_list("ipdomain", "port")
            ipdomain_port_list = IPDomain.get_list_common(tmp_list, ipdomain_port_list)

        # pagination
        if pagination is None:
            pagination = {'current': 1, 'pageSize': 10}

        start = (pagination['current'] - 1) * pagination['pageSize']
        end = pagination['current'] * pagination['pageSize']
        pagination["total"] = len(ipdomain_port_list)

        # 和符合的ipdomain+port list

        # ipdomain_models = filter_models.order_by('-update_time')[start:end]
        # ipdomain_list = IPDomainSerializer(ipdomain_models, many=True).data

        ipdomains_result = []
        for ipdomain_port_tuple in ipdomain_port_list[start:end]:
            ipdomain = ipdomain_port_tuple[0]
            port = ipdomain_port_tuple[1]
            ipdomain_record = IPDomain.list_by_ipdomain(ipdomain)
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

            # domainicp
            domainicp = DomainICP.get_by_ipdomain(ipdomain)
            ipdomain_record["domainicp"] = domainicp

            # dnsrecord
            dnsrecord = DNSRecord.list_by_ipdomain(ipdomain)
            ipdomain_record["dnsrecord"] = dnsrecord

            # cdn
            cdn = CDN.get_by_ipdomain_port(ipdomain)
            ipdomain_record["cdn"] = cdn

            port_base = Port.get_by_ipdomain_port(ipdomain, port)

            one_record = {}
            one_record.update(ipdomain_record)
            one_record.update(port_base)

            # ports
            if port != 0:
                port_info = Port.get_info_by_ipdomain_port(ipdomain, port)
                one_record['port_info'] = port_info

            ipdomains_result.append(one_record)

        return ipdomains_result, pagination

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
        Port.update_or_create(ipdomain=ipdomain, port=0, webbase_dict=webbase_dict)  # port=0用于储存只与ipdomain相关信息
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
