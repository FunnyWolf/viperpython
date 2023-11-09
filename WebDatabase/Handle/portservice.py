# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from WebDatabase.Handle.cdn import CDN
from WebDatabase.Handle.cert import Cert
from WebDatabase.Handle.component import Component
from WebDatabase.Handle.httpbase import HttpBase
from WebDatabase.Handle.httpfavicon import HttpFavicon
from WebDatabase.Handle.screenshot import Screenshot
from WebDatabase.models import PortServiceModel
from WebDatabase.serializers import PortServiceSerializer


class PortService(object):

    @staticmethod
    def list_by_ipdomain(ipdomain):
        models = PortServiceModel.objects.filter(ipdomain=ipdomain)
        result = PortServiceSerializer(models, many=True).data
        return result

    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        model = PortServiceModel.objects.filter(ipdomain=ipdomain, port=port).first()
        if not model:
            return None
        result = PortServiceSerializer(model).data
        return result

    @staticmethod
    def get_info_by_ipdomain_port(ipdomain, port):
        portservice = PortService.get_by_ipdomain_port(ipdomain, port)
        if not portservice:
            return None
        service = portservice.get("service")

        result = {}
        result.update(portservice)

        component_list = Component.list_by_ipdomain_port(ipdomain, port)
        result["component_list"] = component_list

        cert = Cert.get_by_ipdomain_port(ipdomain, port)
        result["cert"] = cert

        screenshot = Screenshot.get_by_ipdomain_port(ipdomain, port)
        result["screenshot"] = screenshot

        if service.startswith("http"):
            one_record_http = {}

            httpbase = HttpBase.get_by_ipdomain_port(ipdomain, port)
            one_record_http["httpbase"] = httpbase

            httpfavicon = HttpFavicon.get_by_ipdomain_port(ipdomain, port)
            one_record_http["httpfavicon"] = httpfavicon

            cdn = CDN.get_by_ipdomain_port(ipdomain, port)
            one_record_http["cdn"] = cdn

            result['http'] = one_record_http
        return result

    # portservices_sorted = sorted(port_and_service, key=lambda x: x['port'])
    @staticmethod
    def sort_by_port(a, b):
        if a['port'] < b['port']:
            return 1
        elif b['port'] > a['port']:
            return -1
        else:
            return 0

    @staticmethod
    def update_or_create(ipdomain=None, port=None, transport=None, service=None, version=None, webbase_dict={}):
        # 给出更新PortServiceModel方法

        default_dict = {
            # 'ipdomain': ipdomain,
            # 'port': port,

            'transport': transport,
            'service': service,
            'version': version,
        }
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = PortServiceModel.objects.update_or_create(ipdomain=ipdomain, port=port,
                                                                   defaults=default_dict)
        return created
