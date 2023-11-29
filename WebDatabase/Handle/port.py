# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.Handle.cert import Cert
from WebDatabase.Handle.component import Component
from WebDatabase.Handle.httpbase import HttpBase
from WebDatabase.Handle.httpfavicon import HttpFavicon
from WebDatabase.Handle.screenshot import Screenshot
from WebDatabase.Handle.service import Service
from WebDatabase.Handle.waf import WAF
from WebDatabase.models import PortModel
from WebDatabase.serializers import PortSerializer


class Port(object):

    @staticmethod
    def list_by_ipdomain_and_filter(ipdomain, port):
        models = PortModel.objects.filter(ipdomain=ipdomain)
        if port:
            models = models.filter(port=port)
        result = PortSerializer(models, many=True).data
        return result

    @staticmethod
    def get_info_by_ipdomain_port(ipdomain, port):
        portservice = Service.get_by_ipdomain_port(ipdomain, port)
        if not portservice:
            return None

        result = {}
        result['service'] = portservice

        components = Component.list_by_ipdomain_port(ipdomain, port)
        result["components"] = components

        cert = Cert.get_by_ipdomain_port(ipdomain, port)
        result["cert"] = cert

        screenshot = Screenshot.get_by_ipdomain_port(ipdomain, port)
        result["screenshot"] = screenshot

        service = portservice.get("service")
        if service.startswith("http"):
            httpbase = HttpBase.get_by_ipdomain_port(ipdomain, port)
            result["http_base"] = httpbase

            httpfavicon = HttpFavicon.get_by_ipdomain_port(ipdomain, port)
            result["http_favicon"] = httpfavicon

            # waf
            waf = WAF.get_by_ipdomain_port(ipdomain, port)
            result["waf"] = waf

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
    def update_or_create(ipdomain=None, port=None, webbase_dict={}):
        # 给出更新PortServiceModel方法

        default_dict = {}
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = PortModel.objects.update_or_create(ipdomain=ipdomain, port=port,
                                                            defaults=default_dict)
        return created
