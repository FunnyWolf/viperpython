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
from WebDatabase.Handle.vulnerability import Vulnerability
from WebDatabase.Handle.waf import WAF
from WebDatabase.models import PortModel
from WebDatabase.serializers import PortSerializer


class Port(object):

    @staticmethod
    def list_by_ipdomain_and_filter(ipdomain, port):
        model = PortModel.objects.filter(ipdomain=ipdomain, port=port).first()
        if not model:
            return None
        result = PortSerializer(model).data
        return result

    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        port_base = Port.list_by_ipdomain_and_filter(ipdomain, port)
        if not port_base:
            raise Exception(f"IPDomain with no port {ipdomain}:{port}")
        return port_base

    @staticmethod
    def get_info_by_ipdomain_port(ipdomain, port):
        port_base = Port.list_by_ipdomain_and_filter(ipdomain, port)
        if not port_base:
            return None

        result = {}
        result.update(port_base)
        portservice = Service.get_by_ipdomain_port(ipdomain, port)
        result['service'] = portservice

        components = Component.list_by_ipdomain_port(ipdomain, port)
        result["components"] = components

        cert = Cert.get_by_ipdomain_port(ipdomain, port)
        result["cert"] = cert

        screenshot = Screenshot.get_by_ipdomain_port(ipdomain, port)
        result["screenshot"] = screenshot

        vulnerabilitys = Vulnerability.list_by_ipdomain_port(ipdomain=ipdomain, port=port)
        result["vulnerabilitys"] = vulnerabilitys

        if portservice:
            service_name = portservice.get("service")
            if service_name.startswith("http"):
                httpbase = HttpBase.get_by_ipdomain_port(ipdomain, port)
                if httpbase is not None:
                    httpbase['url'] = Port.group_url_by_ipdomain_record(ipdomain, port, service_name)

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

    @staticmethod
    def update_commnet_by_ipdomain_port(ipdomain=None, port=None, color=None, comment=None):
        rows = PortModel.objects.filter(ipdomain=ipdomain, port=port).update(color=color, comment=comment)
        return rows

    @staticmethod
    def group_url_by_ipdomain_record(ipdomain, port, service_name):
        if service_name == "http/ssl":
            url = f"https://{ipdomain}:{port}"
            return url
        elif service_name == "http":
            url = f"http://{ipdomain}:{port}"
            return url
        else:
            return None
