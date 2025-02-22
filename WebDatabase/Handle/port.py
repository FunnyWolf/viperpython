# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from WebDatabase.documents import PortDocument


class Port(object):

    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):

        doc = PortDocument(ipdomain=ipdomain, port=port)
        return doc.get_dict()

    # @staticmethod
    # def list_by_ipdomain_and_filter(ipdomain, port):
    #     model = PortModel.objects.filter(ipdomain=ipdomain, port=port).first()
    #     if not model:
    #         return None
    #     result = PortSerializer(model).data
    #     return result

    # @staticmethod
    # def get_by_ipdomain_port(ipdomain, port):
    #     port_base = Port.list_by_ipdomain_and_filter(ipdomain, port)
    #     if not port_base:
    #         raise Exception(f"IPDomain with no port {ipdomain}:{port}")
    #     return port_base

    # @staticmethod
    # def get_info_by_ipdomain_port(ipdomain, port):
    #     port_base = Port.get_by_ipdomain_port(ipdomain, port)
    #     if not port_base:
    #         return None
    #
    #     result = {}
    #     result.update(port_base)
    #     portservice = Service.get_by_ipdomain_port(ipdomain, port)
    #
    #     # service
    #     result['service'] = portservice
    #
    #     # components
    #     components = Component.list_by_ipdomain_port(ipdomain, port)
    #     result["components"] = components
    #
    #     # cert
    #     cert = CertDocument(ipdomain=ipdomain, port=port).get_dict()
    #     result["cert"] = cert
    #
    #     # screenshot
    #     screenshot = Screenshot.get_by_ipdomain_port(ipdomain, port)
    #     result["screenshot"] = screenshot
    #
    #     # vulnerabilitys
    #     vulnerabilitys = Vulnerability.list_by_ipdomain_port(ipdomain=ipdomain, port=port)
    #     result["vulnerabilitys"] = vulnerabilitys
    #
    #     if portservice:
    #         service_name = portservice.get("service")
    #         if service_name.startswith("http"):
    #             httpbase = HttpBase.get_by_ipdomain_port(ipdomain, port)
    #             if httpbase is not None:
    #                 httpbase['url'] = Port.group_url_by_ipdomain_record(ipdomain, port, service_name)
    #
    #             result["http_base"] = httpbase
    #
    #             httpfavicon = HttpFavicon.get_by_ipdomain_port(ipdomain, port)
    #             result["http_favicon"] = httpfavicon
    #
    #             # waf
    #             waf = WAF.get_by_ipdomain_port(ipdomain, port)
    #             result["waf"] = waf
    #
    #     return result

    # portservices_sorted = sorted(port_and_service, key=lambda x: x['port'])

    @staticmethod
    def sort_by_port(a, b):
        if a['port'] < b['port']:
            return 1
        elif b['port'] > a['port']:
            return -1
        else:
            return 0

    # @staticmethod
    # def update_or_create(ipdomain=None, port=None, webbase_dict={}):
    #     # 给出更新PortServiceModel方法
    #
    #     default_dict = {}
    #     default_dict.update(webbase_dict)
    #     # key + source 唯一,只要最新数据
    #     model, created = PortModel.objects.update_or_create(ipdomain=ipdomain, port=port,
    #                                                         defaults=default_dict)
    #     return created

    @staticmethod
    def update_commnet_by_ipdomain_port(ipdomain=None, port=None, color=None, comment=None):
        doc = PortDocument(ipdomain=ipdomain, port=port, color=color, comment=comment)
        doc_dict = doc.update_or_create()
        return doc_dict

    @staticmethod
    def group_url_by_ipdomain_record(ipdomain, port, service_name):
        return f"{service_name}://{ipdomain}:{port}"

    # def delete_by_ipdomain_list(self, ipdomain_list):
    #     ipdomain_port_tuple_list = PortModel.objects.filter(ipdomain__in=ipdomain_list).values_list("ipdomain", "port")
    #     for ipdomain, port in ipdomain_port_tuple_list:
    #         PortModel.objects.filter(ipdomain=ipdomain, port=port).delete()
    #
    #     return ipdomain_port_tuple_list

# class PortObject(IPDomainBaseObject, PortBaseObject, WebBaseObject, ConfigBaseObject):
#     def __init__(self):
#         super().__init__()
#         self.alive = True
#         self.color = None
#         self.comment = None
#
#     def update_or_create(self):
#         default_dict = {
#             'source': self.source,
#             'data': self.data,
#             'update_time': self.update_time,
#
#             'ipdomain': self.ipdomain,
#
#             'port': self.port,
#             'alive': self.alive,
#             'color': self.color,
#             'comment': self.comment,
#         }
#         model, create = PortModel.objects.update_or_create(ipdomain=self.ipdomain,
#                                                            port=self.port,
#                                                            defaults=default_dict)
#         return model
