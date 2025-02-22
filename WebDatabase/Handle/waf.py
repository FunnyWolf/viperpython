# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from WebDatabase.documents import WAFDocument


class WAF(object):

    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        doc = WAFDocument(ipdomain=ipdomain, port=port)
        return doc.get_dict()

    # @staticmethod
    # def update_or_create(ipdomain=None, port=None, flag=None, trigger_url=None, name=None, manufacturer=None,
    #                      webbase_dict={}):
    #     default_dict = {
    #         'flag': flag,
    #         'trigger_url': trigger_url,
    #         'name': name,
    #         'manufacturer': manufacturer,
    #     }
    #     default_dict.update(webbase_dict)
    #     # key + source 唯一,只要最新数据
    #
    #     model, created = WAFModel.objects.update_or_create(ipdomain=ipdomain, port=port,
    #                                                        defaults=default_dict)
    #     return created

    # @staticmethod
    # def delete_by_ipdomain_port(ipdomain, port):
    #     WAFModel.objects.filter(ipdomain=ipdomain, port=port).delete()
    #     return True

#
# class WAFObject(IPDomainBaseObject, PortBaseObject, WebBaseObject, ConfigBaseObject):
#     def __init__(self):
#         super().__init__()
#         self.flag = None
#         self.trigger_url = None
#         self.name = None
#         self.manufacturer = None
#
#     def update_or_create(self):
#         default_dict = {
#             'source': self.source,
#             'data': self.data,
#             'update_time': self.update_time,
#
#             'ipdomain': self.ipdomain,
#             'port': self.port,
#
#             'flag': self.flag,
#             'trigger_url': self.trigger_url,
#             'name': self.name,
#             'manufacturer': self.manufacturer,
#         }
#         model, created = WAFModel.objects.update_or_create(ipdomain=self.ipdomain,
#                                                            port=self.port,
#                                                            defaults=default_dict)
#         return model
