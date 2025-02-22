# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from WebDatabase.documents import ScreenshotDocument


class Screenshot(object):
    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        doc = ScreenshotDocument(ipdomain=ipdomain)
        return doc.get_dict()

    # @staticmethod
    # def update_or_create(ipdomain=None, port=None,
    #                      content=None, webbase_dict={}):
    #     default_dict = {
    #         # 'ipdomain': ipdomain,
    #         # 'port': port,
    #
    #         'content': content,
    #     }
    #     default_dict.update(webbase_dict)
    #     # key + source 唯一,只要最新数据
    #
    #     model, created = ScreenshotModel.objects.update_or_create(ipdomain=ipdomain, port=port,
    #                                                               defaults=default_dict)
    #     return created
    #
    # @staticmethod
    # def delete_by_ipdomain_port(ipdomain, port):
    #     ScreenshotModel.objects.filter(ipdomain=ipdomain, port=port).delete()
    #     return True

# class ScreenshotObject(IPDomainBaseObject, PortBaseObject, WebBaseObject, ConfigBaseObject):
#     def __init__(self):
#         super().__init__()
#         self.content = None
#
#     def update_or_create(self):
#         # 空不入库
#         if self.content == "" or self.content is None:
#             return None
#
#         default_dict = {
#             'source': self.source,
#             'data': self.data,
#             'update_time': self.update_time,
#
#             'ipdomain': self.ipdomain,
#             'port': self.port,
#
#             'content': self.content,
#         }
#         model, created = ScreenshotModel.objects.update_or_create(ipdomain=self.ipdomain,
#                                                                   port=self.port,
#                                                                   defaults=default_dict)
#         return model
