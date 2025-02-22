# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.documents import HttpBaseDocument


class HttpBase(object):

    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        doc = HttpBaseDocument(ipdomain=ipdomain, port=port)
        data_dict = doc.get_dict()
        return data_dict

    # @staticmethod
    # def update_or_create(ipdomain=None, port=None,
    #                      title=None, status_code=None, header=None, body=None, webbase_dict={}):
    #     # 给出更新PortServiceModel方法
    #
    #     default_dict = {
    #         # 'ipdomain': ipdomain,
    #         # 'port': port,
    #
    #         'title': title,
    #         'status_code': status_code,
    #         'header': header,
    #         'body': body,
    #     }
    #     default_dict.update(webbase_dict)
    #     model, create = HttpBaseModel.objects.update_or_create(ipdomain=ipdomain, port=port, defaults=default_dict)
    #     return create

    # @staticmethod
    # def delete_by_ipdomain_port(ipdomain, port):
    #     HttpBaseModel.objects.filter(ipdomain=ipdomain, port=port).delete()
    #     return True

# class HttpBaseObject(IPDomainBaseObject, PortBaseObject, WebBaseObject, ConfigBaseObject):
#
#     def __init__(self):
#         super().__init__()
#         self.title = None
#         self.status_code = None
#         self.header = None
#         self.body = None
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
#             'title': self.title,
#             'status_code': self.status_code,
#             'header': self.header,
#             'body': self.body,
#         }
#         model, created = HttpBaseModel.objects.update_or_create(ipdomain=self.ipdomain,
#                                                                 port=self.port,
#                                                                 defaults=default_dict)
#         return model
