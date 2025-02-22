# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.documents import CDNDocument


class CDN(object):
    @staticmethod
    def get_by_ipdomain(ipdomain):
        doc = CDNDocument(ipdomain=ipdomain)
        return doc.get_dict()

# class CDNObject(IPDomainBaseObject, WebBaseObject, ConfigBaseObject):
#
#     def __init__(self):
#         super().__init__()
#         self.flag = None
#         self.domain = None
#         self.name = None
#         self.link = None
#
#     def update_or_create(self):
#         default_dict = {
#             'source': self.source,
#             'data': self.data,
#             'update_time': self.update_time,
#
#             'ipdomain': self.ipdomain,
#
#             'flag': self.flag,
#             'domain': self.domain,
#             'name': self.name,
#             'link': self.link,
#         }
#         model, create = CDNModel.objects.update_or_create(ipdomain=self.ipdomain,
#                                                           defaults=default_dict)
#         return create
