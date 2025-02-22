# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.documents import CertDocument


class Cert(object):
    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        doc = CertDocument(ipdomain=ipdomain, port=port)
        return doc.get_dict()

# @staticmethod
# def update_or_create(ipdomain=None, port=None, cert=None, jarm=None, subject={}, webbase_dict={}):
#     # 给出更新HttpCertModel方法
#     default_dict = {
#         'subject': subject,
#         'cert': cert,
#         'jarm': jarm,
#     }
#     default_dict.update(webbase_dict)
#     model, create = CertModel.objects.update_or_create(ipdomain=ipdomain, port=port,
#                                                        defaults=default_dict)
#     return create

# class CertObject(IPDomainBaseObject, PortBaseObject, WebBaseObject, ConfigBaseObject):
#
#     def __init__(self):
#         super().__init__()
#         self.subject = {}
#         self.cert = None
#         self.jarm = None
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
#             'subject': self.subject,
#             'cert': self.cert,
#             'jarm': self.jarm,
#         }
#         model, created = CertModel.objects.update_or_create(ipdomain=self.ipdomain,
#                                                             port=self.port,
#                                                             defaults=default_dict)
#         return model
