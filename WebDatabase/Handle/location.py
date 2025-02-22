# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from WebDatabase.documents import LocationDocument


class Location(object):

    @staticmethod
    def get_by_ipdomain(ipdomain):
        doc = LocationDocument(ipdomain=ipdomain)
        return doc.get_dict()

    # @staticmethod
    # def update_or_create(ipdomain=None, isp=None, asname=None, geo_info={}, webbase_dict={}):
    #     default_dict = {
    #         'isp': isp,
    #         'asname': asname,
    #         'geo_info': geo_info,
    #     }
    #     default_dict.update(webbase_dict)
    #
    #     # key + source 唯一,只要最新数据
    #     model, created = LocationModel.objects.update_or_create(ipdomain=ipdomain, defaults=default_dict)
    #     return created

    # @staticmethod
    # def delete_by_ipdomain(ipdomain):
    #     LocationModel.objects.filter(ipdomain=ipdomain).delete()
    #     return True

# class LocationObject(IPDomainBaseObject, WebBaseObject, ConfigBaseObject):
#     def __init__(self):
#         super().__init__()
#
#         self.isp = None
#         self.asname = None
#
#         self.scene_cn = None
#         self.scene_en = None
#
#         self.country_cn = None
#         self.country_en = None
#         self.province_cn = None
#         self.province_en = None
#         self.city_cn = None
#         self.city_en = None
#
#     def update_or_create(self):
#         default_dict = {
#             'ipdomain': self.ipdomain,
#
#             'source': self.source,
#             'data': self.data,
#             'update_time': self.update_time,
#
#             'isp': self.isp,
#             'asname': self.asname,
#
#             'scene_cn': self.scene_cn,
#             'scene_en': self.scene_en,
#             'country_cn': self.country_cn,
#             'country_en': self.country_en,
#             'province_cn': self.province_cn,
#             'province_en': self.province_en,
#             'city_cn': self.city_cn,
#             'city_en': self.city_en,
#         }
#         model, created = LocationModel.objects.update_or_create(ipdomain=self.ipdomain,
#                                                                 defaults=default_dict)
#         return model
