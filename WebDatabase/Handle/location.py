# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import LocationModel
from WebDatabase.serializers import LocationSerializer


class Location(object):

    @staticmethod
    def get_by_ipdomain(ipdomain):
        # models = LocationModel.objects.filter(ipdomain=ipdomain).order_by('-update_time')

        if LocationModel.objects.filter(ipdomain=ipdomain).count() == 0:
            return None

        model = LocationModel.objects.get(ipdomain=ipdomain)
        result = LocationSerializer(model, many=False).data
        return result

    @staticmethod
    def update_or_create(ipdomain=None, isp=None, asname=None, geo_info={}, webbase_dict={}):
        default_dict = {
            # 'ipdomain': ipdomain,
            'isp': isp,
            'asname': asname,
            'geo_info': geo_info,
        }
        default_dict.update(webbase_dict)

        # key + source 唯一,只要最新数据
        model, created = LocationModel.objects.update_or_create(ipdomain=ipdomain, defaults=default_dict)
        return created
