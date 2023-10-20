# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import LocationModel
from WebDatabase.serializers import LocationSerializer


class Location(object):

    @staticmethod
    def list_by_ip(ip):
        models = LocationModel.objects.filter(ip=ip).order_by('-update_time')[:1]
        result = LocationSerializer(models, many=False).data
        return result

    @staticmethod
    def update_or_create(ip=None, isp=None, asname=None, geo_info={}, webbase_dict={}):
        default_dict = {
            'ip': ip,
            'isp': isp,
            'asname': asname,
            'geo_info': geo_info,
        }
        default_dict.update(webbase_dict)

        # key + source 唯一,只要最新数据
        model, created = LocationModel.objects.update_or_create(ip=ip, defaults=default_dict)
        return created
