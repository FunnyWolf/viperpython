# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from Lib.log import logger
from WebDatabase.models import LocationModel
from WebDatabase.serializers import LocationSerializer


class Location(object):

    @staticmethod
    def get_by_ipdomain(ipdomain):
        try:
            model = LocationModel.objects.filter(ipdomain=ipdomain).first()
            result = LocationSerializer(model, many=False).data
            return result
        except Exception as E:
            logger.exception(E)
            return None

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
