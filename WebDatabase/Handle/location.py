# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
import time

from django.db import transaction

from Lib.log import logger
from WebDatabase.models import LocationModel


class Location(object):

    @staticmethod
    def add_or_update(source=None, source_key=None, data={}, update_time=None,
                      ipdomain=None, isp=None, asname=None, geo_info={}, ):

        if update_time is None or update_time == 0:
            update_time = int(time.time())

        default_dict = {
            'source': source,
            "source_key": source_key,
            'data': data,
            'update_time': update_time,
            'ipdomain': ipdomain,

            'isp': isp,
            'asname': asname,
            'geo_info': geo_info,
        }

        # key + source 唯一,只要最新数据
        model, created = LocationModel.objects.get_or_create(ipdomain=ipdomain, source=source, defaults=default_dict)
        if created is True:
            return True  # 新建后直接返回
        # 有历史数据
        with transaction.atomic():
            try:
                model = LocationModel.objects.select_for_update().get(ipdomain=ipdomain, source=source)

                model.source_key = source_key
                model.data = data
                model.update_time = update_time

                model.isp = isp
                model.asname = asname
                model.geo_info = geo_info

                model.save()
                return True
            except Exception as E:
                logger.error(E)
                return False
