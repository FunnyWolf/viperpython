# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
import time

from django.db import transaction

from Lib.log import logger
from WebDatabase.models import DomainICPModel


class DomainICP(object):

    @staticmethod
    def add_or_update(source=None, source_key=None, data={}, update_time=None,
                      ipdomain=None,
                      license=None, content_type_name=None, nature=None, unit=None):
        # 给出更新DomainICPModel的方法
        if update_time is None or update_time == 0:
            update_time = int(time.time())

        default_dict = {
            'source': source,
            "source_key": source_key,
            'data': data,
            'update_time': update_time,
            'ipdomain': ipdomain,
            'license': license,
            "content_type_name": content_type_name,
            "nature": nature,
            "unit": unit,
        }

        # key + source 唯一,只要最新数据
        model, created = DomainICPModel.objects.get_or_create(ipdomain=ipdomain, source=source, defaults=default_dict)
        if created is True:
            return True  # 新建后直接返回
        # 有历史数据
        with transaction.atomic():
            try:
                model = DomainICPModel.objects.select_for_update().get(ipdomain=ipdomain, source=source)

                model.source_key = source_key
                model.data = data
                model.update_time = update_time

                model.license = license
                model.content_type_name = content_type_name
                model.nature = nature
                model.unit = unit
                model.save()
                return True
            except Exception as E:
                logger.error(E)
                return False
