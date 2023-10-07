# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
import time

from django.db import transaction

from Lib.log import logger
from WebDatabase.models import HttpComponentModel


class HttpComponent(object):

    @staticmethod
    def add_or_update(source=None, source_key=None, data={}, update_time=None,
                      ipdomain=None, port=None,
                      product_dict_values={}, product_type=[], product_catalog=[]):
        # 给出更新PortServiceModel方法
        if update_time is None or update_time == 0:
            update_time = int(time.time())

        default_dict = {
            'source': source,
            "source_key": source_key,
            'data': data,
            'update_time': update_time,

            'ipdomain': ipdomain,
            'port': port,

            'product_dict_values': product_dict_values,
            'product_type': product_type,
            'product_catalog': product_catalog,

        }
        model, create = HttpComponentModel.objects.get_or_create(ipdomain=ipdomain, port=port, source=source,
                                                                 defaults=default_dict)
        if create is True:
            return True
        with transaction.atomic():
            try:
                model = HttpComponentModel.objects.select_for_update().get(ipdomain=ipdomain, port=port, source=source)
                model.source_key = source_key
                model.data = data
                model.update_time = update_time

                model.ipdomain = ipdomain
                model.port = port

                model.product_dict_values = product_dict_values
                model.product_type = product_type
                model.product_catalog = product_catalog

                model.save()
                return True
            except Exception as E:
                logger.error(E)
                return False
