# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
import time

from django.db import transaction

from Lib.api import data_return
from Lib.configs import IPDomain_MSG_ZH, \
    IPDomain_MSG_EN
from Lib.log import logger
from WebDatabase.models import IPDomainModel


class IPDomain(object):

    @staticmethod
    def add_or_update(ipdomain=None, type=None, source=None, source_key=None, data={}, update_time=None):
        if update_time is None or update_time == 0:
            update_time = int(time.time())

        default_dict = {'ipdomain': ipdomain,
                        'type': type,
                        'source': source,
                        "source_key": source_key,
                        'data': data,
                        'update_time': update_time}  # 没有此主机数据时新建
        model, created = IPDomainModel.objects.get_or_create(ipdomain=ipdomain, defaults=default_dict)
        if created is True:
            return True  # 新建后直接返回
        # 有历史数据
        with transaction.atomic():
            try:
                model = IPDomainModel.objects.select_for_update().get(ipdomain=ipdomain)
                model.type = type
                model.source = source
                model.data = data
                model.update_time = update_time
                model.save()
                return True
            except Exception as E:
                logger.error(E)
                return False

    @staticmethod
    def destory(ipdomain=None):
        try:
            IPDomainModel.objects.filter(ipdomain=ipdomain).delete()
            context = data_return(204, {}, IPDomain_MSG_ZH.get(204), IPDomain_MSG_EN.get(204))
        except Exception as E:
            logger.error(E)
            context = data_return(304, {}, IPDomain_MSG_ZH.get(304), IPDomain_MSG_EN.get(304))
        return context
