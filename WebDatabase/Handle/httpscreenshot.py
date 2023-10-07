# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
import time

from django.db import transaction

from Lib.log import logger
from WebDatabase.models import HttpScreenshotModel


class HttpScreenshot(object):

    @staticmethod
    def add_or_update(source=None, source_key=None, data={}, update_time=None,
                      ipdomain=None, port=None,
                      content=None, ):
        if update_time is None or update_time == 0:
            update_time = int(time.time())

        default_dict = {
            'source': source,
            "source_key": source_key,
            'data': data,
            'update_time': update_time,

            'ipdomain': ipdomain,
            'port': port,

            'content': content,
        }

        # key + source 唯一,只要最新数据
        model, created = HttpScreenshotModel.objects.get_or_create(ipdomain=ipdomain, port=port, source=source,
                                                                   defaults=default_dict)
        if created is True:
            return True  # 新建后直接返回
        # 有历史数据
        with transaction.atomic():
            try:
                model = HttpScreenshotModel.objects.select_for_update().get(ipdomain=ipdomain, port=port, source=source)

                model.source_key = source_key
                model.data = data
                model.update_time = update_time

                model.ipdomain = ipdomain
                model.port = port

                model.content = content

                model.save()
                return True
            except Exception as E:
                logger.error(E)
                return False
