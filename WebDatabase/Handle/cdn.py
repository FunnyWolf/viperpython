# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from django.db import transaction

from WebDatabase.models import CDNModel
from WebDatabase.serializers import CDNSerializer


class CDN(object):

    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        model = CDNModel.objects.filter(ipdomain=ipdomain, port=port).first()
        if not model:
            return None
        result = CDNSerializer(model, many=False).data
        return result

    @staticmethod
    def update_or_create(domain=None, port=None, flag=None, webbase_dict={}):
        # 给出更新DomainICPModel的方法

        default_dict = {
            'flag': flag,
        }

        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        with transaction.atomic():
            model, created = CDNModel.objects.update_or_create(ipdomain=domain,
                                                               port=port,
                                                               defaults=default_dict)
        return created
