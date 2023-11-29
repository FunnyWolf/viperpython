# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import CDNModel
from WebDatabase.serializers import CDNSerializer


class CDN(object):

    @staticmethod
    def get_by_ipdomain_port(ipdomain):
        model = CDNModel.objects.filter(ipdomain=ipdomain).first()
        if not model:
            return None
        result = CDNSerializer(model, many=False).data
        return result

    @staticmethod
    def update_or_create(domain=None, flag=None, webbase_dict={}):
        # 给出更新DomainICPModel的方法

        default_dict = {
            'flag': flag,
        }

        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = CDNModel.objects.update_or_create(ipdomain=domain,
                                                           defaults=default_dict)
        return created

    @staticmethod
    def is_cdn_record(cname):
        if cname is None or len(cname) == 0:
            return False
        else:
            return True
