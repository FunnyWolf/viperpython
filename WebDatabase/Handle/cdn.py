# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import CDNModel
from WebDatabase.serializers import DomainICPSerializer as CDNSerializer


class CDN(object):

    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        if CDNModel.objects.filter(ipdomain=ipdomain, port=port).count() == 0:
            return None

        model = CDNModel.objects.get(ipdomain=ipdomain, port=port)
        result = CDNSerializer(model, many=False).data
        return result

    @staticmethod
    def update_or_create(domain=None, port=None, cname=None, a=None, webbase_dict={}):
        # 给出更新DomainICPModel的方法

        default_dict = {

            'cname': cname,
            'a': a,
        }

        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = CDNModel.objects.update_or_create(ipdomain=domain,
                                                           port=port,
                                                           defaults=default_dict)
        return created
