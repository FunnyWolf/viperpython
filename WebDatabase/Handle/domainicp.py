# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import DomainICPModel
from WebDatabase.serializers import DomainICPSerializer


class DomainICP(object):

    @staticmethod
    def list_by_ipports(ip, port):
        models = DomainICPModel.objects.filter(ip=ip, port=port).order_by('-update_time')[:1]
        result = DomainICPSerializer(models, many=False).data
        return result

    @staticmethod
    def update_or_create(ip=None, port=None,
                         domain_icp=None, unit=None, license=None, webbase_dict={}):
        # 给出更新DomainICPModel的方法

        default_dict = {
            'ip': ip,
            'port': port,
            'license': license,
            'domain_icp': domain_icp,
            'unit': unit,
        }
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = DomainICPModel.objects.update_or_create(ip=ip,
                                                                 defaults=default_dict)
        return created
