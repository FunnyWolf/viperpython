# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from WebDatabase.models import DomainICPModel
from WebDatabase.serializers import DomainICPSerializer


class DomainICP(object):

    @staticmethod
    def get_by_ipdomain(ipdomain):
        model = DomainICPModel.objects.filter(ipdomain=ipdomain).first()
        if not model:
            return None
        result = DomainICPSerializer(model, many=False).data
        return result

    @staticmethod
    def update_or_create(ipdomain=None, unit=None, license=None, webbase_dict={}):
        # 给出更新DomainICPModel的方法

        default_dict = {
            'license': license,
            'unit': unit,
        }
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = DomainICPModel.objects.update_or_create(ipdomain=ipdomain,
                                                                 defaults=default_dict)
        return created
