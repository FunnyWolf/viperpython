# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from Lib.api import data_return
from Lib.configs import IPDomain_MSG_ZH, IPDomain_MSG_EN
from Lib.log import logger
from WebDatabase.models import IPDomainModel
from WebDatabase.serializers import IPDomainSerializer


class IPDomain(object):

    @staticmethod
    def list_all():
        models = IPDomainModel.objects.all()
        result = IPDomainSerializer(models, many=True).data
        return result

    @staticmethod
    def update_or_create(project_id=None,
                         ipdomain=None, webbase_dict={}):

        default_dict = {
            # 'ipdomain': ipdomain,
            'project_id': project_id,
        }
        default_dict.update(webbase_dict)
        # key + source 唯一,只要最新数据
        model, created = IPDomainModel.objects.update_or_create(ipdomain=ipdomain,
                                                                defaults=default_dict)
        return created

    @staticmethod
    def destory(ip=None):
        try:
            IPDomainModel.objects.filter(ipdomain=ip).delete()
            context = data_return(204, {}, IPDomain_MSG_ZH.get(204), IPDomain_MSG_EN.get(204))
        except Exception as E:
            logger.error(E)
            context = data_return(304, {}, IPDomain_MSG_ZH.get(304), IPDomain_MSG_EN.get(304))
        return context
