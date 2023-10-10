# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from Lib.api import data_return
from Lib.configs import IPDomain_MSG_ZH, \
    IPDomain_MSG_EN
from Lib.log import logger
from WebDatabase.models import IPDomainModel
from WebDatabase.serializers import IPDomainSerializer


class IPDomain(object):

    @staticmethod
    def list_ipdomain():
        models = IPDomainModel.objects.all()
        result = IPDomainSerializer(models, many=True).data
        return result

    @staticmethod
    def update_or_create(project_id=None, source=None, source_key=None, data={}, update_time=0,
                         ip=None, domain=None):
        if update_time is None:
            update_time = 0

        default_dict = {
            'project_id': project_id,
            'source': source,
            "source_key": source_key,
            'data': data,
            'update_time': update_time,

            'ip': ip,
            'domain': domain,
        }

        # key + source 唯一,只要最新数据
        model, created = IPDomainModel.objects.update_or_create(ip=ip, domain=domain, source=source,
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
