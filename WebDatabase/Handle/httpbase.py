# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from Lib.log import logger
from WebDatabase.models import HttpBaseModel
from WebDatabase.serializers import HttpBaseSerializer


class HttpBase(object):

    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        try:
            model = HttpBaseModel.objects.filter(ipdomain=ipdomain, port=port).first()
            result = HttpBaseSerializer(model, many=False).data
            return result
        except Exception as E:
            logger.exception(E)
            return None

    @staticmethod
    def update_or_create(ipdomain=None, port=None,
                         title=None, status_code=None, header=None, response=None, body=None, webbase_dict={}):
        # 给出更新PortServiceModel方法

        default_dict = {
            # 'ipdomain': ipdomain,
            # 'port': port,

            'title': title,
            'status_code': status_code,
            'header': header,
            'response': response,
            'body': body,
        }
        default_dict.update(webbase_dict)
        model, create = HttpBaseModel.objects.update_or_create(ipdomain=ipdomain, port=port, defaults=default_dict)
        return create