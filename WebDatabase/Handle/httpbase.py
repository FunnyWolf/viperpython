# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import HttpBaseModel


class HttpBase(object):

    @staticmethod
    def update_or_create(ip=None, port=None,
                         title=None, status_code=None, header=None, response=None, body=None, webbase_dict={}):
        # 给出更新PortServiceModel方法

        default_dict = {
            'ip': ip,
            'port': port,

            'title': title,
            'status_code': status_code,
            'header': header,
            'response': response,
            'body': body,
        }
        default_dict.update(webbase_dict)
        model, create = HttpBaseModel.objects.update_or_create(ip=ip, port=port, defaults=default_dict)
        return create
