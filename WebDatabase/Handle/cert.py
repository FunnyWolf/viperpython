# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import CertModel


class Cert(object):

    @staticmethod
    def update_or_create(ip=None, port=None, cert=None, jarm=None, webbase_dict={}):
        # 给出更新HttpCertModel方法
        default_dict = {
            'ip': ip,
            'port': port,

            'cert': cert,
            'jarm': jarm,
        }
        default_dict.update(webbase_dict)
        model, create = CertModel.objects.update_or_create(ip=ip, port=port,
                                                           defaults=default_dict)
        return create
