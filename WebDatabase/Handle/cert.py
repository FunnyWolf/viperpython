# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
from Lib.log import logger
from WebDatabase.models import CertModel
from WebDatabase.serializers import CertSerializer


class Cert(object):

    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        try:
            model = CertModel.objects.filter(ipdomain=ipdomain, port=port).first()
            result = CertSerializer(model, many=False).data
            return result
        except Exception as E:
            logger.exception(E)
            return None

    @staticmethod
    def update_or_create(ipdomain=None, port=None, cert=None, jarm=None, webbase_dict={}):
        # 给出更新HttpCertModel方法
        default_dict = {
            # 'ipdomain': ipdomain,
            # 'port': port,

            'cert': cert,
            'jarm': jarm,
        }
        default_dict.update(webbase_dict)
        model, create = CertModel.objects.update_or_create(ipdomain=ipdomain, port=port,
                                                           defaults=default_dict)
        return create
