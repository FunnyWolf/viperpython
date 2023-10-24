# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from WebDatabase.models import CertModel
from WebDatabase.serializers import CertSerializer


class Cert(object):

    @staticmethod
    def get_by_ipdomain_port(ipdomain, port):
        if CertModel.objects.filter(ipdomain=ipdomain, port=port).count() == 0:
            return None

        model = CertModel.objects.get(ipdomain=ipdomain, port=port)
        result = CertSerializer(model, many=False).data
        return result

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
