# -*- coding: utf-8 -*-
# @File  : Credential.py
# @Date  : 2019/3/4
# @Desc  :


from Core.lib import logger
from PostLateral.postlateral import Credential as postCredential


class Credential(object):
    def __init__(self):
        pass

    @staticmethod
    def add_credential(username='', password='', password_type='', tag=None, source_module='', host_ipaddress='',
                       desc=''):
        if tag is None:
            tag = {}
        if isinstance(tag, dict) is not True:
            logger.warning('数据类型检查错误,数据 {}'.format(tag))
            tag = {}
        if password is '' or password.find('n.a.(') > 0 or len(password) > 100:
            return False

        result = postCredential.add_or_update(username, password, password_type, tag, source_module, host_ipaddress,
                                              desc)
        return result
