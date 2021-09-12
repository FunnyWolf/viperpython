# -*- coding: utf-8 -*-
# @File  : credential.py
# @Date  : 2021/2/26
# @Desc  :
from Lib.api import data_return
from Lib.configs import CODE_MSG_ZH, Credential_MSG_ZH, CODE_MSG_EN, Credential_MSG_EN
from Lib.log import logger
from PostLateral.models import CredentialModel
from PostLateral.serializers import CredentialSerializer


class Credential(object):
    def __init__(self):
        pass

    @staticmethod
    def list():
        orm_models = CredentialModel.objects.all().order_by('username')
        data = CredentialSerializer(orm_models, many=True).data
        try:
            format_data = Credential.format_tag(data)
        except Exception as E:
            format_data = data
            logger.error(E)
        context = data_return(200, format_data, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        return context

    @staticmethod
    def list_credential():
        orm_models = CredentialModel.objects.all().order_by('username')
        data = CredentialSerializer(orm_models, many=True).data
        return data

    @staticmethod
    def create(username=None, password=None, password_type=None, source_module=None, tag=None):
        if tag is None:
            tag = {}

        model = CredentialModel()
        model.username = username
        model.password = password
        model.tag = tag
        model.password_type = password_type
        model.source_module = source_module
        model.save()
        data = CredentialSerializer(model).data

        context = data_return(201, data, Credential_MSG_ZH.get(201), Credential_MSG_EN.get(201))
        return context

    @staticmethod
    def update(cid=None, desc=None):
        try:
            orm_model = CredentialModel.objects.get(id=cid)
        except Exception as E:
            logger.exception(E)
            context = data_return(404, {}, Credential_MSG_ZH.get(404), Credential_MSG_EN.get(404))
            return context

        orm_model.desc = desc
        orm_model.save()
        data = CredentialSerializer(orm_model).data
        context = data_return(202, data, Credential_MSG_ZH.get(202), Credential_MSG_EN.get(202))
        return context

    @staticmethod
    def destory(cid=None):
        try:
            CredentialModel.objects.filter(id=cid).delete()
            context = data_return(204, {}, Credential_MSG_ZH.get(204), Credential_MSG_EN.get(204))
        except Exception as E:
            logger.error(E)
            context = data_return(304, {}, Credential_MSG_ZH.get(304), Credential_MSG_EN.get(304))
        return context

    @staticmethod
    def add_or_update(username=None, password=None, password_type=None, tag=None, source_module=None,
                      host_ipaddress=None, desc=None):
        if tag is None:
            tag = {}
        if isinstance(tag, dict) is not True:
            logger.warning(f'数据类型检查错误,数据 {tag}')
            tag = {}
        if password == '' or password.find('n.a.(') > 0 or len(password) > 100:
            return False

        # 没有此主机数据时新建
        default_dict = {'username': username,
                        'password': password,
                        'password_type': password_type,
                        'tag': tag,
                        'source_module': source_module,
                        'host_ipaddress': host_ipaddress,
                        'desc': desc}
        CredentialModel.objects.update_or_create(username=username,
                                                 password=password,
                                                 password_type=password_type,
                                                 tag=tag,
                                                 defaults=default_dict)
        return True

    @staticmethod
    def format_tag(credential_list=None):
        """将服务信息格式化"""
        for credential in credential_list:
            if credential.get('password_type') == 'windows':
                try:
                    credential[
                        'tag_zh'] = f"域: {credential.get('tag').get('domain')}  密码类型: {credential.get('tag').get('type')}"
                    credential[
                        'tag_en'] = f"Domain: {credential.get('tag').get('domain')}  Type: {credential.get('tag').get('type')}"
                except Exception as E:
                    logger.warning(E)
                    credential['tag_zh'] = "解析失败"
                    credential['tag_zh'] = "Error"
            elif credential.get('password_type') == 'userinput':
                credential['tag_zh'] = "用户手工输入"
                credential['tag_en'] = "用户手工输入"
            elif credential.get('password_type') == 'browsers':
                credential['tag_zh'] = f"网址: {credential.get('tag_zh').get('url')}"
                credential['tag_en'] = f"URL: {credential.get('tag_zh').get('url')}"
            else:
                credential['tag_zh'] = str(credential.get('tag'))
                credential['tag_en'] = str(credential.get('tag'))

        return credential_list
