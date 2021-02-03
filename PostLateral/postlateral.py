# -*- coding: utf-8 -*-
# @File  : postlateral.py
# @Date  : 2019/2/20
# @Desc  :

import time

from django.db import transaction

from Core.configs import *
from Core.core import logger, list_data_return, dict_data_return
from PostLateral.models import *
from PostLateral.serializers import *


class PortService(object):
    def __init__(self):
        pass

    @staticmethod
    def list(hid=None):
        result = PortService.list_by_hid(hid)
        context = list_data_return(200, CODE_MSG.get(200), result)
        return context

    @staticmethod
    def list_by_hid(hid=None):
        orm_models = PortServiceModel.objects.filter(hid=hid).order_by('port')
        data = PortServiceSerializer(orm_models, many=True).data

        try:
            format_data = PortService.format_banner(data)
        except Exception as E:
            format_data = data
            logger.error(E)
        return format_data

    @staticmethod
    def add_or_update(hid=None, port=None, proxy=None, banner=None, service=None):
        default_dict = {'hid': hid, 'proxy': proxy, 'port': port, 'banner': banner, 'service': service,
                        'update_time': int(time.time())}  # 没有此主机数据时新建
        model, created = PortServiceModel.objects.get_or_create(hid=hid, port=port, defaults=default_dict)
        if created is True:
            return True  # 新建后直接返回
        # 有历史数据
        with transaction.atomic():
            try:
                model = PortServiceModel.objects.select_for_update().get(hid=hid, port=port)
                model.proxy = proxy
                model.banner = banner
                model.service = service
                model.save()
                return True
            except Exception as E:
                logger.error(E)
                return False

    @staticmethod
    def destory(hid=None, port=None):
        try:
            PortServiceModel.objects.filter(hid=hid, port=port).delete()
            context = dict_data_return(204, PortService_MSG.get(204), {})
        except Exception as E:
            logger.error(E)
            context = dict_data_return(304, PortService_MSG.get(304), {})
        return context

    @staticmethod
    def format_banner(port_service_list=None):
        """将服务信息格式化"""
        for port_service in port_service_list:
            output_str = ""
            if port_service.get('banner').get('vendorproductname'):
                output_str += "软件: {}\t".format(",".join(port_service.get('banner').get('vendorproductname')))
            if port_service.get('banner').get('version'):
                output_str += "版本: {}\t".format(",".join(port_service.get('banner').get('version')))
            if port_service.get('banner').get('info'):
                info = ",".join(port_service.get('banner').get('info'))
                info = info.replace('\x00', '').replace('\0', '')
                output_str += "信息: {}\t".format(info)
            if port_service.get('banner').get('hostname'):
                hostname = ",".join(port_service.get('banner').get('hostname'))
                hostname = hostname.replace('\x00', '').replace('\0', '')
                output_str += "主机名: {}\t".format(hostname)
            if port_service.get('banner').get('operatingsystem'):
                output_str += "操作系统: {}\t".format(",".join(port_service.get('banner').get('operatingsystem')))
            if port_service.get('banner').get('devicetype'):
                output_str += "设备类型: {}\t".format(",".join(port_service.get('banner').get('devicetype')))

            if port_service.get('banner').get('mac'):
                output_str += "MAC地址: {}\t".format(port_service.get('banner').get('mac'))
            port_service['banner'] = output_str
        return port_service_list


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
        context = list_data_return(200, CODE_MSG.get(200), format_data)
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

        context = dict_data_return(201, Credential_MSG.get(201), data)
        return context

    @staticmethod
    def update(cid=None, desc=None):
        try:
            orm_model = CredentialModel.objects.get(id=cid)
        except Exception as E:
            logger.exception(E)
            context = dict_data_return(404, Credential_MSG.get(404), {})
            return context

        orm_model.desc = desc
        orm_model.save()
        data = CredentialSerializer(orm_model).data
        context = dict_data_return(202, Credential_MSG.get(202), data)
        return context

    @staticmethod
    def destory(cid=None):
        try:
            CredentialModel.objects.filter(id=cid).delete()
            context = dict_data_return(204, Credential_MSG.get(204), {})
        except Exception as E:
            logger.error(E)
            context = dict_data_return(304, Credential_MSG.get(304), {})
        return context

    @staticmethod
    def add_or_update(username=None, password=None, password_type=None, tag=None, source_module=None,
                      host_ipaddress=None, desc=None):

        # 没有此主机数据时新建
        default_dict = {'username': username, 'password': password, 'password_type': password_type, 'tag': tag,
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
                    output_str = "域: {}  密码类型: {}".format(credential.get('tag').get('domain'),
                                                          credential.get('tag').get('type'))
                except Exception as E:
                    logger.warning(E)
                    output_str = "解析失败"
                credential['tag'] = output_str
            elif credential.get('password_type') == 'userinput':
                credential['tag'] = "用户手工输入"
            elif credential.get('password_type') == 'browsers':
                # credential['tag'] = "网址: {} 浏览器: {}".format(credential.get('tag').get('url'),
                #                                             credential.get('tag').get('browser'))
                credential['tag'] = "网址: {}".format(credential.get('tag').get('url'))
            else:
                credential['tag'] = str(credential.get('tag'))

        return credential_list


class Vulnerability(object):
    """存储扫描到的漏洞信息,以hid为维度处理"""

    def __init__(self):
        pass

    @staticmethod
    def list(hid=None):
        data = Vulnerability.list_vulnerability(hid=hid)
        try:
            format_data = Vulnerability.format_source_module(data)
        except Exception as E:
            format_data = data
            logger.error(E)
        context = list_data_return(200, CODE_MSG.get(200), format_data)
        return context

    @staticmethod
    def list_vulnerability(hid=None):
        if hid is None:
            orm_models = VulnerabilityModel.objects.all().order_by('source_module_loadpath')
        else:
            orm_models = VulnerabilityModel.objects.filter(hid=hid).order_by('source_module_loadpath')
        data = VulnerabilitySerializer(orm_models, many=True).data
        return data

    @staticmethod
    def destory(vid=None):
        try:
            VulnerabilityModel.objects.filter(id=vid).delete()
            context = dict_data_return(204, Vulnerability_MSG.get(204), {})
        except Exception as E:
            logger.error(E)
            context = dict_data_return(304, Vulnerability_MSG.get(304), {})
        return context

    @staticmethod
    def add_or_update(hid=None, source_module_loadpath=None, extra_data=None, desc=None):
        default_dict = {'hid': hid, 'source_module_loadpath': source_module_loadpath, 'extra_data': extra_data,
                        'desc': desc, 'update_time': int(time.time())}  # 没有此主机数据时新建
        model, created = VulnerabilityModel.objects.get_or_create(hid=hid,
                                                                  source_module_loadpath=source_module_loadpath,
                                                                  extra_data=extra_data, defaults=default_dict)
        if created is True:
            return True  # 新建后直接返回
        # 有历史数据
        with transaction.atomic():
            try:
                model = VulnerabilityModel.objects.select_for_update().get(hid=hid,
                                                                           source_module_loadpath=source_module_loadpath,
                                                                           extra_data=extra_data, )
                model.hid = hid
                model.source_module_loadpath = source_module_loadpath
                model.update_time = int(time.time())
                model.extra_data = extra_data
                model.desc = desc
                model.save()
                return True
            except Exception as E:
                logger.error(E)
                return False

    @staticmethod
    def format_source_module(vulnerability_list=None):
        """将服务信息格式化"""
        for vulnerability in vulnerability_list:
            from PostModule.postmodule import PostModuleConfig
            module_name = PostModuleConfig.get_module_name_by_loadpath(vulnerability.get('source_module_loadpath'))
            vulnerability['source_module_name'] = module_name
        return vulnerability_list
