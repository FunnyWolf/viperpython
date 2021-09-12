# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :
import time

from django.db import transaction

from Lib.api import data_return
from Lib.configs import CODE_MSG_ZH, PortService_MSG_ZH, CODE_MSG_EN, PortService_MSG_EN
from Lib.log import logger
from PostLateral.models import PortServiceModel
from PostLateral.serializers import PortServiceSerializer


class PortService(object):
    def __init__(self):
        pass

    @staticmethod
    def list(ipaddress=None):
        result = PortService.list_by_ipaddress(ipaddress)
        context = data_return(200, result, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        return context

    @staticmethod
    def list_by_ipaddress(ipaddress=None):
        orm_models = PortServiceModel.objects.filter(ipaddress=ipaddress).order_by('port')
        data = PortServiceSerializer(orm_models, many=True).data

        try:
            format_data = PortService.format_banner(data)
        except Exception as E:
            format_data = data
            logger.error(E)
        return format_data

    @staticmethod
    def add_or_update(ipaddress=None, port=None, banner=None, service=None):
        default_dict = {'ipaddress': ipaddress, 'port': port, 'banner': banner, 'service': service,
                        'update_time': int(time.time())}  # 没有此主机数据时新建
        model, created = PortServiceModel.objects.get_or_create(ipaddress=ipaddress, port=port, defaults=default_dict)
        if created is True:
            return True  # 新建后直接返回
        # 有历史数据
        with transaction.atomic():
            try:
                model = PortServiceModel.objects.select_for_update().get(ipaddress=ipaddress, port=port)
                model.banner = banner
                model.service = service
                model.save()
                return True
            except Exception as E:
                logger.error(E)
                return False

    @staticmethod
    def destory(ipaddress=None, port=None):
        try:
            PortServiceModel.objects.filter(ipaddress=ipaddress, port=port).delete()
            context = data_return(204, {}, PortService_MSG_ZH.get(204), PortService_MSG_EN.get(204))
        except Exception as E:
            logger.error(E)
            context = data_return(304, {}, PortService_MSG_ZH.get(304), PortService_MSG_EN.get(304))
        return context

    @staticmethod
    def format_banner(port_service_list=None):
        """将服务信息格式化"""
        for port_service in port_service_list:
            output_str = ""
            if port_service.get('banner').get('vendorproductname'):
                output_str += f"Product: {','.join(port_service.get('banner').get('vendorproductname'))}\t"

            if port_service.get('banner').get('version'):
                output_str += f"Version: {','.join(port_service.get('banner').get('version'))}\t"

            if port_service.get('banner').get('info'):
                info = ",".join(port_service.get('banner').get('info'))
                info = info.replace('\x00', '').replace('\0', '')
                output_str += f"Info: {info}\t"

            if port_service.get('banner').get('hostname'):
                hostname = ",".join(port_service.get('banner').get('hostname'))
                hostname = hostname.replace('\x00', '').replace('\0', '')
                output_str += f"Hostname: {hostname}\t"

            if port_service.get('banner').get('operatingsystem'):
                output_str += f"OS: {','.join(port_service.get('banner').get('operatingsystem'))}\t"

            if port_service.get('banner').get('devicetype'):
                output_str += f"Device: {','.join(port_service.get('banner').get('devicetype'))}\t"

            if port_service.get('banner').get('mac'):
                output_str += f"MAC: {port_service.get('banner').get('mac')}\t"

            if port_service.get('banner').get('other'):
                output_str += f"Raw: {port_service.get('banner').get('other')}\t"
            port_service['banner'] = output_str
        return port_service_list
