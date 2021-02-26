# -*- coding: utf-8 -*-
# @File  : host.py
# @Date  : 2021/2/25
# @Desc  :
from django.db import transaction

from Core.models import HostModel
from Core.serializers import HostSerializer
from Lib.api import data_return
from Lib.configs import CODE_MSG, Host_MSG
from Lib.log import logger
from Lib.xcache import Xcache
from PostLateral.Handle.portservice import PortService
from PostLateral.models import PortServiceModel, VulnerabilityModel


class Host(object):
    REGISTER_DESTORY = [PortServiceModel, VulnerabilityModel]  # 删除Host时同时删除列表中的数据

    def __init__(self):
        pass

    @staticmethod
    def list():
        hosts = Host.list_hosts()
        for host in hosts:
            hid = host.get('id')
            host['portService'] = PortService.list_by_hid(hid)

        context = data_return(200, CODE_MSG.get(200), hosts)
        return context

    @staticmethod
    def get_by_ipaddress(ipaddress=None):
        try:
            model = HostModel.objects.get(ipaddress=ipaddress)
            result = HostSerializer(model).data
            return result
        except Exception as _:
            result = Host.create_host(ipaddress)
            return result

    @staticmethod
    def get_by_hid(hid=None):
        try:
            model = HostModel.objects.get(id=hid)
            result = HostSerializer(model).data
            return result
        except Exception as E:
            logger.warning(E)
            return None

    @staticmethod
    def list_hosts():
        models = HostModel.objects.all()
        result = HostSerializer(models, many=True).data
        return result

    @staticmethod
    def create_host(ipaddress=None):
        defaultdict = {'ipaddress': ipaddress, }  # 没有主机数据时新建
        model, created = HostModel.objects.get_or_create(ipaddress=ipaddress, defaults=defaultdict)
        if created is True:
            result = HostSerializer(model, many=False).data
            return result  # 新建后直接返回
        # 有历史数据
        with transaction.atomic():
            try:
                model = HostModel.objects.select_for_update().get(id=model.id)
                model.ipaddress = ipaddress

                model.save()
                result = HostSerializer(model, many=False).data
                return result
            except Exception as E:
                logger.error(E)
                result = HostSerializer(model, many=False).data
                return result

    @staticmethod
    def update(hid=None, tag=None, comment=None):
        """更新主机标签,说明"""
        host_update = Host.update_host(hid, tag, comment)
        if host_update is None:
            context = data_return(304, Host_MSG.get(304), host_update)
        else:
            context = data_return(201, Host_MSG.get(201), host_update)
        return context

    @staticmethod
    def update_host(id=None, tag=None, comment=None):

        defaultdict = {'id': id, 'tag': tag, 'comment': comment}  # 没有此主机数据时新建
        model, created = HostModel.objects.get_or_create(id=id, defaults=defaultdict)
        if created is True:
            result = HostSerializer(model, many=False).data
            return result  # 新建后直接返回
        # 有历史数据
        with transaction.atomic():
            try:
                model = HostModel.objects.select_for_update().get(id=id)
                model.tag = tag
                model.comment = comment
                model.save()
                result = HostSerializer(model, many=False).data
                return result
            except Exception as E:
                logger.error(E)
                return None

    @staticmethod
    def destory_single(hid=-1):
        hid_flag = Host.destory_host(hid)
        if hid_flag:
            context = data_return(202, Host_MSG.get(202), {})
        else:
            context = data_return(301, Host_MSG.get(301), {})
        return context

    @staticmethod
    def destory_mulit(hids):
        for hid in hids:
            Host.destory_host(hid)

        context = data_return(202, Host_MSG.get(202), {})
        return context

    @staticmethod
    def destory_host(id=None):
        # 删除相关缓存信息
        host = Host.get_by_hid(hid=id)
        # 删除缓存的session命令行结果
        Xcache.del_sessionio_cache(hid=id)
        # 删除缓存的模块结果
        Xcache.del_module_result_by_hid(ipaddress=host.get("ipaddress"))
        # 删除缓存的模块历史结果
        Xcache.del_module_result_history_by_hid(ipaddress=host.get("ipaddress"))

        try:
            # 删除主表信息
            HostModel.objects.filter(id=id).delete()
            # 删除关联表信息
            for OneModel in Host.REGISTER_DESTORY:
                OneModel.objects.filter(hid=id).delete()
            return True
        except Exception as E:
            logger.error(E)
            return False
