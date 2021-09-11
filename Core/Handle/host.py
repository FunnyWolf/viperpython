# -*- coding: utf-8 -*-
# @File  : hostinfo.py
# @Date  : 2021/2/25
# @Desc  :
import ipaddress as ipaddr

from django.db import transaction

from Core.models import HostModel
from Core.serializers import HostSerializer
from Lib.api import data_return
from Lib.configs import CODE_MSG, Host_MSG
from Lib.log import logger
from Lib.xcache import Xcache
from Msgrpc.Handle.portfwd import PortFwd
from Msgrpc.Handle.route import Route
from Msgrpc.Handle.socks import Socks
from PostLateral.Handle.edge import Edge
from PostLateral.Handle.portservice import PortService
from PostLateral.models import PortServiceModel, VulnerabilityModel, EdgeModel


class Host(object):
    REGISTER_DESTORY = [PortServiceModel, VulnerabilityModel]  # 删除Host时同时删除列表中的数据

    def __init__(self):
        pass

    @staticmethod
    def list():
        hosts = Host.list_hosts()
        route_list = Route.list_route()
        socks_list = Socks.list_msf_socks()
        portfwds = PortFwd.list_portfwd()
        for host in hosts:
            ipaddress = host.get('ipaddress')
            # 端口信息
            host['portService'] = PortService.list_by_ipaddress(ipaddress)
            # 路由信息
            for route in route_list:
                ipnetwork = ipaddr.ip_network(f"{route.get('subnet')}/{route.get('netmask')}", strict=False)
                if ipaddr.ip_address(ipaddress) in ipnetwork:
                    host['route'] = {'type': 'ROUTE', 'data': route.get("session")}
                    break
            else:
                host['route'] = {'type': 'DIRECT', 'data': None}

        result = {'hosts': hosts, 'routes': route_list, 'socks': socks_list, 'portfwds': portfwds, }

        context = data_return(200, result, CODE_MSG.get(200))
        return context

    @staticmethod
    def list_hosts():
        models = HostModel.objects.all()
        result = HostSerializer(models, many=True).data
        return result

    @staticmethod
    def create_host(ipaddress, source=None, linktype=None, data=None):
        if data is None:
            data = {}
        # 新建edge信息
        if source is not None:
            Edge.create_edge(source=source, target=ipaddress, type=linktype, data=data)

        defaultdict = {'ipaddress': ipaddress, }  # 没有主机数据时新建
        try:
            model, created = HostModel.objects.get_or_create(ipaddress=ipaddress, defaults=defaultdict)
        except Exception as E:
            # ip地址重复
            HostModel.objects.filter(ipaddress=ipaddress).delete()
            model = HostModel.objects.create(ipaddress=ipaddress)
        result = HostSerializer(model, many=False).data
        return result

    @staticmethod
    def update(ipaddress=None, tag=None, comment=None):
        """更新主机标签,说明"""
        host_update = Host.update_host(ipaddress, tag, comment)
        if host_update is None:
            context = data_return(304, host_update, Host_MSG.get(304))
        else:
            context = data_return(201, host_update, Host_MSG.get(201))
        return context

    @staticmethod
    def update_host(ipaddress=None, tag=None, comment=None):
        # 没有此主机数据时新建
        defaultdict = {'ipaddress': ipaddress, 'tag_zh': tag, 'comment': comment}
        model, created = HostModel.objects.get_or_create(ipaddress=ipaddress, defaults=defaultdict)
        if created is True:
            result = HostSerializer(model, many=False).data
            # 新建后直接返回
            return result
        # 有历史数据
        with transaction.atomic():
            try:
                model = HostModel.objects.select_for_update().get(ipaddress=ipaddress)
                model.tag = tag
                model.comment = comment
                model.save()
                result = HostSerializer(model, many=False).data
                return result
            except Exception as E:
                logger.error(E)
                return None

    @staticmethod
    def destory_single(ipaddress=None):
        flag = Host.destory_host(ipaddress)
        if flag:
            context = data_return(202, {}, Host_MSG.get(202))
        else:
            context = data_return(301, {}, Host_MSG.get(301))
        return context

    @staticmethod
    def destory_mulit(ipaddress_list):
        for ipaddress in ipaddress_list:
            Host.destory_host(ipaddress)

        context = data_return(202, {}, Host_MSG.get(202))
        return context

    @staticmethod
    def destory_host(ipaddress=None):
        # 删除相关缓存信息
        # 删除缓存的session命令行结果
        # 255.255.255.255 特殊处理
        if ipaddress == "255.255.255.255":
            return False

        Xcache.del_sessionio_cache(ipaddress=ipaddress)
        # 删除缓存的模块结果
        Xcache.del_module_result_by_ipaddress(ipaddress=ipaddress)
        # 删除缓存的模块历史结果
        Xcache.del_module_result_history_by_ipaddress(ipaddress=ipaddress)

        try:
            # 删除主表信息
            HostModel.objects.filter(ipaddress=ipaddress).delete()
            # 删除关联表信息
            for OneModel in Host.REGISTER_DESTORY:
                OneModel.objects.filter(ipaddress=ipaddress).delete()
            # 删除edge表信息
            EdgeModel.objects.filter(source=ipaddress).delete()
            EdgeModel.objects.filter(target=ipaddress).delete()

            # 删除host_info信息
            Xcache.del_host_info(ipaddress)

            return True
        except Exception as E:
            logger.error(E)
            return False
