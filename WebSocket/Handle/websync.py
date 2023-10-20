# -*- coding: utf-8 -*-
# @File  : heartbeat.py
# @Date  : 2021/2/27
# @Desc  :
from WebDatabase.Handle.domainicp import DomainICP
from WebDatabase.Handle.ipdomain import IPDomain
from WebDatabase.Handle.location import Location
from WebDatabase.Handle.portservice import PortService


class WebSync(object):
    def __init__(self):
        pass

    @staticmethod
    def first_result():

        # 按照ip port 为key进行搜索

        # 区分http类型和其他类型

        ipdomains_result = []
        ipdomains = IPDomain.list_ipdomain()
        for one_ipdomain in ipdomains:
            ip = one_ipdomain.get("ip")

            # location
            location = Location.list_by_ip(ip)
            isp = location.get("isp")
            asname = location.get("asname")

            # ports
            portservices = PortService.list_by_ip(ip)
            for portservice in portservices:
                one_record = {"ip": ip}

                one_record["isp"] = isp
                one_record["asname"] = asname

                port = portservice.get('port')
                service = portservice.get("service")
                one_record["port"] = port
                one_record["service"] = service

                # DomainICP
                domainicp = DomainICP.list_by_ipports(ip, port)

            one_ipdomain['portservice'] = portservices

            port_and_service = []
            for portservice in portservices:
                port_and_service.append({'service': portservice.get('service'), 'port': portservice.get('port')})
            portservices_sorted = sorted(port_and_service, key=lambda x: x['port'])
            one_ipdomain['port_and_service'] = portservices_sorted
            # end
            ipdomains_result.append(one_ipdomain)

        result = {
            'ipdomains_update': True,
            'ipdomains': ipdomains_result,
            # 'network_data_update': True,
            # 'network_data': network_data,
            # 'result_history_update': True,
            # 'result_history': result_history,
            # 'notices_update': True,
            # 'notices': notices,
            # 'task_queue_length': task_queue_length,
            # 'jobs_update': True,
            # 'jobs': jobs,
            # 'bot_wait_list_update': True,
            # 'bot_wait_list': bot_wait_list,
            # 'module_options_update': True,
            # 'module_options': module_options,

        }

        return result
