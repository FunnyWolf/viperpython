# -*- coding: utf-8 -*-
# @File  : heartbeat.py
# @Date  : 2021/2/27
# @Desc  :

from WebDatabase.Handle.ipdomain import IPDomain
from WebDatabase.Handle.portservice import PortService


class WebSync(object):
    def __init__(self):
        pass

    @staticmethod
    def first_result():
        ipdomains_result = []
        ipdomains = IPDomain.list_ipdomain()
        for one_ipdomain in ipdomains:
            ip = one_ipdomain.get("ip")
            portservices = PortService.list_by_ip(ip)
            one_ipdomain['portservice'] = portservices
            port_and_service = []
            for portservice in portservices:
                port_and_service.append(f"{portservice.get('port')}:{portservice.get('service')}")
            one_ipdomain['port_and_service'] = port_and_service
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
