# -*- coding: utf-8 -*-
# @File  : heartbeat.py
# @Date  : 2021/2/27
# @Desc  :

from WebDatabase.Handle.ipdomain import IPDomain


class WebSync(object):
    def __init__(self):
        pass

    @staticmethod
    def first_heartbeat_result():
        ipdomains = IPDomain.list_ipdomain()

        result = {
            'ipdomains_update': True,
            'ipdomains': ipdomains,
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
