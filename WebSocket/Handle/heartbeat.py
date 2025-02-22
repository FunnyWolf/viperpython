# -*- coding: utf-8 -*-
# @File  : heartbeat.py
# @Date  : 2021/2/27
# @Desc  :

from Core.Handle.host import Host
from Lib.notice import Notice
from Lib.xcache import Xcache
from Msgrpc.Handle.job import Job
from PostModule.Handle.postmoduleconfig import PostModuleConfig
from PostModule.Handle.postmoduleresulthistory import PostModuleResultHistory


class HeartBeat(object):
    def __init__(self):
        pass

    @staticmethod
    def first_heartbeat_result():
        hosts_sorted, network_data = Host.list_hostandsession()

        result_history = PostModuleResultHistory.list_all()

        Xcache.set_heartbeat_cache_result_history(result_history)

        notices = Notice.list_notices()

        jobs = Job.list_jobs()

        bot_wait_list = Job.list_bot_wait()

        # 任务队列长度
        task_queue_length = Xcache.get_module_task_length()
        module_options = PostModuleConfig.list_dynamic_option()
        result = {
            'hosts_sorted_update': True,
            'hosts_sorted': hosts_sorted,
            'network_data_update': True,
            'network_data': network_data,
            'result_history_update': True,
            'result_history': result_history,
            'notices_update': True,
            'notices': notices,
            'task_queue_length': task_queue_length,
            'jobs_update': True,
            'jobs': jobs,
            'bot_wait_list_update': True,
            'bot_wait_list': bot_wait_list,
            'module_options_update': True,
            'module_options': module_options,
        }

        return result

    @staticmethod
    def get_heartbeat_result():
        result = {}

        # jobs 列表 首先执行,刷新数据,删除过期任务
        jobs = Job.list_jobs()
        cache_jobs = Xcache.get_heartbeat_cache_jobs()
        if cache_jobs == jobs:
            result["jobs_update"] = False
            result["jobs"] = []
        else:
            Xcache.set_heartbeat_cache_jobs(jobs)
            result["jobs_update"] = True
            result["jobs"] = jobs

        # hosts_sorted,network_data
        hosts_sorted, network_data = Host.list_hostandsession()

        cache_hosts_sorted = Xcache.get_heartbeat_cache_hosts_sorted()
        if cache_hosts_sorted == hosts_sorted:
            result["hosts_sorted_update"] = False
            result["hosts_sorted"] = []
        else:
            Xcache.set_heartbeat_cache_hosts_sorted(hosts_sorted)
            result["hosts_sorted_update"] = True
            result["hosts_sorted"] = hosts_sorted

        cache_network_data = Xcache.get_heartbeat_cache_network_data()
        if cache_network_data == network_data:
            result["network_data_update"] = False
            result["network_data"] = {"nodes": [], "edges": []}
        else:
            Xcache.set_heartbeat_cache_network_data(network_data)
            result["network_data_update"] = True
            result["network_data"] = network_data

        # result_history
        result_history = PostModuleResultHistory.list_all()

        cache_result_history = Xcache.get_heartbeat_cache_result_history()

        if cache_result_history == result_history:
            result["result_history_update"] = False
            result["result_history"] = []
        else:
            Xcache.set_heartbeat_cache_result_history(result_history)
            result["result_history_update"] = True
            result["result_history"] = result_history

        # notices
        notices = Notice.list_notices()
        cache_notices = Xcache.get_heartbeat_cache_notices()
        if cache_notices == notices:
            result["notices_update"] = False
            result["notices"] = []
        else:
            Xcache.set_heartbeat_cache_notices(notices)
            result["notices_update"] = True
            result["notices"] = notices

        # 任务队列长度
        task_queue_length = Xcache.get_module_task_length()
        result["task_queue_length"] = task_queue_length

        # bot_wait_list 列表
        bot_wait_list = Job.list_bot_wait()
        cache_bot_wait_list = Xcache.get_heartbeat_cache_bot_wait_list()
        if cache_bot_wait_list == bot_wait_list:
            result["bot_wait_list_update"] = False
            result["bot_wait_list"] = []
        else:
            Xcache.set_heartbeat_cache_bot_wait_list(bot_wait_list)
            result["bot_wait_list_update"] = True
            result["bot_wait_list"] = bot_wait_list

        # module_options 列表
        module_options = PostModuleConfig.list_dynamic_option()
        cache_module_options = Xcache.get_heartbeat_cache_module_options()
        if cache_module_options == module_options:
            result["module_options_update"] = False
            result["module_options"] = []
        else:
            Xcache.set_heartbeat_cache_module_options(module_options)
            result["module_options_update"] = True
            result["module_options"] = module_options
        return result
