# -*- coding: utf-8 -*-
# @File  : websocket.py
# @Date  : 2020/3/24
# @Desc  :

from Core.Handle.hostandsession import HostAndSession
from Lib.notice import Notice
from Lib.xcache import Xcache
from Msgrpc.Handle.job import Job
from PostModule.Handle.postmoduleresulthistory import PostModuleResultHistory


class HeartBeat(object):
    def __init__(self):
        pass

    @staticmethod
    def first_heartbeat_result():
        hosts_sorted = HostAndSession.list_hostandsession()

        result_history = PostModuleResultHistory.list_all()
        for one in result_history:
            for host in hosts_sorted:
                if one.get("hid") == host.get("id"):
                    one["ipaddress"] = host.get("ipaddress")
                    break
        Xcache.set_heartbeat_cache_result_history(result_history)

        notices = Notice.list_notices()

        jobs = Job.list_jobs()

        bot_wait_list = Job.list_bot_wait()

        # 任务队列长度
        task_queue_length = Xcache.get_module_task_length()

        result = {
            'hosts_sorted_update': True,
            'hosts_sorted': hosts_sorted,
            'result_history_update': True,
            'result_history': result_history,
            'notices_update': True,
            'notices': notices,
            'task_queue_length': task_queue_length,
            'jobs_update': True,
            'jobs': jobs,
            'bot_wait_list_update': True,
            'bot_wait_list': bot_wait_list
        }

        return result

    @staticmethod
    def get_heartbeat_result():
        result = {}

        # hosts_sorted
        hosts_sorted = HostAndSession.list_hostandsession()
        cache_hosts_sorted = Xcache.get_heartbeat_cache_hosts_sorted()
        if cache_hosts_sorted == hosts_sorted:
            result["hosts_sorted_update"] = False
            result["hosts_sorted"] = []
        else:
            Xcache.set_heartbeat_cache_hosts_sorted(hosts_sorted)
            result["hosts_sorted_update"] = True
            result["hosts_sorted"] = hosts_sorted

        # result_history
        result_history = PostModuleResultHistory.list_all()
        for one in result_history:
            for host in hosts_sorted:
                if one.get("hid") == host.get("id"):
                    one["ipaddress"] = host.get("ipaddress")
                    break

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

        # jobs 列表
        jobs = Job.list_jobs()
        cache_jobs = Xcache.get_heartbeat_cache_jobs()
        if cache_jobs == jobs:
            result["jobs_update"] = False
            result["jobs"] = []
        else:
            Xcache.set_heartbeat_cache_jobs(jobs)
            result["jobs_update"] = True
            result["jobs"] = jobs

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

        return result
