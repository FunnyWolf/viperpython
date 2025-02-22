# -*- coding: utf-8 -*-
# @File  : heartbeat.py
# @Date  : 2021/2/27
# @Desc  :
from Lib.webnotice import WebNotice
from Lib.xcache import Xcache
from Msgrpc.Handle.job import Job
from PostModule.Handle.postmoduleconfig import PostModuleConfig
from WebDatabase.Interface.webtaskresult import WebTaskResult


class WebSync(object):
    def __init__(self):
        pass

    @staticmethod
    def get_result():
        result = {}

        # module_options 列表
        module_options = PostModuleConfig.list_dynamic_option()
        cache_module_options = Xcache.get_heartbeat_cache_web_module_options()
        if cache_module_options == module_options:
            result["module_options_update"] = False
            result["module_options"] = []
        else:
            Xcache.set_heartbeat_cache_web_module_options(module_options)
            result["module_options_update"] = True
            result["module_options"] = module_options

        jobs = Job.list_web_jobs()
        cache_jobs = Xcache.get_websync_cache_jobs()
        if cache_jobs == jobs:
            result["jobs_update"] = False
            result["jobs"] = []
        else:
            Xcache.set_websync_cache_jobs(jobs)
            result["jobs_update"] = True
            result["jobs"] = jobs

        # result_history
        task_result = WebTaskResult.list()
        cache_task_result = Xcache.get_websync_cache_web_module_result()

        if cache_task_result == task_result:
            result["task_result_update"] = False
            result["task_result"] = []
        else:
            Xcache.set_websync_cache_web_module_result(task_result)
            result["task_result_update"] = True
            result["task_result"] = task_result

        # notices
        notices = WebNotice.list_notices()
        cache_notices = Xcache.get_websync_cache_web_notices()
        if cache_notices == notices:
            result["notices_update"] = False
            result["notices"] = []
        else:
            Xcache.set_websync_cache_web_notices(notices)
            result["notices_update"] = True
            result["notices"] = notices

        return result

    @staticmethod
    def first_result():
        jobs = Job.list_web_jobs()
        module_options = PostModuleConfig.list_dynamic_option()

        task_result = WebTaskResult.list()
        notices = WebNotice.list_notices()
        result = {
            'jobs_update': True,
            'jobs': jobs,
            'module_options_update': True,
            'module_options': module_options,
            'task_result_update': True,
            'task_result': task_result,
            'notices_update': True,
            'notices': notices,
        }
        return result
