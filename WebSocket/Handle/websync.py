# -*- coding: utf-8 -*-
# @File  : heartbeat.py
# @Date  : 2021/2/27
# @Desc  :
from Lib.xcache import Xcache
from Msgrpc.Handle.job import Job
from PostModule.Handle.postmoduleconfig import PostModuleConfig


class WebSync(object):
    def __init__(self):
        pass

    @staticmethod
    def get_result():
        result = {}

        jobs = Job.list_web_jobs()
        cache_jobs = Xcache.get_websync_cache_jobs()
        if cache_jobs == jobs:
            result["jobs_update"] = False
            result["jobs"] = []
        else:
            Xcache.set_websync_cache_jobs(jobs)
            result["jobs_update"] = True
            result["jobs"] = jobs

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

    @staticmethod
    def first_result():
        jobs = Job.list_web_jobs()
        module_options = PostModuleConfig.list_dynamic_option()
        result = {
            'jobs_update': True,
            'jobs': jobs,
            'module_options_update': True,
            'module_options': module_options,
        }
        return result
