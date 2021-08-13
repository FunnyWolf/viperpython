# -*- coding: utf-8 -*-
# @File  : handler.py
# @Date  : 2021/2/25
# @Desc  :
import uuid

from Lib.api import data_return
from Lib.configs import CODE_MSG, Handler_MSG, RPC_JOB_API_REQ
from Lib.log import logger
from Lib.msfmodule import MSFModule
from Lib.notice import Notice
from Lib.xcache import Xcache
from Msgrpc.Handle.job import Job


class WebDelivery(object):
    """监听类"""

    def __init__(self):
        pass

    @staticmethod
    def list():
        deliverys = WebDelivery.list_webdelivery()
        context = data_return(200, CODE_MSG.get(200), deliverys)
        return context

    @staticmethod
    def list_webdelivery():
        deliverys = []
        infos = Job.list_msfrpc_jobs()
        if infos is None:
            return deliverys
        for key in infos.keys():
            info = infos.get(key)
            jobid = int(key)
            if info.get('name') == 'Exploit: multi/script/web_delivery_api':
                datastore = info.get('datastore')
                if datastore is not None:
                    one_handler = {'ID': jobid, 'PAYLOAD': None}
                    if datastore.get('PAYLOAD') is not None:
                        one_handler['PAYLOAD'] = datastore.get('PAYLOAD')

                    elif datastore.get('Payload') is not None:
                        one_handler['PAYLOAD'] = datastore.get('Payload')
                    elif datastore.get('payload') is not None:
                        one_handler['PAYLOAD'] = datastore.get('payload')

                    z = datastore.copy()
                    z.update(one_handler)
                    one_handler = z
                    deliverys.append(one_handler)

        return deliverys

    @staticmethod
    def create(opts=None):
        # 真正的监听
        # 处理代理相关参数
        if opts.get("proxies_proto") == "Direct" or opts.get("proxies_proto") is None:
            try:
                opts.pop('proxies_proto')
            except Exception as _:
                pass
            try:
                opts.pop('proxies_ipport')
            except Exception as _:
                pass

        else:
            proxies_proto = opts.get('proxies_proto')
            proxies_ipport = opts.get('proxies_ipport')
            opts["proxies"] = f"{proxies_proto}:{proxies_ipport}"
            try:
                opts.pop('proxies_proto')
            except Exception as _:
                pass
            try:
                opts.pop('proxies_ipport')
            except Exception as _:
                pass
        try:
            if opts.get('PAYLOAD').find("reverse") > 0:
                if opts.get('PAYLOAD').find("reverse_dns") > 0:
                    try:
                        opts.pop('LHOST')
                    except Exception as _:
                        pass
                    opts['AutoVerifySessionTimeout'] = 3600  # DNS传输较慢,默认等待一个小时
                else:
                    try:
                        opts.pop('RHOST')
                    except Exception as _:
                        pass

                # 查看端口是否已占用
                # lport = int(opts.get('LPORT'))
                # flag, lportsstr = is_empty_ports(lport)
                # if flag is not True:
                #     context = dict_data_return(306, Handler_MSG.get(306), {})
                #     return context

            elif opts.get('PAYLOAD').find("bind") > 0:
                try:
                    opts.pop('LHOST')
                except Exception as _:
                    pass

            # 反向http(s)服务常驻问题特殊处理
            if opts.get('PAYLOAD').find("reverse_http") or opts.get('PAYLOAD').find("reverse_winhttp"):
                opts['EXITONSESSION'] = False
                opts['KillHandlerFouce'] = True
            else:
                if opts.get('EXITONSESSION'):
                    opts['EXITONSESSION'] = True
                else:
                    opts['EXITONSESSION'] = False
            opts['PayloadUUIDSeed'] = str(uuid.uuid1())
        except Exception as E:
            logger.error(E)
            context = data_return(500, CODE_MSG.get(500), {})
            return context

        result = MSFModule.run(module_type="exploit", mname="multi/handler", opts=opts, runasjob=True,
                               timeout=RPC_JOB_API_REQ)
        if isinstance(result, dict) is not True or result.get('job_id') is None:
            opts['ID'] = None
            context = data_return(301, Handler_MSG.get(301), opts)
        else:
            job_id = int(result.get('job_id'))
            if Job.is_msf_job_alive(job_id):
                opts['ID'] = int(result.get('job_id'))
                Notice.send_success("新建监听成功:{} {} JobID:{}".format(opts.get('PAYLOAD'), opts.get('LPORT'),
                                                                   result.get('job_id')))
                context = data_return(201, Handler_MSG.get(201), opts)
            else:
                context = data_return(301, Handler_MSG.get(301), opts)

        return context

    @staticmethod
    def destroy(id=None):
        if id is None:
            context = data_return(303, Handler_MSG.get(303), {})
            return context
        else:
            if -10000 < id < 0:  # 虚拟监听
                flag_result = Xcache.del_virtual_handler(id)
                if flag_result:
                    context = data_return(202, Handler_MSG.get(202), {})
                else:
                    context = data_return(303, Handler_MSG.get(303), {})
            else:
                flag = Job.destroy(id)
                if flag:
                    # 删除msf监听
                    if Job.is_msf_job_alive(id):
                        context = data_return(303, Handler_MSG.get(303), {})
                    else:
                        context = data_return(202, Handler_MSG.get(202), {})
                else:
                    context = data_return(303, Handler_MSG.get(303), {})
            return context
