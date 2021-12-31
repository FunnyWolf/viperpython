# -*- coding: utf-8 -*-
# @File  : handler.py
# @Date  : 2021/2/25
# @Desc  :

from Lib.api import data_return
from Lib.configs import CODE_MSG_ZH, WebDelivery_MSG_ZH, RPC_JOB_API_REQ, WebDelivery_MSG_EN, CODE_MSG_EN
from Lib.msfmodule import MSFModule
from Lib.notice import Notice
from Msgrpc.Handle.job import Job


class WebDelivery(object):
    """监听类"""

    def __init__(self):
        pass

    @staticmethod
    def list():
        deliverys = WebDelivery.list_webdelivery()
        context = data_return(200, deliverys, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
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
                    if datastore.get('SSL'):
                        title = "https"
                    else:
                        title = "http"
                    url = f"{title}://{datastore.get('URIHOST')}:{datastore.get('URIPORT')}{info.get('uripath')}"
                    one_delivery = {'ID': jobid, 'PAYLOAD': None, 'URL': url}

                    if datastore.get('PAYLOAD') is not None:
                        one_delivery['PAYLOAD'] = datastore.get('PAYLOAD')
                    elif datastore.get('Payload') is not None:
                        one_delivery['PAYLOAD'] = datastore.get('Payload')
                    elif datastore.get('payload') is not None:
                        one_delivery['PAYLOAD'] = datastore.get('payload')

                    z = datastore.copy()
                    z.update(one_delivery)
                    one_delivery = z
                    deliverys.append(one_delivery)

        return deliverys

    @staticmethod
    def create(opts=None):
        opts["SRVHOST"] = "0.0.0.0"
        opts["SRVPORT"] = opts["URIPORT"]

        result = MSFModule.run_msf_module_realtime(module_type="exploit", mname="multi/script/web_delivery_api",
                                                   opts=opts, runasjob=True,
                                                   timeout=RPC_JOB_API_REQ)
        if isinstance(result, dict) is not True or result.get('job_id') is None:
            opts['ID'] = None
            context = data_return(307, opts, WebDelivery_MSG_ZH.get(307), WebDelivery_MSG_EN.get(307))
        else:
            job_id = int(result.get('job_id'))
            if Job.is_msf_job_alive(job_id):
                opts['ID'] = int(result.get('job_id'))
                Notice.send_info(
                    f"新建WebDelivery成功:{opts.get('PAYLOAD')} {opts.get('LPORT')} JobID:{result.get('job_id')}",
                    f"Create WebDelivery successfully:{opts.get('PAYLOAD')} {opts.get('LPORT')} JobID:{result.get('job_id')}")
                context = data_return(201, opts, WebDelivery_MSG_ZH.get(201), WebDelivery_MSG_EN.get(201))
            else:
                context = data_return(301, opts, WebDelivery_MSG_ZH.get(301), WebDelivery_MSG_EN.get(301))
        return context

    @staticmethod
    def destroy(id=None):
        if id is None:
            context = data_return(303, {}, WebDelivery_MSG_ZH.get(303), WebDelivery_MSG_EN.get(303))
            return context
        else:
            flag = Job.destroy(id)
            if flag:
                # 删除msf监听
                if Job.is_msf_job_alive(id):
                    context = data_return(303, {}, WebDelivery_MSG_ZH.get(303), WebDelivery_MSG_EN.get(303))
                else:
                    context = data_return(202, {}, WebDelivery_MSG_ZH.get(202), WebDelivery_MSG_EN.get(202))
            else:
                context = data_return(303, {}, WebDelivery_MSG_ZH.get(303), WebDelivery_MSG_EN.get(303))
            return context
