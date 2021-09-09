# -*- coding: utf-8 -*-
# @File  : handler.py
# @Date  : 2021/2/25
# @Desc  :

from Lib.api import data_return
from Lib.configs import CODE_MSG, WebDelivery_MSG, RPC_JOB_API_REQ
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

        result = MSFModule.run(module_type="exploit", mname="multi/script/web_delivery_api", opts=opts, runasjob=True,
                               timeout=RPC_JOB_API_REQ)
        if isinstance(result, dict) is not True or result.get('job_id') is None:
            opts['ID'] = None
            context = data_return(301, WebDelivery_MSG.get(301), opts)
        else:
            job_id = int(result.get('job_id'))
            if Job.is_msf_job_alive(job_id):
                opts['ID'] = int(result.get('job_id'))
                Notice.send_success(
                    f"新建WebDelivery成功:{opts.get('PAYLOAD')} {opts.get('LPORT')} JobID:{result.get('job_id')}",
                    f"Create WebDelivery success:{opts.get('PAYLOAD')} {opts.get('LPORT')} JobID:{result.get('job_id')}")
                context = data_return(201, WebDelivery_MSG.get(201), opts)
            else:
                context = data_return(301, WebDelivery_MSG.get(301), opts)
        return context

    @staticmethod
    def destroy(id=None):
        if id is None:
            context = data_return(303, WebDelivery_MSG.get(303), {})
            return context
        else:
            flag = Job.destroy(id)
            if flag:
                # 删除msf监听
                if Job.is_msf_job_alive(id):
                    context = data_return(303, WebDelivery_MSG.get(303), {})
                else:
                    context = data_return(202, WebDelivery_MSG.get(202), {})
            else:
                context = data_return(303, WebDelivery_MSG.get(303), {})
            return context
