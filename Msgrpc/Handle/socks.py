# -*- coding: utf-8 -*-
# @File  : socks.py
# @Date  : 2021/2/25
# @Desc  :

from Core.Handle.setting import Settings
from Lib.api import data_return, is_empty_ports
from Lib.configs import CODE_MSG, Socks_MSG, RPC_JOB_API_REQ
from Lib.log import logger
from Lib.msfmodule import MSFModule
from Lib.notice import Notice
from Msgrpc.Handle.job import Job
from Msgrpc.Handle.portfwd import PortFwd
from Msgrpc.Handle.route import Route


class Socks(object):
    """socks代理"""

    @staticmethod
    def list():
        route_list = Route.list_route()
        socks_list = Socks.list_msf_socks()
        portfwds = PortFwd.list_portfwd()
        # 检查host对应的路由信息
        ipaddresses = []
        from Core.Handle.host import Host
        hosts = Host.list_hosts()
        for onehost in hosts:
            ipaddresses.append(onehost.get("ipaddress"))
        route_session_list = Route.get_match_route_for_ipaddress_list(ipaddresses)
        if route_session_list is None:
            for host in hosts:
                host['route'] = {'type': 'DIRECT', 'data': None}
        else:
            try:
                for host, route_session in zip(hosts, route_session_list):
                    sessionid = route_session.get('session')
                    if sessionid is None:
                        # TODO 处理socks代理类型
                        host['route'] = {'type': 'DIRECT', 'data': None}
                    else:
                        host['route'] = {'type': 'ROUTE', 'data': sessionid}
            except Exception as E:
                logger.error(E)

        result = {'socks': socks_list, 'routes': route_list, 'portfwds': portfwds, 'hostsRoute': hosts}

        context = data_return(200, CODE_MSG.get(200), result)
        return context

    @staticmethod
    def list_msf_socks():
        lhost = Settings.get_lhost()
        socks_list = []
        infos = Job.list_msfrpc_jobs()
        if infos is None:
            return socks_list
        for key in infos.keys():
            info = infos.get(key)
            jobid = int(key)
            if info.get('name') == 'Auxiliary: server/socks4a_api':
                datastore = info.get('datastore')
                if datastore is not None:
                    onesocks4a = {'ID': jobid,
                                  "type": "msf_socks4a",
                                  "lhost": lhost,
                                  "port": datastore.get("SRVPORT"),
                                  'datastore': datastore}
                    socks_list.append(onesocks4a)
            elif info.get('name') == 'Auxiliary: server/socks5_api':
                datastore = info.get('datastore')
                if datastore is not None:
                    onesocks4a = {'ID': jobid,
                                  "type": "msf_socks5",
                                  "lhost": lhost,
                                  "port": datastore.get("SRVPORT"),
                                  'datastore': datastore}
                    socks_list.append(onesocks4a)

        return socks_list

    @staticmethod
    def create(socks_type=None, port=None):
        if socks_type == "msf_socks4a":
            opts = {'SRVHOST': '0.0.0.0', 'SRVPORT': port}
            flag, lportsstr = is_empty_ports(port)
            if flag is not True:
                # 端口已占用
                context = data_return(408, CODE_MSG.get(408), {})
                return context

            result = MSFModule.run(module_type="auxiliary", mname="server/socks4a_api", opts=opts, runasjob=True,
                                   timeout=RPC_JOB_API_REQ)
            if isinstance(result, dict) is not True or result.get('job_id') is None:
                opts['job_id'] = None
                context = data_return(303, Socks_MSG.get(303), opts)
            else:
                job_id = int(result.get('job_id'))
                if Job.is_msf_job_alive(job_id):
                    opts['job_id'] = int(result.get('job_id'))
                    Notice.send_success(
                        "新建msf_socks4a代理成功,Port: {}".format(opts.get('SRVPORT'), opts.get('job_id')))
                    context = data_return(201, Socks_MSG.get(201), opts)
                else:
                    context = data_return(306, Socks_MSG.get(306), opts)
            return context
        elif socks_type == "msf_socks5":
            opts = {'SRVHOST': '0.0.0.0', 'SRVPORT': port}
            flag, lportsstr = is_empty_ports(port)
            if flag is not True:
                # 端口已占用
                context = data_return(408, CODE_MSG.get(408), {})
                return context

            result = MSFModule.run(module_type="auxiliary", mname="server/socks5_api", opts=opts, runasjob=True,
                                   timeout=RPC_JOB_API_REQ)
            if isinstance(result, dict) is not True or result.get('job_id') is None:
                opts['job_id'] = None
                context = data_return(303, Socks_MSG.get(303), opts)
            else:
                job_id = int(result.get('job_id'))
                if Job.is_msf_job_alive(job_id):
                    opts['job_id'] = int(result.get('job_id'))
                    Notice.send_success(
                        "新建msf_socks5代理成功,Port: {}".format(opts.get('SRVPORT'), opts.get('job_id')))
                    context = data_return(201, Socks_MSG.get(201), opts)
                else:
                    context = data_return(306, Socks_MSG.get(306), opts)
            return context

    @staticmethod
    def destory(socks_type=None, jobid=None):
        if socks_type == "msf_socks4a":
            flag = Job.destroy(jobid)
            if flag:
                if Job.is_msf_job_alive(jobid) is not True:
                    Notice.send_success("删除msf_socks4a代理 JobID:{}".format(jobid))
                    context = data_return(204, Socks_MSG.get(204), {})
                else:
                    context = data_return(304, Socks_MSG.get(304), {})
            else:
                context = data_return(304, Socks_MSG.get(304), {})
            return context
        elif socks_type == "msf_socks5":
            flag = Job.destroy(jobid)
            if flag:
                if Job.is_msf_job_alive(jobid) is not True:
                    Notice.send_success("删除msf_socks5代理 JobID:{}".format(jobid))
                    context = data_return(204, Socks_MSG.get(204), {})
                else:
                    context = data_return(304, Socks_MSG.get(304), {})
            else:
                context = data_return(304, Socks_MSG.get(404), {})
            return context
