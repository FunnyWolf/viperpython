# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :

#
#
import json

from PostModule.lib.Host import Host
from PostModule.lib.ModuleTemplate import PostMSFRawModule, TAG2CH
from PostModule.lib.Notice import Notices
from PostModule.lib.OptionAndResult import Option, register_options


class PostModule(PostMSFRawModule):
    NAME = "RDP挂盘&登录监控"
    DESC = "对Session所在主机RDP挂盘/新用户登录监控,并提醒(Bot,WEB控制台)\n" \
           "(此模块需配合DarkGuardian使用)"
    MODULETYPE = TAG2CH.Collection
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1039"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1039/",
                  "https://github.com/FunnyWolf/DarkGuardian"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        Option(name='DarkGuardian_path', name_tag="DarkGuardian目录", type='str', required=False,
               desc="DarkGuardian可执行文件所在目录",
               option_length=12
               ),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "post"
        self.mname = "windows/gather/session_monitor"

    def check(self):
        """执行前的检查函数"""
        DarkGuardian_path = self.param("DarkGuardian_path")
        self.set_option(key='DarkGuardian_path', value=DarkGuardian_path)
        from PostModule.lib.Session import Session
        session = Session(self._sessionid)
        if session.is_alive:
            pass
        else:
            return False, "Session不可用"
        if session.is_windows:
            pass
        else:
            return False, "模块只支持Windows系统"
        return True, None

    def callback(self, status, message, data):
        hostinfo = Host.get_host(self._hid)
        self.log_good("获取监控信息")

        if status:
            alertstr = "IP: {} 注释: {} Session监控模块有新信息 ".format(
                hostinfo.get("ipaddress"),
                hostinfo.get("comment"),
            )
            Notices.send_alert(alertstr)
            if message == "RDP_NOTICES":
                if isinstance(data, str):
                    if "share_disk" in data:
                        share_disk_info = json.loads(data)
                        timeStamp = share_disk_info.get("update_time")

                        logstr = "IP: {} \n注释: {} \nSID: {} \n盘符: {} \n挂载时间: {}".format(
                            hostinfo.get("ipaddress"),
                            hostinfo.get("comment"),
                            self._sessionid,
                            share_disk_info.get("share_disk"),
                            self.timeStampToStr(timeStamp),
                        )
                        smsstr = "IP: {}      注释: {}       SID: {}        盘符: {}        挂载时间: {}".format(
                            hostinfo.get("ipaddress"),
                            hostinfo.get("comment"),
                            self._sessionid,
                            share_disk_info.get("share_disk"),
                            self.timeStampToStr(timeStamp),
                        )
                        self.log_raw(logstr)
                        if Notices.send_sms(smsstr):
                            self.log_good("发送Bot提醒成功")
                        else:
                            self.log_error("发送Bot提醒失败")
            elif message == "LOGGED_ON_USERS":
                if isinstance(data, list):
                    logstr = "IP: {} \n注释: {} \nSID: {} \n登录用户:\n".format(
                        hostinfo.get("ipaddress"),
                        hostinfo.get("comment"),
                        self._sessionid,
                    )
                    self.log_raw(logstr)
                    for logged_on_user in data:
                        for key in logged_on_user:
                            logstr = "USER: {} SID: {} \n".format(
                                logged_on_user.get(key),
                                key,
                            )
                            self.log_raw(logstr)
                    smsstr = "IP: {}  注释: {}  SID: {}  登录用户: {}  ".format(
                        hostinfo.get("ipaddress"),
                        hostinfo.get("comment"),
                        self._sessionid,
                        data,
                    )
                    if Notices.send_sms(smsstr):
                        self.log_good("发送Bot提醒成功")
                    else:
                        self.log_error("发送Bot提醒失败")


        else:
            self.log_error("模块执行失败")
            self.log_error(message)
