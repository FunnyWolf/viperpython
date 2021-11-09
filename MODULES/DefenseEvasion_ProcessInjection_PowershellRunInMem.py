# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellModule):
    NAME_ZH = "内存执行Powershell脚本"
    DESC_ZH = "内存中执行自定义Powershell脚本.\n" \
              "Powershell script only supports Powershell2.0 API.\n" \
              "执行的脚本可以通过<文件列表>上传到服务器"

    NAME_EN = "Execute Powershell script in memory.\n"
    DESC_EN = "Execute custom Powershell script in memory.\n" \
              "The executed script can be uploaded to the server through <Files>"

    MODULETYPE = TAG2TYPE.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/lpmn93"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    AUTHOR = ["Viper"]

    OPTIONS = register_options([
        OptionFileEnum(ext=['ps', 'ps1']),
        OptionInt(name='timeout',
                  tag_zh="脚本超时时间(秒)", desc_zh="脚本执行的超时时间(5-3600)",
                  tag_en="Script timeout (seconds)", desc_en="Script execution timeout time (5-3600)",
                  required=True, default=60),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        script = self.get_fileoption_filename()
        if script is None:
            return False, "请选择执行的脚本,脚本后缀必须为ps或ps1", "Please select the script to execute, the script suffix must be ps or ps1"
        self.set_script(script)

        timeout = self.param("timeout")
        # 检查timeout
        if timeout < 5 or timeout > 3600:
            return False, "输入的模块超时时间有误(最小值60,最大值3600)", "The entered module timeout time is incorrect (minimum value 60, maximum value 3600)"
        self.set_script_timeout(timeout)

        session = Session(self._sessionid)
        if session.is_alive:
            pass
        else:
            return False, "Session不可用", "Session is unavailable"
        if session.is_windows:
            return True, None
        else:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

    def callback(self, status, message, data):
        if status:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_info("脚本输出:", "Script output:")
            self.log_raw(data)
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
