# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFPythonModule):
    NAME_ZH = "内存执行Python脚本"
    DESC_ZH = "内存中(Windows)或者系统Python解释器(Linux)执行自定义的Python脚本.\n" \
              "Python脚本只支持Python2.7及其自带的库.\n" \
              "执行的脚本可以通过<文件列表>上传到服务器."

    NAME_EN = "Memory execution Python script"
    DESC_EN = "Execute custom Python scripts in memory (Windows) or the system Python interpreter (Linux).\n" \
              "Python scripts only support Python2.7 and its own libraries.\n" \
              "The executed script can be uploaded to the server through <Files>."

    MODULETYPE = TAG2TYPE.Defense_Evasion
    PLATFORM = ["Windows", "Linux"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", "Root"]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/qxfra8"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    AUTHOR = ["Viper"]

    OPTIONS = register_options([
        OptionFileEnum(ext=['py', 'pyc']),
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
            return False, "请选择执行的脚本,脚本后缀必须为py或pyc", "Please select the script to execute, the script suffix must be py or pyc"
        self.set_script(script)

        timeout = self.param("timeout")
        # 检查timeout
        if timeout < 5 or timeout > 3600:
            return False, "输入的模块超时时间有误(最小值60,最大值3600)", "The entered module timeout time is incorrect (minimum value 60, maximum value 3600)"
        self.set_script_timeout(timeout)

        session = Session(self._sessionid)
        if session.is_alive:
            return True, None
        else:
            return False, "Session不可用", "Session is unavailable"

    def callback(self, status, message, data):
        if status:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_info("脚本输出:", "Script output:")
            self.log_raw(data)
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
