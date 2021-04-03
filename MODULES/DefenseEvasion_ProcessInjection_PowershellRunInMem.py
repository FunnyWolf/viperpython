# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellModule):
    NAME = "执行自定义Powershell脚本"
    DESC = "内存中执行自定义Powershell脚本,\n" \
           "Powershell脚本只支持Powershell2.0的API.\n" \
           "执行的脚本可以通过<文件列表>上传到服务器"
    MODULETYPE = TAG2CH.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/lpmn93"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionFileEnum(ext=['ps', 'ps1']),
        OptionInt(name='timeout', name_tag="脚本超时时间(秒)", desc="脚本执行的超时时间(5-3600)", required=True, default=60),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        script = self.get_option_filename()
        if script is None:
            return False, "请选择执行的脚本,脚本后缀必须为ps或ps1"
        self.set_script(script)

        timeout = self.param("timeout")
        # 检查timeout
        if timeout < 5 or timeout > 3600:
            return False, "输入的模块超时时间有误(最小值60,最大值3600),请重新输入"
        self.set_script_timeout(timeout)

        session = Session(self._sessionid)
        if session.is_alive:
            pass
        else:
            return False, "Session不可用"
        if session.is_windows:
            return True, None
        else:
            return False, "模块只支持Windows系统"

    def callback(self, status, message, data):
        if status:
            self.log_good("脚本执行完成")
            self.log_raw(data)
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
