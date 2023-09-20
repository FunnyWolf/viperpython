# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFPythonWithParamsModule):
    NAME_ZH = "Last日志删除"
    DESC_ZH = "删除目标机器上的last日志.\n由于last命令显示和实际文件内容不一致\n实际需要删除的行请通过utmpdump /var/log/wtmp |tail -20查看.\n"

    NAME_EN = "last log deleter"
    DESC_EN = "delete last log.\n"

    MODULETYPE = TAG2TYPE.Defense_Evasion
    PLATFORM = ["Linux"]  # 平台
    PERMISSIONS = ["SYSTEM", "Root"]  # 所需权限
    ATTCK = ["T1070"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/asi9mp7hgpgc88nz"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1070/003/"]
    AUTHOR = ["Nova"]

    OPTIONS = register_options([
        OptionInt(name='NUM',
                  tag_zh="删除行数", desc_zh="要删除的last日志的行数(默认1)",
                  tag_en="delete num",
                  desc_en="The count to delete last",
                  default=1),
        OptionInt(name='timeout',
                  tag_zh="模块超时时间(秒)", desc_zh="模块执行的超时时间",
                  tag_en="Module timeout time (seconds)", desc_en="Module execution timeout",
                  required=True, default=10),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("dellast.py")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        # session 检查

        self.session = Session(self._sessionid)
        if self.session.is_alive is not True:
            return False, "Session不可用", "Session is unavailable"

        # 参数检查
        num = self.param('NUM')
        timeout = self.param('timeout')

        # 检查timeout
        if timeout <= 0 or timeout > 360:
            return False, "输入的模块超时时间有误(最大值60)", "ErroThe entered module timeout time is incorrect (maximum 60)r"

        self.set_script_param('NUM', num)
        self.set_script_timeout(timeout)

        return True, None

    def callback(self, status, message, data):
        if status:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_info("脚本输出:", "Script output:")
            self.log_raw(data)
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
