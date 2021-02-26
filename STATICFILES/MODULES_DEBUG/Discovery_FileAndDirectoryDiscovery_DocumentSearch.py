# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

#
#

from PostModule.lib.ModuleTemplate import TAG2CH, PostMSFRawModule
from PostModule.lib.OptionAndResult import register_options


class PostModule(PostMSFRawModule):
    NAME = "搜索主机文档类文件"
    DESC = "搜索并获取主机中所有后缀为doc,docx,ppt,pst,pdf,pptx,xls,xlsx文件路径.\n" \
           "(针对C盘模块只搜索用户桌面路径,其他盘符全盘搜索)"
    MODULETYPE = TAG2CH.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1083"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1083/"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = True
    OPTIONS = register_options([])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "post"
        self.mname = "multi/gather/locate_useful_documents"

    def check(self):
        """执行前的检查函数"""
        from PostModule.lib.Session import Session
        session = Session(self._sessionid)
        if session.is_windows:
            return True, None
        else:
            return False, "当前Session不可用"

    def callback(self, status, message, data):
        if status:
            self.log_status("模块执行完成")
            for filepath in data:
                filepath = filepath.replace("\\\\\\\\", "/").replace("\\\\", "/").replace("\\", "/")
                self.log_raw(filepath)
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
