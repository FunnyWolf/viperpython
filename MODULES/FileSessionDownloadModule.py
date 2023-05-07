# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "下载文件"
    DESC_ZH = "模块用于下载Session所在主机文件到服务器."

    NAME_EN = "Download file"
    DESC_EN = "The module is used to download the host file from session to the server."

    REQUIRE_SESSION = True
    MODULETYPE = TAG2TYPE.internal

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "multi/manage/file_system_operation_api"

    # opts = {'OPERATION': 'upload', 'SESSION': sessionid, 'SESSION_DIR': formatdir, 'MSF_FILE': filename}

    def check(self):
        self.set_msf_option("OPERATION", 'download')
        SESSION_FILE = File.tran_win_path_to_unix_path(self.param("SESSION_FILE"))
        self.set_msf_option("SESSION_FILE", SESSION_FILE)

        return True, None

    def callback(self, status, message, data):
        # 调用父类函数存储结果(必须调用)
        if status:
            self.log_good(f"{self.param('SESSION_FILE')} 下载完成.",
                          f"{self.param('SESSION_FILE')} download completed.")
        else:
            self.log_error('下载失败', "Download failed")
            self.log_error(message, message)
