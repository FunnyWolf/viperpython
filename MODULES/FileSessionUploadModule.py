# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "上传文件"
    DESC_ZH = "模块用于上传服务器文件到Session所在主机."

    NAME_EN = "Upload file"
    DESC_EN = "The module is used to upload server file to the host where the session is located."

    REQUIRE_SESSION = True
    MODULETYPE = TAG2TYPE.internal

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "multi/manage/file_system_operation_api"

    # opts = {'OPERATION': 'upload', 'SESSION': sessionid, 'SESSION_DIR': formatdir, 'MSF_FILE': filename}

    def check(self):
        self.set_msf_option("OPERATION", 'upload')
        SESSION_DIR = File.tran_win_path_to_unix_path(self.param("SESSION_DIR"))
        self.set_msf_option("SESSION_DIR", SESSION_DIR)
        self.set_msf_option("MSF_FILE", self.param("MSF_FILE"))
        return True, None

    def callback(self, status, message, data):
        # 调用父类函数存储结果(必须调用)
        if status:
            self.log_good(f'{self.param("MSF_FILE")} 上传完成.', f'{self.param("MSF_FILE")} upload completed.')
        else:
            self.log_error('上传失败', "Upload failed")
            self.log_error(message, message)
