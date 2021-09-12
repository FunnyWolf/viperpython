# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


import re
from pathlib import PurePosixPath

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

    def deal_path(self, path=None):
        """处理成linux路径"""
        tmppath = path.replace('\\\\', '/').replace('\\', '/')

        if re.match("^/[a-zA-Z]:/", tmppath) is not None:
            tmppath = tmppath[1:]

        # 只支持最后加/..和/../
        if tmppath.startswith('/'):  # linux路径
            if tmppath.endswith('/..') or tmppath.endswith('/../'):
                parts = PurePosixPath(tmppath).parent.parent.parts
                if len(parts) == 1:
                    tmppath = '/'
                elif len(parts) == 0:
                    tmppath = '/'
                else:
                    tmppath = "/".join(parts)

        else:
            if tmppath.endswith('/..') or tmppath.endswith('/../'):
                parts = PurePosixPath(tmppath).parent.parent.parts
                if len(parts) == 1:
                    tmppath = parts[0] + '/'
                elif len(parts) == 0:
                    tmppath = '/'
                else:
                    tmppath = "/".join(parts)

        tmppath = tmppath.replace('//', '/')
        if tmppath == '' or tmppath is None:
            self.log_warning('输入错误字符', "Typing wrong characters")
            tmppath = '/'
        return tmppath

    def check(self):
        self.set_msf_option("OPERATION", 'upload')
        SESSION_DIR = self.deal_path(self.param("SESSION_DIR"))
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
