# -*- coding: utf-8 -*-
# @File  : Session.py
# @Date  : 2019/2/10
# @Desc  :


import json
import os

from Msgrpc.msgrpc import Session as msfrpcSession
from Msgrpc.msgrpc import SessionLib, MSFModule, FileMsf

__all__ = ["Session", "SessionList", "SessionOperation"]


class Session(SessionLib):
    def __init__(self, sessionid, rightinfo=False, uacinfo=False, pinfo=False):
        super().__init__(sessionid, rightinfo, uacinfo, pinfo)  # 父类无需入参


class SessionList(msfrpcSession):
    def __init__(self):
        super().__init__()  # 父类无需入参


class SessionOperation(object):
    # 注册表type信息
    REG_NONE = 0
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_BINARY = 3
    REG_DWORD = 4
    REG_DWORD_LITTLE_ENDIAN = 4
    REG_DWORD_BIG_ENDIAN = 5
    REG_LINK = 6
    REG_MULTI_SZ = 7

    def __init__(self, sessionid, view=0):
        self._sessionid = sessionid
        self._view = view

    def registry_getvalinfo(self, key, valname):
        module_type = "post"
        mname = "windows/manage/registry_api"
        opts = {
            'SESSION': self._sessionid,
            'VIEW': self._view,
            'OPERATION': "registry_getvalinfo",
            'KEY': key,
            'VALNAME': valname,
        }
        result = MSFModule.run(module_type=module_type, mname=mname, opts=opts, timeout=12)
        if result is None:
            return {'status': False, "message": "MSFRPC Error", "data": None}
        try:
            result = json.loads(result)
            return result
        except Exception as E:
            return {'status': False, "message": E, "data": None}

    def registry_enumkeys(self, key):
        module_type = "post"
        mname = "windows/manage/registry_api"
        opts = {
            'SESSION': self._sessionid,
            'VIEW': self._view,
            'OPERATION': "registry_enumkeys",
            'KEY': key,
        }
        result = MSFModule.run(module_type=module_type, mname=mname, opts=opts, timeout=12)
        if result is None:
            return {'status': False, "message": "MSFRPC Error", "data": None}
        try:
            result = json.loads(result)
            return result
        except Exception as E:
            return {'status': False, "message": E, "data": None}

    def download_file(self, filepath=None):
        """返回下载的文件内容,二进制数据"""
        opts = {'OPERATION': 'download', 'SESSION': self._sessionid, 'SESSION_FILE': filepath}
        result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts,
                               timeout=300)  # 后台运行
        if result is None:
            return None
        filename = os.path.basename(filepath)
        binary_data = FileMsf.read_msf_file(filename)
        if binary_data is None:
            return None
        else:
            return binary_data
