# -*- coding: utf-8 -*-
# @File  : filesession.py
# @Date  : 2021/2/25
# @Desc  :
import base64
import json
import os
import re
from pathlib import PurePosixPath

from Lib.api import data_return
from Lib.configs import FileSession_MSG, CODE_MSG, RPC_SESSION_OPER_SHORT_REQ, RPC_JOB_API_REQ, \
    RPC_SESSION_OPER_LONG_REQ
from Lib.log import logger
from Lib.msfmodule import MSFModule


class FileSession(object):
    OPERATION_ENUM = ['upload', 'download', 'list', 'pwd', 'create_dir', 'destory_file', 'destory_dir']  # 可用操作 列表

    def __init__(self):
        pass

    @staticmethod
    def list(sessionid=None, filepath=None, dirpath=None, operation=None, arg=""):

        if operation == "list" and sessionid is not None and dirpath is not None:  # 列目录
            formatdir = FileSession.deal_path(dirpath)
            opts = {'OPERATION': 'list', 'SESSION': sessionid, 'SESSION_DIR': formatdir}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=False,
                                   timeout=RPC_SESSION_OPER_SHORT_REQ)
            if result is None:
                context = data_return(301, FileSession_MSG.get(301), {})
                return context
            try:
                result = json.loads(result)
            except Exception as E:
                logger.warning(E)
                context = data_return(302, FileSession_MSG.get(302), {})
                return context

            if result.get('status') is not True:
                context = data_return(303, FileSession_MSG.get(303), {})
                return context
            else:
                data = result.get('data')
                entries = data.get('entries')
                path = data.get('path')
                for one in entries:
                    if len(one.get('mode').split('/')) > 1:
                        one['format_mode'] = one.get('mode').split('/')[1]
                    else:
                        one['format_mode'] = ''

                    if one.get('total_space') is not None and one.get('free_space') is not None:
                        use_space = one.get('total_space') - one.get('free_space')
                        one['format_size'] = FileSession.get_size_in_nice_string(use_space)
                        one['format_mode'] = '{}|{}'.format(FileSession.get_size_in_nice_string(one.get('free_space')),
                                                            FileSession.get_size_in_nice_string(one.get('total_space')))
                    else:
                        one['format_size'] = FileSession.get_size_in_nice_string(one.get('size'))

                    if one.get('size') is None or one.get('size') >= 1024 * 100:
                        one['cat_able'] = False
                    else:
                        one['cat_able'] = True

                    if one.get('type') in ['directory', 'file', 'fixed', "remote"]:
                        one['absolute_path'] = os.path.join(path, one.get('name')).replace('\\\\', '/').replace('\\',
                                                                                                                '/')
                    elif one.get('type') in ['fix', 'cdrom']:
                        one['absolute_path'] = "{}".format(one.get('name'))
                    else:
                        one['absolute_path'] = "{}".format(path)

                context = data_return(200, CODE_MSG.get(200), data)
                return context
        elif operation == 'pwd' and sessionid is not None:  # 列当前目录
            opts = {'OPERATION': 'pwd', 'SESSION': sessionid}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=False,
                                   timeout=RPC_SESSION_OPER_SHORT_REQ)
            if result is None:
                context = data_return(301, FileSession_MSG.get(301), {})
                return context
            try:
                result = json.loads(result)
            except Exception as E:
                logger.warning(E)
                context = data_return(302, FileSession_MSG.get(302), {})
                return context

            if result.get('status') is not True:
                context = data_return(303, FileSession_MSG.get(303), {})
                return context
            else:
                data = result.get('data')
                entries = data.get('entries')
                path = data.get('path')
                for one in entries:
                    one['format_size'] = FileSession.get_size_in_nice_string(one.get('size'))
                    if one.get('size') >= 1024 * 100:
                        one['cat_able'] = False
                    else:
                        one['cat_able'] = True
                    if one.get('type') in ['directory', 'file']:
                        one['absolute_path'] = os.path.join(path, one.get('name')).replace('\\\\', '/').replace('\\',
                                                                                                                '/')
                    elif one.get('type') in ['fix', 'cdrom']:
                        one['absolute_path'] = "{}".format(one.get('name'))
                    else:
                        one['absolute_path'] = "{}".format(path)
                    if len(one.get('mode').split('/')) > 1:
                        one['format_mode'] = one.get('mode').split('/')[1]
                    else:
                        one['format_mode'] = ''
                context = data_return(200, CODE_MSG.get(200), data)
                return context
        elif operation == 'download' and sessionid is not None and filepath is not None:  # 下载文件
            opts = {'OPERATION': 'download', 'SESSION': sessionid, 'SESSION_FILE': filepath}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=True,
                                   timeout=RPC_JOB_API_REQ)  # 后台运行
            if result is None:
                context = data_return(301, FileSession_MSG.get(301), {})
                return context
            else:
                context = data_return(200, CODE_MSG.get(200), result)
                return context
        elif operation == "run":  # 执行文件
            opts = {'OPERATION': 'execute', 'SESSION': sessionid, 'SESSION_FILE': filepath, 'ARGS': arg}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=True,
                                   timeout=RPC_JOB_API_REQ)  # 后台运行
            if result is None:
                context = data_return(301, FileSession_MSG.get(301), {})
                return context
            else:
                context = data_return(202, FileSession_MSG.get(202), result)
                return context
        elif operation == "cat":  # 查看文件
            opts = {'OPERATION': 'cat', 'SESSION': sessionid, 'SESSION_FILE': filepath}
            moduleresult = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=False,
                                         timeout=RPC_SESSION_OPER_LONG_REQ)  # 后台运行
            if moduleresult is None:
                context = data_return(301, FileSession_MSG.get(301), {})
                return context
            else:
                try:
                    moduleresult = json.loads(moduleresult)
                except Exception as E:
                    logger.warning(E)
                    context = data_return(302, FileSession_MSG.get(302), {})
                    return context

                if moduleresult.get("status"):
                    filedata = base64.b64decode(moduleresult.get("data")).decode("utf-8", 'ignore')
                    result = {"data": filedata, "reason": filepath}
                    context = data_return(200, CODE_MSG.get(200), result)
                    return context
                else:
                    result = {"data": None, "reason": moduleresult.get("message")}
                    context = data_return(303, FileSession_MSG.get(303), result)
                    return context

        elif operation == "cd":  # 查看文件
            formatdir = FileSession.deal_path(dirpath)
            opts = {'OPERATION': 'cd', 'SESSION': sessionid, 'SESSION_DIR': formatdir}
            moduleresult = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=False,
                                         timeout=RPC_SESSION_OPER_SHORT_REQ)  # 后台运行
            if moduleresult is None:
                context = data_return(301, FileSession_MSG.get(301), {})
                return context
            else:
                try:
                    moduleresult = json.loads(moduleresult)
                except Exception as E:
                    logger.warning(E)
                    context = data_return(302, FileSession_MSG.get(302), {})
                    return context

                if moduleresult.get("status"):
                    result = {}
                    context = data_return(203, FileSession_MSG.get(203), result)
                    return context
                else:
                    result = {"data": None, "reason": moduleresult.get("message")}
                    context = data_return(303, FileSession_MSG.get(303), result)
                    return context
        else:
            context = data_return(306, FileSession_MSG.get(306), {})
            return context

    @staticmethod
    def create(sessionid=None, filename=None, dirpath=None, operation=None):
        if operation == 'create_dir' and sessionid is not None and dirpath is not None:  # 新建文件夹
            formatdir = FileSession.deal_path(dirpath)
            opts = {'OPERATION': 'create_dir', 'SESSION': sessionid, 'SESSION_DIR': formatdir}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=False,
                                   timeout=RPC_SESSION_OPER_SHORT_REQ)
            if result is None:
                context = data_return(301, FileSession_MSG.get(301), [])
                return context
            try:
                result = json.loads(result)
            except Exception as E:
                logger.warning(E)
                context = data_return(302, FileSession_MSG.get(302), {})
                return context

            if result.get('status') is not True:
                context = data_return(303, FileSession_MSG.get(303), [])
                return context
            else:
                context = data_return(201, FileSession_MSG.get(201), result.get('data'))
                return context
        # 上传文件
        elif operation == 'upload_file' and sessionid is not None and filename is not None and dirpath is not None:
            formatdir = FileSession.deal_path(dirpath)
            opts = {'OPERATION': 'upload', 'SESSION': sessionid, 'SESSION_DIR': formatdir, 'MSF_FILE': filename}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=True,
                                   timeout=RPC_JOB_API_REQ)
            if result is None:
                context = data_return(301, FileSession_MSG.get(301), {})
                return context
            else:
                context = data_return(201, FileSession_MSG.get(201), result)
                return context
        else:
            context = data_return(306, FileSession_MSG.get(306), [])
            return context

    @staticmethod
    def update(sessionid, filepath, filedata):
        opts = {'OPERATION': 'update_file', 'SESSION': sessionid, 'SESSION_FILE': filepath, 'FILE_DATA': filedata}
        result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=True,
                               timeout=RPC_SESSION_OPER_LONG_REQ)
        if result is None:
            context = data_return(301, FileSession_MSG.get(301), {})
            return context
        else:
            context = data_return(204, FileSession_MSG.get(204), result)
            return context

    @staticmethod
    def destory(sessionid=None, filepath=None, dirpath=None, operation=None):
        if operation == 'destory_file' and sessionid is not None and filepath is not None:
            opts = {'OPERATION': 'destory_file', 'SESSION': sessionid, 'SESSION_FILE': filepath}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=False,
                                   timeout=RPC_SESSION_OPER_SHORT_REQ)
            if result is None:
                context = data_return(301, FileSession_MSG.get(301), [])
                return context
            try:
                result = json.loads(result)
            except Exception as E:
                logger.warning(E)
                context = data_return(302, FileSession_MSG.get(302), {})
                return context
            if result.get('status') is not True:
                context = data_return(303, FileSession_MSG.get(303), [])
                return context
            else:
                context = data_return(201, FileSession_MSG.get(201), [])
                return context
        elif operation == 'destory_dir':
            formatdir = FileSession.deal_path(dirpath)
            opts = {'OPERATION': 'destory_dir', 'SESSION': sessionid, 'SESSION_DIR': formatdir}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=False,
                                   timeout=RPC_SESSION_OPER_SHORT_REQ)
            if result is None:
                context = data_return(301, FileSession_MSG.get(301), [])
                return context
            try:
                result = json.loads(result)
            except Exception as E:
                logger.warning(E)
                context = data_return(302, FileSession_MSG.get(302), {})
                return context
            if result.get('status') is not True:
                context = data_return(303, FileSession_MSG.get(303), [])
                return context
            else:
                context = data_return(201, FileSession_MSG.get(201), [])
                return context
        else:
            context = data_return(306, FileSession_MSG.get(306), {})
            return context

    @staticmethod
    def get_size_in_nice_string(size_in_bytes=None):
        """
        Convert the given byteCount into a string like: 9.9bytes/KB/MB/GB
        """
        if size_in_bytes is None:
            size_in_bytes = 0
        for (cutoff, label) in [(1024 * 1024 * 1024, "GB"),
                                (1024 * 1024, "MB"),
                                (1024, "KB"),
                                ]:
            if size_in_bytes >= cutoff:
                return "%.1f %s" % (size_in_bytes * 1.0 / cutoff, label)

        if size_in_bytes == 1:
            return "1 B"
        else:
            bytes_str = "%.1f" % (size_in_bytes or 0,)
            return (bytes_str[:-2] if bytes_str.endswith('.0') else bytes_str) + ' B'

    @staticmethod
    def deal_path(path=None):
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
            logger.warning('输入错误字符')
            tmppath = '/'
        return tmppath
