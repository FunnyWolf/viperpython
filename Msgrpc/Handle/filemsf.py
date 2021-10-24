# -*- coding: utf-8 -*-
# @File  : filemsf.py
# @Date  : 2021/2/25
# @Desc  :
import base64
import functools
import os
from urllib import parse

from django.http import HttpResponse

from CONFIG import MSFLOOTTRUE
from Lib.aescrypt import Aescrypt
from Lib.api import data_return
from Lib.configs import CODE_MSG_ZH, FileMsf_MSG_ZH, MSFLOOT, CODE_MSG_EN, FileMsf_MSG_EN
from Lib.file import File
from Lib.log import logger
from Lib.xcache import Xcache
from Msgrpc.Handle.filesession import FileSession


class FileMsf(object):
    def __init__(self):
        pass

    @staticmethod
    def list(filename=None, action=None):
        if filename is None:  # 列出所有文件
            result = FileMsf.list_msf_files()
            for one in result:
                one['format_size'] = FileSession.get_size_in_nice_string(one.get('size'))

            def sort_files(a, b):
                if a['mtime'] < b['mtime']:
                    return 1
                if a['mtime'] > b['mtime']:
                    return -1
                return 0

            # 根据时间排序
            result_sorted = sorted(result, key=functools.cmp_to_key(sort_files))
            context = data_return(200, result_sorted, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
            return context
        else:  # 下载文件
            binary_data = FileMsf.read_msf_file(filename)
            if binary_data is None:
                context = data_return(303, {}, FileMsf_MSG_ZH.get(303), FileMsf_MSG_EN.get(303))
                return context

            if action == "view":
                b64data = base64.b64encode(binary_data)
                ext = os.path.splitext(filename)[-1]
                if ext in ['.jpeg', '.png', '.jpg']:
                    context = data_return(200, {"type": "img", "data": b64data}, CODE_MSG_ZH.get(200),
                                          CODE_MSG_EN.get(200))
                    return context
                else:
                    context = data_return(200, {"type": "txt", "data": b64data}, CODE_MSG_ZH.get(200),
                                          CODE_MSG_EN.get(200))
                    return context

            response = HttpResponse(binary_data)
            response['Content-Type'] = 'application/octet-stream'
            response['Code'] = 200
            response['Msg_zh'] = parse.quote(FileMsf_MSG_ZH.get(203))
            response['Msg_en'] = parse.quote(FileMsf_MSG_EN.get(203))
            # 中文特殊处理
            urlpart = parse.quote(os.path.splitext(filename)[0], 'utf-8')
            leftpart = os.path.splitext(filename)[-1]
            response['Content-Disposition'] = f"{urlpart}{leftpart}"
            return response

    @staticmethod
    def create(file=None):
        result = FileMsf.write_file_to_msf(file)
        if result is True:
            context = data_return(201, {}, FileMsf_MSG_ZH.get(201), FileMsf_MSG_EN.get(201))
        else:
            context = data_return(302, {}, FileMsf_MSG_ZH.get(302), FileMsf_MSG_EN.get(302))
        return context

    @staticmethod
    def destory(filename=None):
        result = FileMsf.destory_msf_file(filename)
        if result is True:

            context = data_return(202, {}, FileMsf_MSG_ZH.get(202), FileMsf_MSG_EN.get(202))
            return context
        else:

            context = data_return(301, {}, FileMsf_MSG_ZH.get(301), FileMsf_MSG_EN.get(301))
            return context

    @staticmethod
    def list_msf_files():
        result = []
        try:
            filelist = os.listdir(MSFLOOT)
            for file in filelist:
                filepath = File.safe_os_path_join(MSFLOOT, file)
                if os.path.isfile(filepath):
                    fileinfo = os.stat(filepath)
                    enfilename = FileMsf.encrypt_file_name(file)
                    result.append({
                        "name": file,
                        "enfilename": enfilename,
                        "size": fileinfo.st_size,
                        "mtime": int(fileinfo.st_mtime)
                    })
            return result
        except Exception as E:
            logger.exception(E)
            return []

    @staticmethod
    def write_file_to_msf(file=None):
        try:
            filename = file.name
            filepath = File.safe_os_path_join(MSFLOOT, filename)
            with open(filepath, "wb+") as f:
                for chunk in file.chunks():
                    f.write(chunk)
            return True
        except Exception as E:
            logger.warning(E)
            return False

    @staticmethod
    def write_msf_file(filename=None, data=None, msf=True):
        filepath = File.safe_os_path_join(MSFLOOT, filename)
        with open(filepath, "wb+") as f:
            f.write(data)
        return FileMsf.get_absolute_path(filename, msf=msf)

    @staticmethod
    def read_msf_file(filename=None):
        filepath = File.safe_os_path_join(MSFLOOT, filename)
        if os.path.isfile(filepath):
            with open(filepath, "rb+") as f:
                binary_data = f.read()
            return binary_data
        else:
            return None

    @staticmethod
    def destory_msf_file(filename=None):
        filepath = File.safe_os_path_join(MSFLOOT, filename)
        if os.path.isfile(filepath):
            os.remove(filepath)
            return True
        else:
            return False

    @staticmethod
    def encrypt_file_name(filename):
        key = Xcache.get_aes_key()
        pr = Aescrypt(key, 'ECB', '', 'utf-8')
        en_text = pr.aesencrypt(filename)
        en_text_url = parse.quote(en_text)
        return en_text_url

    @staticmethod
    def decrypt_file_name(enfilename):
        key = Xcache.get_aes_key()
        pr = Aescrypt(key, 'ECB', '', 'utf-8')
        try:
            enfilename_url = parse.unquote(enfilename)
            filename = pr.aesdecrypt(enfilename_url)

            return filename
        except Exception as E:
            logger.exception(E)
            return None

    @staticmethod
    def get_absolute_path(filename, msf=False):
        """获取loot目录文件的绝对路径,msf表示是不是msf模块使用此路径"""
        if msf:
            filepath = f"{MSFLOOTTRUE}/{filename}"
        else:
            filepath = File.safe_os_path_join(MSFLOOT, filename)
        return filepath
