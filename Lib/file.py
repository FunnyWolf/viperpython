# -*- coding: utf-8 -*-
# @File  : file.py
# @Date  : 2021/4/1
# @Desc  :
import os
import shutil
import time
import zipfile

from django.conf import settings

from Lib.configs import MSFLOOT

TMP_DIR = os.path.join(settings.BASE_DIR, 'STATICFILES', 'TMP')


class File(object):
    """文件,目录相关API"""

    def __init__(self):
        pass

    @staticmethod
    def tmp_dir():
        return TMP_DIR

    @staticmethod
    def safe_os_path_join(path, filename):
        filename = os.path.normpath(filename)
        outpath = os.path.join(path, filename)
        if outpath.startswith(path):
            return outpath
        else:
            return None

    @staticmethod
    def clean_tmp_dir():
        shutil.rmtree(TMP_DIR)
        os.mkdir(TMP_DIR)
        return True

    @staticmethod
    def loot_dir():
        return MSFLOOT

    @staticmethod
    def clean_logs():
        """每天定时清除日志"""
        for root, dirs, files in os.walk(os.path.join(settings.BASE_DIR, 'Docker', 'log')):
            for file in files:
                log_file = os.path.join(settings.BASE_DIR, 'Docker', 'log', file)
                with open(log_file, "r+") as f:
                    f.seek(0)
                    f.truncate()
        try:
            with open("/root/.msf4/log/framework.log", "r+", encoding="utf-8") as f:
                f.seek(0)
                f.truncate()
        except Exception as E:
            pass

    @staticmethod
    def zip_logs():
        filename = f"logs-{int(time.time())}.zip"
        ziplog_path = os.path.join(File.tmp_dir(), filename)
        new_zip = zipfile.ZipFile(ziplog_path, 'w')
        for root, dirs, files in os.walk(os.path.join(settings.BASE_DIR, 'Docker', 'log')):
            for file in files:
                log_file = os.path.join(settings.BASE_DIR, 'Docker', 'log', file)
                new_zip.write(log_file, arcname=file, compress_type=zipfile.ZIP_DEFLATED)
        try:
            new_zip.write("/root/.msf4/log/framework.log", arcname="framework.log", compress_type=zipfile.ZIP_DEFLATED)
        except Exception as E:
            pass
        new_zip.close()
        return ziplog_path
