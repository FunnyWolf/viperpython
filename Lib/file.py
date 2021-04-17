# -*- coding: utf-8 -*-
# @File  : file.py
# @Date  : 2021/4/1
# @Desc  :
import os
import shutil

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
