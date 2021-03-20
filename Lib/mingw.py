# -*- coding: utf-8 -*-
# @File  : mingw.py
# @Date  : 2021/2/26
# @Desc  :
import os
import subprocess
import time

from django.conf import settings

from CONFIG import DEBUG
from Lib.configs import STATIC_STORE_PATH
from Lib.lib import TMP_DIR
from Lib.log import logger


class MingwOld(object):
    INCULDE_DIR = os.path.join(settings.BASE_DIR, STATIC_STORE_PATH, "mingw_header")
    CODE_TEMPLATE_DIR = os.path.join(settings.BASE_DIR, STATIC_STORE_PATH, "mingw_template")

    def __init__(self):
        self.mingw_bin = "x86_64-w64-mingw32-gcc"
        self.file_name = int(time.time())

        self.strip_syms = True
        self.link_script = None

    def build_cmd(self, src, arch="x64"):

        src_file = os.path.join(TMP_DIR, f"{self.file_name}.c")
        exe_file = os.path.join(TMP_DIR, f"{self.file_name}.exe")
        cmd = []
        with open(src_file, "wb") as f:
            f.write(src.encode("utf-8"))
        # 编译src
        if arch == "x64":
            cmd.append("x86_64-w64-mingw32-gcc")
        else:
            cmd.append("i686-w64-mingw32-gcc")

        cmd.append(src_file)
        # 头文件
        cmd.append("-I")
        cmd.append(self.INCULDE_DIR)
        # 输出文件
        cmd.append("-o")
        cmd.append(exe_file)

        # cmd.append("-nostdlib")

        # 其他参数
        cmd.append("-mwindows")
        cmd.append("-fno-ident")
        cmd.append("-ffunction-sections")

        opt_level = "-O2"
        cmd.append(opt_level)

        # linux独有参数
        if DEBUG:
            if self.strip_syms:
                cmd.append("-s")
        else:
            cmd.append("-fno-asynchronous-unwind-tables")
            link_options = '-Wl,' + '--no-seh,'
            if self.strip_syms:
                link_options += '-s'
            if self.link_script:
                link_options += f",-T{self.link_script}"
            cmd.append(link_options)
        return cmd

    def compile_c(self, src, arch="x64"):
        bindata = None
        exe_file = os.path.join(TMP_DIR, f"{self.file_name}.exe")
        cmd = self.build_cmd(src, arch)
        ret = subprocess.run(cmd, capture_output=True, text=True)
        if ret.returncode != 0:
            logger.warning(ret.stdout)
            logger.warning(ret.stderr)
        else:
            try:
                with open(exe_file, 'rb') as f:
                    bindata = f.read()
            except Exception as E:
                logger.exception(E)
        self.cleanup_files()
        return bindata

    def cleanup_files(self):
        src_file = os.path.join(TMP_DIR, f"{self.file_name}.c")
        exe_file = os.path.join(TMP_DIR, f"{self.file_name}.exe")
        try:
            os.remove(src_file)
        except Exception as E:
            logger.exception(E)

        try:
            os.remove(exe_file)
        except Exception as E:
            logger.exception(E)


class Mingw(object):
    MINGW_BIN_X64 = "x86_64-w64-mingw32-gcc"
    MINGW_BIN_X86 = "i686-w64-mingw32-gcc"

    def __init__(self, include_dir: str, source_code: str):
        self.include_dir = include_dir
        self.source_code = source_code  # 源码文件的内容,str格式
        self.strip_syms = True
        self.link_script = None

        self._filename = str(time.time() * 1000_0000)
        self._src_file = os.path.join(TMP_DIR, f"{self._filename}.cpp")
        self._exe_file = os.path.join(TMP_DIR, f"{self._filename}.exe")

    def _build_cmd(self, arch="x64", extra_params=[]):
        cmd = []
        if arch == "x64":
            cmd.append("x86_64-w64-mingw32-gcc")
        else:
            cmd.append("i686-w64-mingw32-gcc")
        # cpp文件
        cmd.append(self._src_file)
        # 头文件
        cmd.append("-I")
        cmd.append(self.include_dir)
        # 输出文件
        cmd.append("-o")
        cmd.append(self._exe_file)

        # cmd.append("-nostdlib")

        # 其他参数
        cmd.append("-mwindows")
        cmd.append("-fno-ident")
        cmd.append("-ffunction-sections")

        cmd.append("-fvisibility=hidden")

        opt_level = "-O2"
        cmd.append(opt_level)
        if extra_params != []:
            cmd.extend(extra_params)

        cmd.append(opt_level)
        # linux独有参数
        if DEBUG:
            if self.strip_syms:
                cmd.append("-s")
        else:
            cmd.append("-fno-asynchronous-unwind-tables")
            link_options = '-Wl,' + '--no-seh,'
            if self.strip_syms:
                link_options += '-s'
            if self.link_script:
                link_options += f",-T{self.link_script}"
            cmd.append(link_options)
        return cmd

    def compile(self, arch="x64", extra_params=[]):

        bindata = None
        # 生成源码文件
        with open(self._src_file, "wb") as f:
            f.write(self.source_code.encode("utf-8"))

        # 编译
        cmd = self._build_cmd(arch, extra_params=extra_params)
        ret = subprocess.run(cmd, capture_output=True, text=True)
        if ret.returncode != 0:
            logger.warning(ret.stdout)
            logger.warning(ret.stderr)
        else:
            try:
                with open(self._exe_file, 'rb') as f:
                    bindata = f.read()
            except Exception as E:
                logger.exception(E)

        # 清理遗留文件
        self._cleanup_files()
        return bindata

    def _cleanup_files(self):
        try:
            os.remove(self._src_file)
        except Exception as E:
            logger.exception(E)

        try:
            os.remove(self._exe_file)
        except Exception as E:
            logger.exception(E)
