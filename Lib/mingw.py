# -*- coding: utf-8 -*-
# @File  : mingw.py
# @Date  : 2021/2/26
# @Desc  :
import os
import subprocess

from django.conf import settings

from CONFIG import DEBUG
from Lib.api import random_str
from Lib.configs import STATIC_STORE_PATH
from Lib.file import File
from Lib.log import logger

MINGW_INCULDE_DIR = os.path.join(settings.BASE_DIR, STATIC_STORE_PATH, "mingw_header")
MINGW_CODE_TEMPLATE_DIR = os.path.join(settings.BASE_DIR, STATIC_STORE_PATH, "mingw_template")


class Mingw(object):
    MINGW_BIN_X64 = "x86_64-w64-mingw32-gcc"
    MINGW_BIN_X86 = "i686-w64-mingw32-gcc"

    def __init__(self, include_dir, source_code: str):
        self.include_dir = include_dir
        self.source_code = source_code  # 源码文件的内容,str格式
        self.strip_syms = True
        self.link_script = None

        self._filename = random_str(8)
        self._c_src_file = os.path.join(File.tmp_dir(), f"{self._filename}.c")
        self._cpp_src_file = os.path.join(File.tmp_dir(), f"{self._filename}.cpp")
        self._exe_file = os.path.join(File.tmp_dir(), f"{self._filename}.exe")

    def _c_build_cmd(self, arch="x64", extra_params=[]):
        cmd = []
        if arch == "x64":
            cmd.append("x86_64-w64-mingw32-gcc")
        else:
            cmd.append("i686-w64-mingw32-gcc")
        # cpp文件
        cmd.append(self._c_src_file)
        # 头文件
        if self.include_dir:
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

    def _cpp_build_cmd(self, arch="x64", extra_params=[]):
        cmd = []
        if arch == "x64":
            cmd.append("x86_64-w64-mingw32-gcc")
        else:
            cmd.append("i686-w64-mingw32-gcc")

        # cpp文件
        cmd.append(self._cpp_src_file)

        # 头文件
        if self.include_dir:
            cmd.append("-I")
            cmd.append(self.include_dir)

        # 输出文件
        cmd.append("-o")
        cmd.append(self._exe_file)

        # 其他参数
        cmd.append("-mwindows")
        cmd.append("-fno-ident")
        cmd.append("-ffunction-sections")

        cmd.append("-fvisibility=hidden")

        opt_level = "-O2"
        cmd.append(opt_level)
        if extra_params != []:
            cmd.extend(extra_params)

        # cmd.append("-static")
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

    def compile_cpp(self, arch="x64", extra_params=[]):

        bindata = None
        # 生成源码文件
        with open(self._cpp_src_file, "wb") as f:
            f.write(self.source_code.encode("utf-8"))

        # 编译
        cmd = self._cpp_build_cmd(arch, extra_params=extra_params)
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

    def compile_c(self, arch="x64", extra_params=[]):

        bindata = None
        # 生成源码文件
        with open(self._c_src_file, "wb") as f:
            f.write(self.source_code.encode("utf-8"))

        # 编译
        cmd = self._c_build_cmd(arch, extra_params=extra_params)
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
        if DEBUG:
            return
        try:
            os.remove(self._cpp_src_file)
            os.remove(self._c_src_file)
        except Exception as E:
            pass
        try:
            os.remove(self._exe_file)
        except Exception as E:
            pass
