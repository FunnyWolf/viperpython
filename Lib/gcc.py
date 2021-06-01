# -*- coding: utf-8 -*-
# @File  : mingw.py
# @Date  : 2021/2/26
# @Desc  :
import os
import subprocess
import time

from django.conf import settings

from Lib.configs import STATIC_STORE_PATH
from Lib.file import File
from Lib.log import logger

GCC_INCULDE_DIR = os.path.join(settings.BASE_DIR, STATIC_STORE_PATH, "gcc_header")
GCC_CODE_TEMPLATE_DIR = os.path.join(settings.BASE_DIR, STATIC_STORE_PATH, "gcc_template")

GLIBC_PATH = os.path.join(settings.BASE_DIR, STATIC_STORE_PATH, "glibc", "lib64")
GLIBC_LD_PATH = os.path.join(settings.BASE_DIR, STATIC_STORE_PATH, "glibc", "lib64", "ld-linux-x86-64.so.2")


class Gcc(object):
    def __init__(self, include_dir: str, source_code: str):
        self.include_dir = include_dir
        self.source_code = source_code  # 源码文件的内容,str格式
        self.strip_syms = True
        self.link_script = None

        self._filename = str(time.time() * 1000_0000)
        self._c_src_file = os.path.join(File.tmp_dir(), f"{self._filename}.c")
        self._cpp_src_file = os.path.join(File.tmp_dir(), f"{self._filename}.cpp")
        self._exe_file = os.path.join(File.tmp_dir(), f"{self._filename}.elf")

    def _c_build_cmd(self, arch="x64", extra_params=[]):
        cmd = []
        cmd.append("gcc")
        if arch == "x64":
            pass
        else:
            cmd.append("-m32")
        # cpp文件
        cmd.append(self._c_src_file)
        # 头文件
        cmd.append("-I")
        cmd.append(self.include_dir)
        # 输出文件
        cmd.append("-o")
        cmd.append(self._exe_file)

        # static link glibc
        cmd.append(f"-Wl,-rpath='{GLIBC_PATH}',-dynamic-linker='{GLIBC_LD_PATH}'")

        # 其他参数
        cmd.append("-static")
        cmd.append("-z execstack")

        if extra_params != []:
            cmd.extend(extra_params)
        return cmd

    def _cpp_build_cmd(self, arch="x64", extra_params=[]):
        cmd = []
        cmd.append("gcc")
        if arch == "x64":
            pass
        else:
            cmd.append("-m32")
        # cpp文件
        cmd.append(self._cpp_src_file)
        # 头文件
        cmd.append("-I")
        cmd.append(self.include_dir)
        # 输出文件
        cmd.append("-o")
        cmd.append(self._exe_file)

        # 其他参数
        cmd.append("-static")
        cmd.append("-z execstack")

        if extra_params != []:
            cmd.extend(extra_params)
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
        try:
            os.remove(self._cpp_src_file)
            os.remove(self._c_src_file)
        except Exception as E:
            pass
        try:
            os.remove(self._exe_file)
        except Exception as E:
            pass
