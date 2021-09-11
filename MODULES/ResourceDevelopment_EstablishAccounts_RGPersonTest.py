# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *
from MODULES_DATA.Reconnaissance_Other_RGPerson.RGPerson import *


class PostModule(PostPythonModule):
    NAME_ZH = "随机身份生成(中文)111111111111"
    DESC_ZH = "该脚本生成信息：中国黑客ID\姓名\年龄\性别\身份证\手机号\组织机构代码\统一社会信用代码."
    NAME_EN = "Base module"
    DESC_EN = "Base desc_zh"
    MODULETYPE = TAG2TYPE.Resource_Development

    ATTCK = ["T1585"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/gsz9lt"]
    REFERENCES = ["https://github.com/gh0stkey/RGPerson",
                  "https://attack.mitre.org/techniques/T1585/"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = False
    OPTIONS = register_options([
        OptionStr(name='apiip',
                  tag_zh="API网关公网IP地址", desc_zh="使用IP地址上线时填写此信息",
                  tag_en="API gateway public IP address",
                  desc_en="Fill in this information when using the IP address to online session",
                  ),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        return True, None

    def run(self):
        import time
        time.sleep(20)
        age = random.randint(18, 60)  # 可调整生成的年龄范围（身份证），这边是16-60岁
        gender = random.randint(0, 1)
        name = genName()
        sex = u"男" if gender == 1 else u"女"

        self.log_raw("ID: {}\n姓名: {} \n年龄: {}\n性别: {}\n身份证: {}\n手机号: {} {}\n组织机构代码: {}\n统一社会信用代码: {}\n单位性质: {}".format(
            genHackerId(), name, age, sex, genIdCard(age, gender), list(genMobile().keys())[0],
            list(genMobile().values())[0], genOrgCode(), list(genCreditCode().keys())[0],
            list(genCreditCode().values())[0]))
