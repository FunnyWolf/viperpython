# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *
from MODULES_DATA.Reconnaissance_Other_RGPerson.RGPerson import *


class PostModule(PostPythonModule):
    NAME_ZH = "随机身份生成(中文)"
    DESC_ZH = "该脚本生成信息：中国黑客ID\姓名\年龄\性别\身份证\手机号\组织机构代码\统一社会信用代码."

    NAME_EN = "Random Identity Generation (Chinese)"
    DESC_EN = "The script generates information: Chinese hacker ID\\name\\age\\gender\\ID card\\phone number\\organization code\\unified social credit code."

    MODULETYPE = TAG2TYPE.Resource_Development

    ATTCK = ["T1585"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/gsz9lt"]
    REFERENCES = ["https://github.com/gh0stkey/RGPerson",
                  "https://attack.mitre.org/techniques/T1585/"]
    AUTHOR = ["Viper"]

    REQUIRE_SESSION = False
    OPTIONS = []

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        return True, None

    def run(self):
        age = random.randint(18, 60)  # 可调整生成的年龄范围（身份证），这边是16-60岁
        gender = random.randint(0, 1)
        name = genName()
        sex = u"男" if gender == 1 else u"女"

        self.log_raw(f"ID: {genHackerId()}\n"
                     f"姓名: {name} \n"
                     f"年龄: {age}\n"
                     f"性别: {sex}\n"
                     f"身份证: {genIdCard(age, gender)}\n"
                     f"手机号: {list(genMobile().keys())[0]} {list(genMobile().values())[0]}\n"
                     f"组织机构代码: {genOrgCode()}\n"
                     f"统一社会信用代码: {list(genCreditCode().keys())[0]}\n"
                     f"单位性质: {list(genCreditCode().values())[0]}")
