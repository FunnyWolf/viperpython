# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

#
#

from PostModule.lib.Configs import *
from PostModule.lib.ModuleTemplate import TAG2CH, PostMSFRawModule
from PostModule.lib.OptionAndResult import Option, register_options


# from PostModule.lib.Session import Session


class PostModule(PostMSFRawModule):
    NAME = "原始msf模块样例"
    DESC = "这是一个原始msf模块的样例,执行的是multi/gather/session_info模块"
    REQUIRE_SESSION = True
    MODULETYPE = TAG2CH.example
    OPTIONS = register_options([
        Option(name='StrTest', name_tag="字符串测试", type='str', required=False, desc="测试一个字符串参数", ),
        Option(name='BoolTest', name_tag="Bool测试", type='bool', required=False, desc="测试一个Bool参数", default=False),
        Option(name='IntgerTest', name_tag="Intger测试", type='integer', required=False, desc="测试一个Intger参数"),
        Option(name='EnumTest', name_tag="Enum测试", type='enum', required=False, desc="测试一个enum参数", default='test1',
               enum_list=['test1', 'test2', 'test3']),
        Option(name=HANDLER_OPTION.get('name'), name_tag=HANDLER_OPTION.get('name_tag'),
               type=HANDLER_OPTION.get('type'), required=False,
               desc=HANDLER_OPTION.get('desc'),
               enum_list=[], option_length=HANDLER_OPTION.get('option_length')),
        Option(name=CREDENTIAL_OPTION.get('name'), name_tag=CREDENTIAL_OPTION.get('name_tag'),
               type=CREDENTIAL_OPTION.get('type'),
               required=False,
               desc=CREDENTIAL_OPTION.get('desc'),
               enum_list=[],
               option_length=CREDENTIAL_OPTION.get('option_length'),
               extra_data={'password_type': ['windows', 'browsers']}
               ),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "post"
        self.mname = "multi/gather/session_info"
        self.runasjob = True

    def check(self):
        """执行前的检查函数"""
        return True, None

    def callback(self, status, message, data):
        print(status)
        print(message)
        print(data)

