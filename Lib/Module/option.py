# -*- coding: utf-8 -*-
# @File  : ModuleOptionAndResult.py
# @Date  : 2019/2/12
# @Desc  :


from Lib.Module.configs import FILE_OPTION, CREDENTIAL_OPTION, HANDLER_OPTION, CACHE_HANDLER_OPTION
from Lib.log import logger

option_type_list = ['str', 'bool', 'address', 'address_range', 'float', 'integer', 'enum']
result_type_list = ['str', 'list', 'dict', 'table']
option_type_default_length = {
    'float': 6, 'integer': 6, 'bool': 6, 'enum': 6,
    'str': 12, 'address': 12,
    'address_range': 18,
}


def register_options(options_list=None):
    """注册参数"""
    if options_list is None:
        options_list = []
    options = []
    try:
        for option in options_list:
            options.append(option.to_dict())
        return options
    except Exception as E:
        logger.error(E)
        return []


class _Option(object):
    def __init__(self, name, name_tag=None, option_type='str', required=False, desc=None, default=None, enum_list=None,
                 option_length=None, extra_data=None):
        if enum_list is None:
            enum_list = []
        self._name = name  # 参数名称

        if name_tag is None:
            self._name_tag = name
        else:
            self._name_tag = name_tag  # 参数的前端显示名称(前端显示用,例如如果name为"path",则name_tag为"路径")
        if desc is None:
            self._desc = name
        else:
            self._desc = desc  # 参数提示信息,详细描述参数作用

        self._type = option_type  # 参数类型,参考option_type_list
        self._required = required  # 是否必填
        self._default = default  # 参数默认值
        self._enum_list = enum_list  # enum类型的待选列表,如果type为enum类型则此参数必须填写
        self._option_length = option_length
        self._extra_data = extra_data  # 参数需要传递的额外信息

    def to_dict(self):
        """将参数对象转化为json格式数据"""
        _dict = {
            'name': self._name,
            'name_tag': self._name_tag,
            'type': self._type,
            'required': self._required,
            'desc': self._desc,
            'default': self._default,
            'extra_data': self._extra_data,
        }

        # 处理option_length参数的兼容性
        if self._option_length is None:
            _dict['option_length'] = option_type_default_length.get(self._type)
        else:
            _dict['option_length'] = self._option_length

        # 处理enum_list参数的兼容性,请注意,此处无法处理handler和凭证等动态参数
        tmp_enmu_list = []
        for one_enmu in self._enum_list:
            if isinstance(one_enmu, str) or isinstance(one_enmu, bytes):
                tmp_enmu_list.append({'name': one_enmu, 'value': one_enmu})
            else:
                if one_enmu.get('name') is not None and one_enmu.get('value') is not None:
                    tmp_enmu_list.append(one_enmu)
                else:
                    logger.warning("参数错误, name: {} name_tag:{}".format(self._name, self._name_tag))
        _dict['enum_list'] = tmp_enmu_list
        return _dict


class OptionStr(_Option):
    def __init__(self, name, name_tag=None, desc=None, required=False, default=None,
                 option_length=None):
        super().__init__(option_type='str', name=name, name_tag=name_tag, desc=desc, required=required, default=default,
                         option_length=option_length)

#
class OptionIntger(_Option):
    def __init__(self, name, name_tag=None, desc=None, required=False, default=None,
                 option_length=6):
        super().__init__(option_type='integer', name=name, name_tag=name_tag, desc=desc, required=required,
                         default=default,
                         option_length=option_length)


class OptionBool(_Option):
    def __init__(self, name, name_tag=None, desc=None, required=False, default=False,
                 option_length=4):
        super().__init__(option_type='bool', name=name, name_tag=name_tag, desc=desc, required=required,
                         default=default,
                         option_length=option_length)



class OptionEnum(_Option):
    def __init__(self, name=None, name_tag=None, desc=None, required=False, default=None, option_length=6,
                 enum_list=None):
        # enum_list = [
        #     {'name': "劫持", 'value': "Hijack"},
        #     {'name': "恢复", 'value': "Recovery"},
        # ]
        if enum_list is None:
            enum_list = []
        super().__init__(option_type='enum', name=name, name_tag=name_tag, required=required, desc=desc,
                         default=default,
                         enum_list=enum_list,
                         option_length=option_length, extra_data=None)
        self.is_valid()

    def is_valid(self):
        for oneEnum in self._enum_list:
            if oneEnum.get("name") is None:
                logger.exception(f"参数 {self._name} 格式不符合要求,正确格式应为字典,其中包含name及value字段")


class OptionIPAddressRange(_Option):
    def __init__(self, name, name_tag=None, desc=None, required=False, default=None):
        super().__init__(option_type='address_range', name=name, name_tag=name_tag, desc=desc, required=required,
                         default=default)


class OptionFileEnum(_Option):
    def __init__(self, required=True, ext=None):
        if ext is None:
            ext = []
        super().__init__(option_type='enum',
                         name=FILE_OPTION.get('name'),
                         name_tag=FILE_OPTION.get('name_tag'),
                         desc=FILE_OPTION.get('desc'),
                         option_length=FILE_OPTION.get('option_length'),
                         required=required,
                         extra_data={'file_extension': ext}
                         )


class OptionCredentialEnum(_Option):
    def __init__(self, required=True, password_type=None):
        if password_type is None:
            password_type = []
        super().__init__(option_type='enum',
                         name=CREDENTIAL_OPTION.get('name'),
                         name_tag=CREDENTIAL_OPTION.get('name_tag'),
                         desc=CREDENTIAL_OPTION.get('desc'),
                         option_length=CREDENTIAL_OPTION.get('option_length'),
                         required=required,
                         extra_data={'password_type': password_type}
                         )


class OptionHander(_Option):
    def __init__(self, required=True):
        super().__init__(option_type='enum',
                         name=HANDLER_OPTION.get('name'),
                         name_tag=HANDLER_OPTION.get('name_tag'),
                         desc=HANDLER_OPTION.get('desc'),
                         option_length=HANDLER_OPTION.get('option_length'),
                         required=required,
                         )


class OptionCacheHanderConfig(_Option):
    def __init__(self):
        super().__init__(option_type='bool',
                         name=CACHE_HANDLER_OPTION.get('name'),
                         name_tag=CACHE_HANDLER_OPTION.get('name_tag'),
                         desc=CACHE_HANDLER_OPTION.get('desc'),
                         option_length=CACHE_HANDLER_OPTION.get('option_length'),
                         required=CACHE_HANDLER_OPTION.get('required'),
                         default=CACHE_HANDLER_OPTION.get('default'),
                         )
