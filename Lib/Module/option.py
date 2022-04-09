# -*- coding: utf-8 -*-
# @File  : ModuleOptionAndResult.py
# @Date  : 2019/2/12
# @Desc  :


from Lib.Module.configs import FILE_OPTION, CREDENTIAL_OPTION, HANDLER_OPTION, CACHE_HANDLER_OPTION
from Lib.log import logger

option_type_list = ['str', 'bool', 'address', 'address_range', 'float', 'integer', 'enum']
result_type_list = ['str', 'list', 'dict', 'table']
option_type_default_length = {
    'float': 6,
    'integer': 6,
    'bool': 6,
    'enum': 6,
    'str': 12,
    'address': 12,
    'address_range': 18,
}


def register_options(options_list=None):
    """注册模块参数"""
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
    def __init__(self, name,
                 tag_zh=None, desc_zh=None,
                 tag_en=None, desc_en=None,
                 type='str', required=False, default=None, enum_list=None,
                 length=None, extra_data=None):
        if enum_list is None:
            enum_list = []

        self._name = name  # 参数名称

        if tag_zh is None:
            self._tag_zh = name
        else:
            self._tag_zh = tag_zh  # 参数的前端显示名称(前端显示用,例如如果name为"path",则name_tag为"路径")

        if desc_zh is None:
            self._desc_zh = name
        else:
            self._desc_zh = desc_zh  # 参数提示信息,详细描述参数作用

        if tag_en is None:
            self._tag_en = name
        else:
            self._tag_en = tag_en  # 参数的前端显示名称(前端显示用,例如如果name为"path",则name_tag为"路径")

        if desc_en is None:
            self._desc_en = name
        else:
            self._desc_en = desc_en  # 参数提示信息,详细描述参数作用

        self._type = type  # 参数类型,参考option_type_list
        self._required = required  # 是否必填
        self._default = default  # 参数默认值
        self._enum_list = enum_list  # enum类型的待选列表,如果type为enum类型则此参数必须填写
        self._length = length  # 参数在前端需要的UI长度 1表示24表示最长
        self._extra_data = extra_data  # 参数需要传递的额外信息

    def to_dict(self):
        """将参数对象转化为json格式数据"""
        _dict = {
            'name': self._name,
            'tag_zh': self._tag_zh,
            'desc_zh': self._desc_zh,
            'tag_en': self._tag_en,
            'desc_en': self._desc_en,
            'type': self._type,
            'required': self._required,
            'default': self._default,
            'extra_data': self._extra_data,
        }

        # 处理option_length参数的兼容性
        if self._length is None:
            _dict['length'] = option_type_default_length.get(self._type)
        else:
            _dict['length'] = self._length

        # 处理enum_list参数的兼容性,请注意,此处无法处理handler和凭证等动态参数
        tmp_enmu_list = []
        for one_enmu in self._enum_list:
            if isinstance(one_enmu, str) or isinstance(one_enmu, bytes):
                tmp_enmu_list.append({'name': one_enmu, 'value': one_enmu})
            else:
                if one_enmu.get('tag_zh') is not None and one_enmu.get('value') is not None:
                    tmp_enmu_list.append(one_enmu)
                else:
                    logger.warning(f"参数错误, name: {self._name} tag_zh:{self._tag_zh}")
        _dict['enum_list'] = tmp_enmu_list
        return _dict


class OptionStr(_Option):
    """字符串类型参数"""

    def __init__(self, name,
                 tag_zh=None, desc_zh=None,
                 tag_en=None, desc_en=None,
                 required=False, default=None,
                 length=None):
        super().__init__(type='str', name=name, tag_zh=tag_zh, desc_zh=desc_zh, tag_en=tag_en, desc_en=desc_en,
                         required=required, default=default,
                         length=length)


class OptionText(_Option):
    """text类型参数"""

    def __init__(self, name,
                 tag_zh=None, desc_zh=None,
                 tag_en=None, desc_en=None,
                 required=False, default=None,
                 length=24):
        super().__init__(type='text',
                         name=name, tag_zh=tag_zh, desc_zh=desc_zh, tag_en=tag_en, desc_en=desc_en, required=required,
                         default=default,
                         length=length)


class OptionInt(_Option):
    """数字类型参数"""

    def __init__(self, name,
                 tag_zh=None, desc_zh=None,
                 tag_en=None, desc_en=None,
                 required=False, default=None,
                 min=None, max=None,
                 length=6):
        super().__init__(type='integer', name=name, tag_zh=tag_zh, desc_zh=desc_zh, tag_en=tag_en, desc_en=desc_en,
                         required=required,
                         default=default,
                         extra_data={
                             "min": min,
                             "max": max
                         },
                         length=length)


class OptionBool(_Option):
    """布尔类型参数"""

    def __init__(self, name,
                 tag_zh=None, desc_zh=None,
                 tag_en=None, desc_en=None,
                 required=False, default=False,
                 length=4):
        super().__init__(type='bool', name=name, tag_zh=tag_zh, desc_zh=desc_zh, tag_en=tag_en, desc_en=desc_en,
                         required=required,
                         default=default,
                         length=length)


class OptionEnum(_Option):
    """枚举类型参数
    enum_list参数样例:
    enum_list = [
        {'tag_zh': "劫持",'tag_en': "Hijack", 'value': "Hijack"},
        {'tag_zh': "恢复",'tag_en': "Recovery", 'value': "Recovery"},
    ]
    """

    def __init__(self, name=None,
                 tag_zh=None, desc_zh=None,
                 tag_en=None, desc_en=None,
                 required=False, default=None, length=6,
                 enum_list=None):
        if enum_list is None:
            enum_list = []
        super().__init__(type='enum', name=name, tag_zh=tag_zh, tag_en=tag_en, desc_en=desc_en, required=required,
                         desc_zh=desc_zh,
                         default=default,
                         enum_list=enum_list,
                         length=length, extra_data=None)
        self.is_valid()

    def is_valid(self):
        for oneEnum in self._enum_list:
            if oneEnum.get("tag_zh") is None or oneEnum.get("tag_en") is None:
                logger.exception(f"参数 {self._name} 格式不符合要求,正确格式应为字典,其中包含tag_zh,tag_en及value字段")


class OptionIPAddressRange(_Option):
    """IP地址范围类型参数"""

    def __init__(self, name,
                 tag_zh=None, desc_zh=None,
                 tag_en=None, desc_en=None,
                 required=False, default=None):
        super().__init__(type='address_range', name=name, tag_zh=tag_zh, desc_zh=desc_zh, tag_en=tag_en,
                         desc_en=desc_en, required=required,
                         default=default)


class OptionFileEnum(_Option):
    """文件类型参数
    返回<文件列表>中的用户选择的文件
    """

    def __init__(self, required=True, ext=None):
        super().__init__(type='enum',
                         name=FILE_OPTION.get('name'),
                         tag_zh=FILE_OPTION.get('tag_zh'),
                         desc_zh=FILE_OPTION.get('desc_zh'),
                         tag_en=FILE_OPTION.get('tag_en'),
                         desc_en=FILE_OPTION.get('desc_en'),
                         length=FILE_OPTION.get('option_length'),
                         required=required,
                         extra_data={'file_extension': ext}
                         )


class OptionCredentialEnum(_Option):
    """凭据类型参数
    展示<凭据列表>中的所有凭据,返回用户选择的凭据
    """

    def __init__(self, required=True, password_type=None):
        if password_type is None:
            password_type = []
        super().__init__(type='enum',
                         name=CREDENTIAL_OPTION.get('name'),
                         tag_zh=CREDENTIAL_OPTION.get('tag_zh'),
                         desc_zh=CREDENTIAL_OPTION.get('desc_zh'),
                         tag_en=CREDENTIAL_OPTION.get('tag_en'),
                         desc_en=CREDENTIAL_OPTION.get('desc_en'),
                         length=CREDENTIAL_OPTION.get('option_length'),
                         required=required,
                         extra_data={'password_type': password_type}
                         )


class OptionHander(_Option):
    """监听配置参数"""

    def __init__(self, required=True):
        super().__init__(type='enum',
                         name=HANDLER_OPTION.get('name'),
                         tag_zh=HANDLER_OPTION.get('tag_zh'),
                         desc_zh=HANDLER_OPTION.get('desc_zh'),
                         tag_en=HANDLER_OPTION.get('tag_en'),
                         desc_en=HANDLER_OPTION.get('desc_en'),
                         length=HANDLER_OPTION.get('option_length'),
                         required=required,
                         )


class OptionCacheHanderConfig(_Option):
    """是否选择新建缓存监听"""

    def __init__(self):
        super().__init__(type='bool',
                         name=CACHE_HANDLER_OPTION.get('name'),
                         tag_zh=CACHE_HANDLER_OPTION.get('tag_zh'),
                         desc_zh=CACHE_HANDLER_OPTION.get('desc_zh'),
                         tag_en=CACHE_HANDLER_OPTION.get('tag_en'),
                         desc_en=CACHE_HANDLER_OPTION.get('desc_en'),
                         length=CACHE_HANDLER_OPTION.get('option_length'),
                         required=CACHE_HANDLER_OPTION.get('required'),
                         default=CACHE_HANDLER_OPTION.get('default'),
                         )
