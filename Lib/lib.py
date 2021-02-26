# -*- coding: utf-8 -*-
# @File  : lib.py
# @Date  : 2019/1/11
# @Desc  :

import os

from django.conf import settings

# 临时目录
TMP_DIR = os.path.join(settings.BASE_DIR, 'STATICFILES', 'TMP')
