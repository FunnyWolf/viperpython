# -*- coding: utf-8 -*-
# @File  : setup.py
# @Date  : 2019/11/13
# @Desc  :

from distutils.core import setup

from Cython.Build import cythonize

setup(ext_modules=cythonize(["core.py"], compiler_directives={'always_allow_keywords': True}))
