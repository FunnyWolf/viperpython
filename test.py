# 启动django项目
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Viper.settings")
import django

django.setup()
from Lib.xcache import Xcache

print(Xcache.list_web_module_result())
