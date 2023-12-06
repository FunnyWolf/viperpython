# 启动django项目
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Viper.settings")
import django

django.setup()
from Lib.xcache import Xcache

result = Xcache.list_web_module_result()
print(result)
