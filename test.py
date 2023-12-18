# 启动django项目
import os
import time

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Viper.settings")
import django

django.setup()
from WebDatabase.Handle.ipdomain import IPDomain

timenow = int(time.time())

IPDomain.list_simple(project_id='92b5b5e8989f11ee')
print(int(time.time()) - timenow)
