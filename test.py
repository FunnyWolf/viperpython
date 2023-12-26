# 启动django项目
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Viper.settings")
import django

django.setup()
# import time
# from WebDatabase.Handle.ipdomain import IPDomain
#
# timenow = int(time.time())
#
# IPDomain.list_simple(project_id='92b5b5e8989f11ee')
# print(int(time.time()) - timenow)


# from External.nucleiapi import NucleiAPI
#
# targets = ["http://8.217.7.168:7001"]
# n = NucleiAPI()
# result = n.check(targets=targets)
# print(result)

import datetime

today = datetime.date.today()
print("Today's date:", today)

year_ago = today.replace(year=today.year - 1)
print("Date a year ago:", year_ago)
