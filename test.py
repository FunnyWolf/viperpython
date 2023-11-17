# 启动django项目
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Viper.settings")
import django

django.setup()
