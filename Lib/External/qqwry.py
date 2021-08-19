import os

from django.conf import settings
from qqwry import QQwry


class QQwryIP(object):
    def __init__(self):
        qqwry_path = os.path.join(settings.BASE_DIR, 'STATICFILES', 'STATIC', 'qqwrt.dat')
        self.qqwry = QQwry()
        self.qqwry.load_file(qqwry_path)

    def get_location(self, ipaddress):
        result = self.qqwry.lookup(ipaddress)
        if result:
            return f"{result[0]} {result[1]}"
        else:
            return ""


qqwry = QQwryIP()
