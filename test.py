# 启动django项目
# import os
#
# os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Viper.settings")
# import django
#
# django.setup()

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

# import datetime
#
# today = datetime.date.today()
# print("Today's date:", today)
#
# year_ago = today.replace(year=today.year - 1)
# print("Date a year ago:", year_ago)
# url = "http://honey.scanme.sh"
# # url = "https://did-sso.bba-app.biz"
# result = WafCheck.check_url(url)
# print(result)


import json
import re

import requests


class CompanyBaseInfo(object):
    def __init__(self):
        self.pid = None
        # self.entName = None
        self.entType = None
        self.validityFrom = None
        # self.'domicile' = None
        self.openStatus = None  # "注销" "吊销"
        self.legalPerson = None
        self.logoWord = None
        self.titleName = None
        self.titleDomicile = None
        self.regCap = None
        self.regNo = None
        self.email = None
        self.website = None
        self.scope = None
        self.telephone = None
        self.webRecordTotal = None

        self.icp = []
        self.app = []
        self.wechat = []


class CompanyICP(object):
    def __init__(self):
        self.domain = []
        self.homeSite = []
        self.icpNo = None
        self.siteName = None


class CompanyAPP(object):
    def __init__(self):
        self.name = None
        self.classify = None
        self.logo = None
        self.logoBrief = None


class CompanyWechat(object):
    def __init__(self):
        self.principalName = None
        self.wechatId = None
        self.wechatName = None
        self.wechatIntruduction = None
        self.wechatLogo = None
        self.qrcode = None


class AiqichaAPI(object):
    def __init__(self, cookie):
        self.cookie = cookie
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36 Edg/98.0.1108.43',
            'Accept': "text/html, application/xhtml+xml, image/jxr, */*",
            "Cookie": cookie,
            "Referer": 'https://aiqicha.baidu.com/'
        }

    def get_en_info_by_pid(self, company_base_info):
        url = f"https://aiqicha.baidu.com/compdata/navigationListAjax?pid={company_base_info.pid}"
        response = requests.get(url, headers=self.headers)
        try:
            response_json = response.json()
        except Exception as E:
            raise Exception(f"Aiqicha {url} error")
        if response_json.get("status") != 0:
            return None
        data = response_json.get("data")
        for x in data:
            # 获取备案信息
            if x.get("id") == 'certRecord':
                children = x.get("children")
                for y in children:
                    if y.get("id") == "webRecord":
                        company_base_info.webRecordTotal = y.get("total")

    def get_muitpage_data(self, url):
        response = requests.get(url, headers=self.headers)
        try:
            response_json = response.json()
        except Exception as E:
            raise Exception(f"Aiqicha {url} error")
        if response_json.get("status") != 0:
            raise Exception(f"Aiqicha {url} status error")
        data = response_json.get("data")
        pageCount = data.get('pageCount')
        if pageCount == 1:
            return data.get("list")
        else:
            result_list: list = data.get("list")
            for i in range(2, pageCount + 1):
                page_url = f"{url}&p={i}"
                response = requests.get(page_url, headers=self.headers)
                try:
                    response_json = response.json()
                except Exception as E:
                    break
                if response_json.get("status") != 0:
                    break
                result_list.extend(response_json.get("data").get("list"))
            return result_list

    def get_icp_by_pid(self, company_base_info):
        api = "detail/icpinfoAjax"
        url = f"https://aiqicha.baidu.com/{api}?pid={company_base_info.pid}"
        result_list = self.get_muitpage_data(url)
        if result_list is None:
            return
        icp_list = []
        for one in result_list:
            company_icp = CompanyICP()
            company_icp.domain = one.get("domain")
            company_icp.homeSite = one.get("homeSite")
            company_icp.icpNo = one.get("icpNo")
            company_icp.siteName = one.get("siteName")
            icp_list.append(company_icp)
        company_base_info.icp = icp_list

    def get_app_by_pid(self, company_base_info):
        api = "c/appinfoAjax"
        url = f"https://aiqicha.baidu.com/{api}?pid={company_base_info.pid}"
        result_list = self.get_muitpage_data(url)
        app_list = []
        for one in result_list:
            company_app = CompanyAPP()
            company_app.name = one.get("name")
            company_app.classify = one.get("classify")
            company_app.logo = one.get("logo")
            company_app.logoBrief = one.get("logoBrief")
            app_list.append(company_app)
        company_base_info.app = app_list

    def get_wechat_by_pid(self, company_base_info):
        api = "c/wechatoaAjax"
        url = f"https://aiqicha.baidu.com/{api}?pid={company_base_info.pid}"
        result_list = self.get_muitpage_data(url)
        wechat_list = []
        for one in result_list:
            company_wechat = CompanyWechat()
            company_wechat.principalName = one.get("principalName")
            company_wechat.wechatId = one.get("wechatId")
            company_wechat.wechatName = one.get("wechatName")
            company_wechat.wechatIntruduction = one.get("wechatIntruduction")
            company_wechat.wechatLogo = one.get("wechatLogo")
            company_wechat.qrcode = one.get("qrcode")
            wechat_list.append(company_wechat)
        company_base_info.wechat = wechat_list

    def search_by_name(self, company_name):
        company_base_info_list = []
        url = f"https://aiqicha.baidu.com/s?q={company_name}&t=0"
        response = requests.get(url, headers=self.headers)
        pattern = re.compile(r'window\.pageData = (.*});')
        match = pattern.search(response.text)
        if match:
            data = match.group(1)
            data = data.replace("\n", "")
            data = data.replace(" ", "")
            try:
                data = json.loads(data)
                resultList = data.get("result").get("resultList")
            except Exception as E:
                raise Exception("Aiqicha Cookie expire")
            for one_result in resultList:
                company_base_info = CompanyBaseInfo()
                company_base_info.pid = one_result.get("pid")
                company_base_info.entType = one_result.get("entType")
                company_base_info.validityFrom = one_result.get("validityFrom")
                company_base_info.legalPerson = one_result.get("legalPerson")
                company_base_info.openStatus = one_result.get("openStatus")
                company_base_info.logoWord = one_result.get("logoWord")
                company_base_info.titleName = one_result.get("titleName")
                company_base_info.titleDomicile = one_result.get("titleDomicile")
                company_base_info.regCap = one_result.get("regCap")
                company_base_info.regNo = one_result.get("regNo")
                company_base_info.email = one_result.get("email")
                company_base_info.website = one_result.get("website")
                company_base_info.scope = one_result.get("scope")
                company_base_info.telephone = one_result.get("telephone")
                self.get_icp_by_pid(company_base_info)
                self.get_app_by_pid(company_base_info)
                self.get_wechat_by_pid(company_base_info)
                company_base_info_list.append(company_base_info)
                print(f"finish {company_base_info.titleName} {company_base_info.pid}")
            return company_base_info_list
        else:
            raise Exception("Aiqicha Cookie expire")

    def is_alive(self):
        url = f"https://aiqicha.baidu.com/usercenter/getvipinfoAjax"
        response = requests.get(url, headers=self.headers)

        try:
            data = response.json()
            if data.get("status") == 0:
                return True
            else:
                return False
        except Exception as E:
            logger.exception(E)
            return False


if __name__ == '__main__':
    aiqicha_api = AiqichaAPI(cookie)
    aiqicha_api.is_alive()
    # result = aiqicha_api.search_by_name("华晨宝马汽车有限公司")
    # result = aiqicha_api.search_by_name("宝马（中国）汽车贸易有限公司")
