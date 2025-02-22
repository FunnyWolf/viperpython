from Lib.api import parse_url_simple
from WebDatabase.documents import IPDomainDocument, PortDocument, DNSRecordDocument, CDNDocument, CertDocument, CompanyAPPDocument, CompanyICPDocument, \
    CompanyWechatDocument, ComponentDocument, HttpBaseDocument, HttpFaviconDocument, LocationDocument, ScreenshotDocument, ServiceDocument, \
    VulnerabilityDocument, WAFDocument, ClueCompanyDocument


class DataSet(object):
    """数据接口类,用于存储各个api查询到的数据,各个api传递该类的对象"""

    def __init__(self):

        self.project_id = None

        self.companyBaseInfoList: list = []
        self.companyAPPList: list = []
        self.companyWechatList: list = []
        self.companyICPList: list = []

        self.ipdomainList: list = []
        self.dnsrecordList: list = []
        self.cdnList: list = []
        self.certList: list = []
        self.componentList: list = []
        self.httpbaseList: list = []
        self.httpfaviconList: list = []
        self.locationList: list = []
        self.portList: list = []
        self.screenshotList: list = []
        self.serviceList: list = []
        self.vulnerabilityList: list = []
        self.wafList: list = []

    def set_project_id(self, project_id: str):
        self.project_id = project_id

    def _company_base_info_list_to_db(self):
        if self.companyBaseInfoList:
            for clue_company in self.companyBaseInfoList:
                clue_company: ClueCompanyDocument
                clue_company.project_id = self.project_id
                clue_company.update_or_create()

    def _company_icp_to_db(self):
        if self.companyICPList:
            for companyICP in self.companyICPList:
                companyICP: CompanyICPDocument
                companyICP.project_id = self.project_id
                companyICP.update_or_create()

    def _company_app_to_db(self):
        if self.companyAPPList:
            for companyAPP in self.companyAPPList:
                companyAPP: CompanyAPPDocument
                companyAPP.project_id = self.project_id
                companyAPP.update_or_create()

    def _company_wechat_to_db(self):
        if self.companyWechatList:
            for companyWechat in self.companyWechatList:
                companyWechat: CompanyWechatDocument
                companyWechat.project_id = self.project_id
                companyWechat.update_or_create()

    def _ipdomain_to_db(self):
        if self.ipdomainList:
            for ipdomain_object in self.ipdomainList:
                ipdomain_object: IPDomainDocument
                ipdomain_object.project_id = self.project_id
                ipdomain_object.update_or_create()

    def _dnsrecord_to_db(self):
        if self.dnsrecordList:
            for dnsrecord in self.dnsrecordList:
                dnsrecord: DNSRecordDocument
                dnsrecord.update_or_create()

    def _cdn_to_db(self):
        if self.cdnList:
            for cdn in self.cdnList:
                cdn: CDNDocument
                cdn.update_or_create()

    def _cert_to_db(self):
        if self.certList:
            for cert in self.certList:
                cert: CertDocument
                cert.update_or_create()

    def _component_to_db(self):
        if self.componentList:
            for component in self.componentList:
                component: ComponentDocument
                component.update_or_create()

    def _httpbase_to_db(self):
        if self.httpbaseList:
            for httpbase in self.httpbaseList:
                httpbase: HttpBaseDocument
                httpbase.update_or_create()

    def _httpfavicon_to_db(self):
        if self.httpfaviconList:
            for httpfavicon in self.httpfaviconList:
                httpfavicon: HttpFaviconDocument
                httpfavicon.update_or_create()

    def _location_to_db(self):
        if self.locationList:
            for location in self.locationList:
                location: LocationDocument
                location.update_or_create()

    def _port_to_db(self):
        if self.portList:
            for port in self.portList:
                port: PortDocument
                port.update_or_create()

    def _screenshot_to_db(self):
        if self.screenshotList:
            for screenshot in self.screenshotList:
                screenshot: ScreenshotDocument
                screenshot.update_or_create()

    def _service_to_db(self):
        if self.serviceList:
            for service in self.serviceList:
                service: ServiceDocument
                service.update_or_create()

    def _vulnerability_to_db(self):
        if self.vulnerabilityList:
            for vulnerability in self.vulnerabilityList:
                vulnerability: VulnerabilityDocument
                vulnerability.update_or_create()

    def _waf_to_db(self):
        if self.wafList:
            for waf in self.wafList:
                waf: WAFDocument
                waf.update_or_create()

    def get_urls(self):
        targets = []
        for service_obj in self.serviceList:
            service_obj: ServiceDocument
            url = service_obj.group_url()
            if url is None:
                continue
            targets.append(url)
        return targets

    def add_by_urls(self, urls):
        for url in urls:
            scheme, hostname, port = parse_url_simple(url)

            ipdomain_object = IPDomainDocument()
            ipdomain_object.ipdomain = hostname
            ipdomain_object.port = port
            ipdomain_object.source = "Manual"
            self.ipdomainList.append(ipdomain_object)

            port_obj = PortDocument()
            port_obj.ipdomain = hostname
            port_obj.port = port
            port_obj.source = "Manual"
            self.portList.append(port_obj)

            service_obj = ServiceDocument()
            service_obj.ipdomain = hostname
            service_obj.port = port
            service_obj.source = "Manual"
            service_obj.service = scheme
            self.serviceList.append(service_obj)

    def save_to_db(self):
        self._company_base_info_list_to_db()
        self._company_icp_to_db()
        self._company_app_to_db()
        self._company_wechat_to_db()

        self._ipdomain_to_db()
        self._port_to_db()
        self._dnsrecord_to_db()
        self._cert_to_db()
        self._component_to_db()
        self._httpbase_to_db()
        self._httpfavicon_to_db()
        self._location_to_db()
        self._screenshot_to_db()
        self._service_to_db()

        self._waf_to_db()
        self._cdn_to_db()
        self._vulnerability_to_db()
