from elasticsearch import NotFoundError
from elasticsearch_dsl import Document, Text, Keyword, Boolean, Integer, Object

from Lib.api import get_one_uuid_str


class ProjectMetaDocument(Document):
    project_id = Keyword()


class CompanyMetaDocument(Document):
    company_name = Keyword()


class WebMetaDocument(Document):
    source = Keyword()
    data = Object()
    update_time = Integer()


class ClueMetaDocument(Document):
    exact = Boolean()
    note = Keyword()


class IPDomainMetaDocument(Document):
    ipdomain = Keyword()


class PortMetaDocument(Document):
    port = Integer()


class ProjectDocument(ProjectMetaDocument):
    name = Text()
    desc = Text()

    class Index:
        name = 'project'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return self.project_id

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(ProjectDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        if self.project_id is None:
            self.project_id = get_one_uuid_str()
        self.save(refresh=refresh)
        return self.to_dict()


class DNSRecordDocument(IPDomainMetaDocument, WebMetaDocument):
    type = Keyword()
    value = Keyword(multi=True)

    class Index:
        name = 'dns_record'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.ipdomain}:{self.type}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(DNSRecordDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        if self.value is None or self.value == "":
            self.value = []

        self.save(refresh=refresh)
        return self.to_dict()


class IPDomainDocument(IPDomainMetaDocument, ProjectMetaDocument, CompanyMetaDocument, WebMetaDocument):
    class Index:
        name = 'ipdomain'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return self.ipdomain

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        # try:
        #     doc_old = self.get(self.id)
        #     self.company_name = doc_old.company_name
        # except NotFoundError:
        #     pass
        return super(IPDomainDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        try:
            if self.id:
                doc_old = self.get(id=self.id)
            else:
                return None
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.company_name is None:
                self.company_name = doc_old.company_name
            self.save(refresh=refresh)
        return self.to_dict()

    def get_dict(self):
        try:
            doc_old = self.get(id=self.id)
            return doc_old.to_dict()
        except NotFoundError:
            return None

    def get_doc(self):
        try:
            doc_old = self.get(id=self.id)
            return doc_old
        except NotFoundError:
            return None


class LocationDocument(IPDomainMetaDocument, WebMetaDocument):
    isp = Keyword()
    asname = Keyword()
    scene_cn = Keyword()
    scene_en = Keyword()
    country_cn = Keyword()
    country_en = Keyword()
    province_cn = Keyword()
    province_en = Keyword()
    city_cn = Keyword()
    city_en = Keyword()

    class Index:
        name = 'location'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return self.ipdomain

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(LocationDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.isp is None:
                self.isp = doc_old.isp
            if self.asname is None:
                self.asname = doc_old.asname
            if self.scene_cn is None:
                self.scene_cn = doc_old.scene_cn
            if self.scene_en is None:
                self.scene_en = doc_old.scene_en
            if self.country_cn is None:
                self.country_cn = doc_old.country_cn
            if self.country_en is None:
                self.country_en = doc_old.country_en
            if self.province_cn is None:
                self.province_cn = doc_old.province_cn
            if self.province_en is None:
                self.province_en = doc_old.province_en
            if self.city_cn is None:
                self.city_cn = doc_old.city_cn
            if self.city_en is None:
                self.city_en = doc_old.city_en
            self.save(refresh=refresh)
        return self.to_dict()

    def get_dict(self):
        try:
            doc_old = self.get(id=self.id)
            return doc_old.to_dict()
        except NotFoundError:
            return None


class PortDocument(IPDomainMetaDocument, PortMetaDocument, WebMetaDocument):
    alive = Boolean()
    color = Keyword()
    comment = Text()

    class Index:
        name = 'port'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.ipdomain}:{self.port}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(PortDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.color is None:
                self.color = doc_old.color
            if self.comment is None:
                self.comment = doc_old.comment
            self.save(refresh=refresh)
        return self.to_dict()

    def get_dict(self):
        try:
            doc_old = self.get(id=self.id)
            return doc_old.to_dict()
        except NotFoundError:
            return None


class ServiceDocument(IPDomainMetaDocument, PortMetaDocument, WebMetaDocument):
    transport = Keyword()
    service = Keyword()
    version = Keyword()
    response = Text()
    response_hash = Keyword()

    class Index:
        name = 'service'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.ipdomain}:{self.port}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(ServiceDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.transport is None:
                self.transport = doc_old.transport
            if self.service is None:
                self.service = doc_old.service
            if self.version is None:
                self.version = doc_old.version
            if self.response is None:
                self.response = doc_old.response
            if self.response_hash is None:
                self.response_hash = doc_old.response_hash

            self.save(refresh=refresh)
        return self.to_dict()

    def group_url(self):
        if self.service.lower() in ["http", "https"]:
            return f"{self.service}://{self.ipdomain}:{self.port}"
        else:
            return None

    def get_dict(self):
        try:
            doc_old = self.get(id=self.id)
            return doc_old.to_dict()
        except NotFoundError:
            return None


class ComponentDocument(IPDomainMetaDocument, PortMetaDocument, WebMetaDocument):
    product_name = Keyword()
    product_version = Keyword()
    product_extrainfo = Keyword()
    # product_type = Object()
    # product_catalog = Object()
    product_type = Keyword(multi=True)
    product_catalog = Keyword(multi=True)
    ipdomain_port = Keyword()

    class Index:
        name = 'component'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.ipdomain}:{self.port}:{self.product_name}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(ComponentDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        self.ipdomain_port = f"{self.ipdomain}:{self.port}"
        if self.product_catalog is None or self.product_catalog == "":
            self.product_catalog = []
        if self.product_type is None or self.product_type == "":
            self.product_type = []

        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.product_name is None or self.product_name == "":
                # self.product_name = doc_old.product_name
                return None
            if self.product_version is None:
                self.product_version = doc_old.product_version
            if self.product_extrainfo is None:
                self.product_extrainfo = doc_old.product_extrainfo
            if not self.product_type:
                self.product_type = doc_old.product_type
            if not self.product_catalog:
                self.product_catalog = doc_old.product_catalog

            self.save(refresh=refresh)
        return self.to_dict()


class CertDocument(IPDomainMetaDocument, PortMetaDocument, WebMetaDocument):
    fingerprint_md5 = Keyword()
    cert = Text()
    jarm = Keyword()
    subject = Object()
    subject_dn = Keyword()
    dns_names = Keyword(multi=True)

    class Index:
        name = 'cert'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.ipdomain}:{self.port}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(CertDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        if self.subject is None:
            self.subject = {}

        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.cert is None:
                self.cert = doc_old.cert
            if self.jarm is None:
                self.jarm = doc_old.jarm
            if not self.subject:
                self.subject = doc_old.subject
            self.save(refresh=refresh)
        return self.to_dict()

    def get_dict(self):
        try:
            doc_old = self.get(id=self.id)
            return doc_old.to_dict()
        except NotFoundError:
            return None


class ScreenshotDocument(IPDomainMetaDocument, PortMetaDocument, WebMetaDocument):
    content = Text()

    class Index:
        name = 'screenshot'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.ipdomain}:{self.port}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(ScreenshotDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        if self.subject is None or self.subject == "":
            self.subject = []

        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.content is None:
                self.content = doc_old.content
            self.save(refresh=refresh)
        return self.to_dict()

    def get_dict(self):
        try:
            doc_old = self.get(id=self.id)
            return doc_old.to_dict()
        except NotFoundError:
            return None


class HttpBaseDocument(IPDomainMetaDocument, PortMetaDocument, WebMetaDocument):
    title = Keyword()
    status_code = Integer()
    header = Text()
    body = Text()

    class Index:
        name = 'http_base'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.ipdomain}:{self.port}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(HttpBaseDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.title is None:
                self.title = doc_old.title
            if self.status_code == 0:
                self.status_code = doc_old.status_code
            if self.header is None:
                self.header = doc_old.header
            if self.body is None:
                self.body = doc_old.body
            self.save(refresh=refresh)
        return self.to_dict()

    def get_dict(self):
        try:
            doc_old = self.get(id=self.id)
            return doc_old.to_dict()
        except NotFoundError:
            return None


class HttpFaviconDocument(IPDomainMetaDocument, PortMetaDocument, WebMetaDocument):
    hash = Keyword()
    content = Text()

    class Index:
        name = 'http_favicon'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.ipdomain}:{self.port}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(HttpFaviconDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.hash is None:
                self.hash = doc_old.hash
            if self.content is None:
                self.content = doc_old.content
            self.save(refresh=refresh)
        return self.to_dict()

    def get_dict(self):
        try:
            doc_old = self.get(id=self.id)
            return doc_old.to_dict()
        except NotFoundError:
            return None


class CDNDocument(IPDomainMetaDocument, WebMetaDocument):
    flag = Boolean()
    domain = Keyword()
    name = Keyword()
    link = Keyword()

    class Index:
        name = 'cdn'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.ipdomain}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(CDNDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.domain is None:
                self.domain = doc_old.domain
            if self.name is None:
                self.name = doc_old.name
            if self.link is None:
                self.link = doc_old.link
            self.save(refresh=refresh)
        return self.to_dict()

    def get_dict(self):
        doc = CDNDocument()
        try:
            doc_old = doc.get(id=self.id)
            return doc_old.to_dict()
        except NotFoundError:
            return None


class WAFDocument(IPDomainMetaDocument, PortMetaDocument, WebMetaDocument):
    flag = Boolean()
    trigger_url = Text()
    name = Keyword()
    manufacturer = Keyword()

    class Index:
        name = 'waf'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.ipdomain}:{self.port}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(WAFDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.trigger_url is None:
                self.trigger_url = doc_old.trigger_url
            if self.name is None:
                self.name = doc_old.name
            if self.manufacturer is None:
                self.manufacturer = doc_old.manufacturer
            self.save(refresh=refresh)
        return self.to_dict()

    def get_dict(self):
        doc = WAFDocument()
        try:
            doc_old = doc.get(id=self.id)
            return doc_old.to_dict()
        except NotFoundError:
            return None


class VulnerabilityDocument(IPDomainMetaDocument, PortMetaDocument, WebMetaDocument):
    name = Text()
    description = Text()
    severity = Keyword()
    template_id = Text()
    matched_at = Text()
    reference = Keyword(multi=True)
    request = Text()
    response = Text()

    ipdomain_port = Keyword()

    class Index:
        name = 'vulnerability'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.ipdomain}:{self.port}:{self.name}:{self.key}:{self.tool}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(VulnerabilityDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        self.ipdomain_port = f"{self.ipdomain}:{self.port}"
        if self.reference is None or self.reference == "":
            self.reference = []
        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.name is None:
                self.name = doc_old.name
            if self.description is None:
                self.description = doc_old.description
            if self.severity is None:
                self.severity = doc_old.severity

            if self.template_id is None:
                self.template_id = doc_old.template_id

            if self.matched_at is None:
                self.matched_at = doc_old.matched_at

            if not self.reference:
                self.reference = doc_old.reference
            if self.request is None:
                self.request = doc_old.request
            if self.response is None:
                self.response = doc_old.response
            self.save(refresh=refresh)
        return self.to_dict()


class CompanyICPDocument(ProjectMetaDocument, CompanyMetaDocument, WebMetaDocument):
    pid = Keyword()
    domain = Keyword()
    homeSite = Keyword()
    icpNo = Keyword()
    siteName = Keyword()

    class Index:
        name = 'company_icp'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.company_name}:{self.domain}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(CompanyICPDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.pid is None:
                self.pid = doc_old.pid
            if self.domain is None:
                self.domain = doc_old.domain
            if self.homeSite is None:
                self.homeSite = doc_old.homeSite
            if self.icpNo is None:
                self.icpNo = doc_old.icpNo
            if self.siteName is None:
                self.siteName = doc_old.siteName
            self.save(refresh=refresh)
        return self.to_dict()


class CompanyAPPDocument(ProjectMetaDocument, CompanyMetaDocument, WebMetaDocument):
    pid = Keyword()
    name = Keyword()
    classify = Keyword()
    logo = Keyword()
    logoBrief = Keyword()

    class Index:
        name = 'company_app'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.company_name}:{self.name}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(CompanyAPPDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.pid is None:
                self.pid = doc_old.pid
            if self.name is None:
                self.name = doc_old.name
            if self.classify is None:
                self.classify = doc_old.classify
            if self.logo is None:
                self.logo = doc_old.logo
            if self.logoBrief is None:
                self.logoBrief = doc_old.logoBrief
            self.save(refresh=refresh)
        return self.to_dict()


class CompanyWechatDocument(ProjectMetaDocument, CompanyMetaDocument, WebMetaDocument):
    pid = Keyword()
    principalName = Keyword()
    wechatId = Keyword()
    wechatName = Keyword()
    wechatIntruduction = Text()
    wechatLogo = Keyword()
    qrcode = Keyword()

    class Index:
        name = 'company_wechat'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.company_name}:{self.wechatId}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(CompanyWechatDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):

        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.pid is None:
                self.pid = doc_old.pid
            if self.principalName is None:
                self.principalName = doc_old.principalName
            if self.wechatId is None:
                self.wechatId = doc_old.wechatId
            if self.wechatName is None:
                self.wechatName = doc_old.wechatName
            if self.wechatIntruduction is None:
                self.wechatIntruduction = doc_old.wechatIntruduction
            if self.wechatLogo is None:
                self.wechatLogo = doc_old.wechatLogo
            if self.qrcode is None:
                self.qrcode = doc_old.qrcode
            self.save(refresh=refresh)
        return self.to_dict()


class ClueCompanyDocument(ProjectMetaDocument, ClueMetaDocument, WebMetaDocument):
    pid = Keyword()
    entType = Keyword()
    validityFrom = Keyword()
    openStatus = Keyword()
    legalPerson = Keyword()
    logoWord = Keyword()
    company_name = Keyword()
    titleDomicile = Text()
    regCap = Keyword()
    regNo = Keyword()
    email = Keyword()
    website = Keyword()
    scope = Text()
    telephone = Keyword()

    class Index:
        name = 'clue_company'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.company_name}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(ClueCompanyDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.pid is None:
                self.pid = doc_old.pid
            if self.entType is None:
                self.entType = doc_old.entType
            if self.validityFrom is None:
                self.validityFrom = doc_old.validityFrom
            if self.openStatus is None:
                self.openStatus = doc_old.openStatus
            if self.legalPerson is None:
                self.legalPerson = doc_old.legalPerson
            if self.logoWord is None:
                self.logoWord = doc_old.logoWord
            if self.company_name is None:
                self.company_name = doc_old.company_name
            if self.titleDomicile is None:
                self.titleDomicile = doc_old.titleDomicile
            if self.regCap is None:
                self.regCap = doc_old.regCap
            if self.regNo is None:
                self.regNo = doc_old.regNo
            if self.email is None:
                self.email = doc_old.email
            if self.website is None:
                self.website = doc_old.website
            if self.scope is None:
                self.scope = doc_old.scope
            if self.telephone is None:
                self.telephone = doc_old.telephone

            self.save(refresh=refresh)
        return self.to_dict()


class ClueFaviconDocument(ProjectMetaDocument, ClueMetaDocument, WebMetaDocument):
    hash = Keyword()
    content = Text()

    class Index:
        name = 'clue_favicon'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.hash}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(ClueFaviconDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.content is None:
                self.content = doc_old.content
            self.save(refresh=refresh)
        return self.to_dict()


class ClueCertDocument(ProjectMetaDocument, ClueMetaDocument, WebMetaDocument):
    fingerprint_md5 = Keyword()
    cert = Text()
    jarm = Keyword()
    subject = Object()
    subject_dn = Keyword()
    dns_names = Keyword(multi=True)

    class Index:
        name = 'clue_cert'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }

    @property
    def id(self):
        return f"{self.fingerprint_md5}"

    def save(self, **kwargs):
        """ 保存文档前生成并设置自定义ID """
        self.meta.id = self.id
        return super(ClueCertDocument, self).save(**kwargs)

    def update_or_create(self, refresh=False):
        if self.subject is None or self.subject == "":
            self.subject = []

        try:
            doc_old = self.get(id=self.id)
        except NotFoundError:
            self.save(refresh=refresh)
        else:
            if self.cert is None:
                self.cert = doc_old.cert
            if self.jarm is None:
                self.jarm = doc_old.jarm
            if self.subject_dn is None:
                self.subject_dn = doc_old.subject_dn
            if not self.subject:
                self.subject = doc_old.subject
            if not self.dns_names:
                self.dns_names = doc_old.dns_names
            self.save(refresh=refresh)
        return self.to_dict()

    def get_dict(self):
        try:
            doc_old = self.get(id=self.id)
            return doc_old.to_dict()
        except NotFoundError:
            return None


class ClueHttpTitleDocument(ProjectMetaDocument, ClueMetaDocument, WebMetaDocument):
    title = Keyword()

    class Index:
        name = 'clue_http_title'
        settings = {
            "number_of_shards": 1,  # 设置为1，这是最小值
            "number_of_replicas": 0  # 禁用复制
        }
