from elasticsearch import Elasticsearch
from elasticsearch_dsl import connections

from CONFIG import ES_HOST, ES_PASSWORD, ES_USERNAME
from WebDatabase.documents import ProjectDocument, HttpFaviconDocument, HttpBaseDocument, WAFDocument, ClueCompanyDocument, \
    CompanyWechatDocument, CompanyAPPDocument, CompanyICPDocument, ClueCertDocument, ClueHttpTitleDocument, ClueFaviconDocument, \
    PortDocument, IPDomainDocument, LocationDocument, ScreenshotDocument, VulnerabilityDocument, ServiceDocument, CDNDocument, ComponentDocument, CertDocument


class EsClient(object):
    def __index__(self):
        pass

    @staticmethod
    def init():
        raw_es_client = EsClient.raw_es_client()
        document_class_list = [ProjectDocument, HttpFaviconDocument, HttpBaseDocument, WAFDocument, ClueCompanyDocument, CompanyWechatDocument,
                               CompanyAPPDocument, CompanyICPDocument, ClueCertDocument, ClueHttpTitleDocument, ClueFaviconDocument, PortDocument,
                               IPDomainDocument, LocationDocument, ScreenshotDocument, VulnerabilityDocument, ServiceDocument, CDNDocument, ComponentDocument,
                               CertDocument]
        for one_class in document_class_list:
            if not raw_es_client.indices.exists(index=one_class.Index.name):
                one_class.init()

    @staticmethod
    def raw_es_client():
        client = Elasticsearch(
            hosts=[ES_HOST],
            basic_auth=(ES_USERNAME, ES_PASSWORD)
        )
        return client

    @staticmethod
    def add_default_connection():
        client = Elasticsearch(
            hosts=[ES_HOST],
            basic_auth=(ES_USERNAME, ES_PASSWORD)
        )
        connections.add_connection('default', client)

    @staticmethod
    def convert_to_dicts(elasticsearch_results):
        dict_objects = []
        for hit in elasticsearch_results:
            obj_dict = hit.to_dict()
            obj_dict['id'] = hit.meta.id  # 添加文档 ID
            dict_objects.append(obj_dict)
        return dict_objects
