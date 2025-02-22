# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from elasticsearch import NotFoundError
from elasticsearch_dsl import Search

from Lib.esclient import EsClient
from WebDatabase.Handle.ipdomain import IPDomain
from WebDatabase.documents import ClueCertDocument, CertDocument


class ClueCert(object):

    @staticmethod
    def list(project_id=None):
        response = Search(index=ClueCertDocument.Index.name).query('term', project_id=project_id).execute()
        data_dict = EsClient.convert_to_dicts(response)
        return data_dict

    @staticmethod
    def update_by_http_Cert(ipdomain, port):
        project_id = IPDomain.get_project_id_by_ipdomain(ipdomain)
        if not project_id:
            return None

        try:
            http_Cert_doc = CertDocument.get(id=f"{ipdomain}:{port}")
        except NotFoundError:
            return None

        doc = ClueCertDocument(
            fingerprint_md5=http_Cert_doc.fingerprint_md5,
            cert=http_Cert_doc.cert,
            jarm=http_Cert_doc.jarm,
            subject=http_Cert_doc.subject,
            subject_dn=http_Cert_doc.subject_dn,
            dns_names=http_Cert_doc.dns_names,

            project_id=project_id,

            note=f"{ipdomain}:{port}",
            exact=True,

            source=http_Cert_doc.source,
            update_time=http_Cert_doc.update_time,
            # data=http_Cert_doc.data,
        )
        data = doc.update_or_create()
        return data

    @staticmethod
    def delete_by_project_id(project_id=None):
        response = Search(index=ClueCertDocument.Index.name).query('term', project_id=project_id).delete()
        return response.deleted

    @staticmethod
    def destroy_by_id(id=None, refresh=False):
        response = Search(index=ClueCertDocument.Index.name).query('term', _id=id).delete()
        if refresh:
            raw_es_client = EsClient.raw_es_client()
            raw_es_client.indices.refresh(index=ClueCertDocument.Index.name)
        return response.deleted
