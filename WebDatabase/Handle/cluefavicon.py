# -*- coding: utf-8 -*-
# @File  : portservice.py
# @Date  : 2021/2/26
# @Desc  :

from elasticsearch import NotFoundError
from elasticsearch_dsl import Search

from Lib.esclient import EsClient
from WebDatabase.Handle.ipdomain import IPDomain
from WebDatabase.documents import ClueFaviconDocument, HttpFaviconDocument


class ClueFavicon(object):

    @staticmethod
    def list(project_id=None):
        response = Search(index=ClueFaviconDocument.Index.name).query('term', project_id=project_id).execute()
        data_dict = EsClient.convert_to_dicts(response)
        return data_dict

    @staticmethod
    def update_by_http_favicon(ipdomain, port):
        project_id = IPDomain.get_project_id_by_ipdomain(ipdomain)
        if not project_id:
            return None

        try:
            http_favicon_doc = HttpFaviconDocument.get(id=f"{ipdomain}:{port}")
        except NotFoundError:
            return None

        doc = ClueFaviconDocument(
            hash=http_favicon_doc.hash,
            content=http_favicon_doc.content,

            project_id=project_id,

            note=f"{ipdomain}:{port}",
            exact=True,

            source=http_favicon_doc.source,
            update_time=http_favicon_doc.update_time,
            # data=http_favicon_doc.data,
        )
        data = doc.update_or_create()
        return data

    @staticmethod
    def delete_by_project_id(project_id=None):
        response = Search(index=ClueFaviconDocument.Index.name).query('term', project_id=project_id).delete()
        return response.deleted

    @staticmethod
    def destroy_by_id(id=None, refresh=False):
        response = Search(index=ClueFaviconDocument.Index.name).query('term', _id=id).delete()
        if refresh:
            raw_es_client = EsClient.raw_es_client()
            raw_es_client.indices.refresh(index=ClueFaviconDocument.Index.name)
        return response.deleted
