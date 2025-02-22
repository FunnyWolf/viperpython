# -*- coding: utf-8 -*-
# @File  : edge.py
# @Date  : 2021/3/27
# @Desc  :

from PostLateral.models import EdgeModel
from PostLateral.serializers import EdgeSerializer


class Edge(object):
    def __init__(self):
        pass

    @staticmethod
    def list_edge(source=None, target=None, type=None):
        models = EdgeModel.objects.all()
        if source is not None:
            models = models.filter(source=source)
        if target is not None:
            models = models.filter(target=target)
        if type is not None:
            models = models.filter(type=type)
        data = EdgeSerializer(models, many=True).data
        return data

    @staticmethod
    def create_edge(source, target, type, data):
        if source == target:
            return False
        default_dict = {'source': source, 'target': target, 'type': type, 'data': data, }
        model, created = EdgeModel.objects.get_or_create(source=source,
                                                         target=target,
                                                         type=type,
                                                         data=data,
                                                         defaults=default_dict)
        if created is True:
            return True  # 新建后直接返回
        else:
            return False
