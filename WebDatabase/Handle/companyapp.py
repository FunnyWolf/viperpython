from WebDatabase.models import CompanyAPPModel
from WebDatabase.serializers import CompanyAPPSerializer


class CompanyAPP(object):
    @staticmethod
    def list(pid=None):
        models = CompanyAPPModel.objects.filter(pid=pid)
        result = CompanyAPPSerializer(models, many=True).data
        return result

    @staticmethod
    def update_or_create(pid=None, data=None, webbase_dict={}):
        default_dict = {
            'pid': pid
        }
        default_dict.update(data)
        default_dict.update(webbase_dict)
        model, create = CompanyAPPModel.objects.update_or_create(pid=pid,
                                                                 defaults=default_dict)
        return create
