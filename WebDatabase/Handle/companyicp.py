from WebDatabase.models import CompanyICPModel
from WebDatabase.serializers import CompanyICPSerializer


class CompanyICP(object):
    @staticmethod
    def list(pid=None):
        models = CompanyICPModel.objects.filter(pid=pid)
        result = CompanyICPSerializer(models, many=True).data
        return result

    @staticmethod
    def update_or_create(pid=None, data=None, webbase_dict={}):
        default_dict = {
            'pid': pid
        }
        default_dict.update(data)
        default_dict.update(webbase_dict)
        model, create = CompanyICPModel.objects.update_or_create(pid=pid,
                                                                 defaults=default_dict)
        return create
