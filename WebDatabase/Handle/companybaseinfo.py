from WebDatabase.models import CompanyBaseInfoModel
from WebDatabase.serializers import CompanyBaseInfoSerializer


class CompanyBaseInfo(object):
    @staticmethod
    def list(project_id=None):
        models = CompanyBaseInfoModel.objects.filter(project_id=project_id)
        result = CompanyBaseInfoSerializer(models, many=True).data
        return result

    @staticmethod
    def update_or_create(project_id=None, pid=None, data=None, webbase_dict={}):
        default_dict = {
            'project_id': project_id,
            'pid': pid
        }
        default_dict.update(data)
        default_dict.update(webbase_dict)
        model, create = CompanyBaseInfoModel.objects.update_or_create(pid=pid,
                                                                      defaults=default_dict)
        return create

    @staticmethod
    def update_project_id(project_id=None, pid=None):
        update_count = CompanyBaseInfoModel.objects.filter(pid=pid).update(project_id=project_id)
        return {"count": update_count}
