from WebDatabase.models import CompanyWechatModel
from WebDatabase.serializers import CompanyWechatSerializer


class CompanyWechat(object):
    @staticmethod
    def list(pid=None):
        models = CompanyWechatModel.objects.filter(pid=pid)
        result = CompanyWechatSerializer(models, many=True).data
        return result

    @staticmethod
    def update_or_create(pid=None, data=None, webbase_dict={}):
        default_dict = {
            'pid': pid
        }
        default_dict.update(data)
        default_dict.update(webbase_dict)
        model, create = CompanyWechatModel.objects.update_or_create(pid=pid,
                                                                    defaults=default_dict)
        return create
