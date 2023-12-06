from Lib.log import logger
from Lib.xcache import Xcache


class WebModuleResult(object):
    def __init__(self):
        pass

    @staticmethod
    def list():
        try:
            task_result_list = []
            result = Xcache.list_web_module_result()
            for task_uuid in result:
                task_result: dict = result[task_uuid]
                loadpath = task_result.get("loadpath")
                moduleconfig = Xcache.get_moduleconfig(loadpath)
                if moduleconfig is None:
                    continue
                task_result["NAME_EN"] = moduleconfig.get("NAME_EN")
                task_result["NAME_ZH"] = moduleconfig.get("NAME_ZH")
                task_result_list.append(task_result)
            task_result_list.reverse()  # 将最新的结果放在最前面
            return task_result_list
        except Exception as E:
            logger.exception(E)
            return []
