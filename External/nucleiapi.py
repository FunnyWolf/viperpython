import json
import os.path
import time

from Lib.api import exec_system, parse_url_simple
from Lib.api import random_str
from Lib.file import File
from Lib.log import logger
from Lib.xcache import Xcache
from WebDatabase.Interface.dataset import DataSet
from WebDatabase.documents import ServiceDocument, VulnerabilityDocument


class NucleiAPI(object):
    def __init__(self):
        ran_str = random_str(16)
        self.nuclei_target_path = os.path.join(File.tmp_dir(),
                                               "nuclei_target_{}.txt".format(ran_str))

        self.nuclei_result_path = os.path.join(File.tmp_dir(),
                                               "nuclei_result_{}.json".format(ran_str))

        self.nuclei_bin_path = File.safe_os_path_join(File.bin_path(), "nuclei")
        self.nuclei_templates_path = File.safe_os_path_join(File.bin_path(), "nuclei-templates")
        # self.levels = ["medium", "high", "critical"]
        self.levels = Xcache.get_common_conf_by_key("nuclei_levels")
        self.rate_limit = Xcache.get_common_conf_by_key("nuclei_rate_limit")

    def _delete_file(self):
        try:
            os.unlink(self.nuclei_target_path)
            # 删除结果临时文件
            if os.path.exists(self.nuclei_result_path):
                os.unlink(self.nuclei_result_path)
        except Exception as e:
            logger.exception(e)

    def _gen_target_file(self, targets: list):
        with open(self.nuclei_target_path, "w") as f:
            f.writelines(target + "\n" for target in targets)

    def dump_result(self) -> list:
        with open(self.nuclei_result_path, "r") as f:
            data = json.load(f)
            return data

    def exec_nuclei(self, silent):

        command = [
            self.nuclei_bin_path,
            ### TARGET
            "-l {}".format(self.nuclei_target_path),

            ### TEMPLATES
            f'-t {self.nuclei_templates_path}',
            # '-t /root/viper/STATICFILES/BIN/nuclei-templates/http/cves/2017/CVE-2017-10271.yaml',

            ### FILTERING

            "-s",
            ",".join(self.levels),

            "-pt http",
            # "-tags cve",
            # "-severity critical",

            ### UPDATE
            "-duc",

            ### OUTPUT
            "-je {}".format(self.nuclei_result_path),

            ### RATE-LIMIT
            f"-rate-limit {self.rate_limit}",
            "-concurrency 100",

            ### OPTIMIZATIONS
            "-timeout 1",
            "-max-host-error 10",

            ### STATISTICS
            # "-stats",
            # "-stats-interval 10",
        ]

        if silent:
            command.append('-silent')

        logger.info(" ".join(command))
        exec_system(command, timeout=12 * 60 * 60)

    def check(self, targets: list, silent=True):
        self._gen_target_file(targets)
        self.exec_nuclei(silent)

        results = self.dump_result()

        # 删除临时文件./
        self._delete_file()

        return results

    def scan(self, urls: list, dataset: DataSet):

        source = "nuclei"

        logger.info(f"Targets Len: {urls}")

        # if there is no input, use dataset
        if not urls:
            urls = []
            for service_obj in dataset.serviceList:
                service_obj: ServiceDocument
                url = service_obj.group_url()
                if url is None:
                    continue
                urls.append(url)

        items = self.check(urls, silent=False)
        for item in items:
            info = item.get("info")
            name = info.get("name")
            description = info.get("description")
            severity = info.get("severity")
            template_id = item.get("template-id")
            matched_at = item.get("matched-at")

            request = item.get("request")
            response = item.get("response")

            update_time = int(time.time())
            reference = info.get("reference")
            if not reference:
                reference = []

            url = item.get("url")

            scheme, hostname, port = parse_url_simple(url)

            vulnerabilityObject = VulnerabilityDocument()
            vulnerabilityObject.ipdomain = hostname
            vulnerabilityObject.port = port

            vulnerabilityObject.name = name
            vulnerabilityObject.description = description
            vulnerabilityObject.severity = severity

            vulnerabilityObject.template_id = template_id
            vulnerabilityObject.matched_at = matched_at
            vulnerabilityObject.reference = reference
            vulnerabilityObject.request = request
            vulnerabilityObject.response = response

            vulnerabilityObject.source = source
            vulnerabilityObject.update_time = update_time
            vulnerabilityObject.data = item

            dataset.vulnerabilityList.append(vulnerabilityObject)

        return dataset
