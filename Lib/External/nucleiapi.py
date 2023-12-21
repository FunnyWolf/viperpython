import json
import os.path
import subprocess

from Lib.api import exec_system
from Lib.api import random_str
from Lib.file import File
from Lib.log import logger


class NucleiAPI(object):
    def __init__(self):
        ran_str = random_str(16)
        self.nuclei_target_path = os.path.join(File.tmp_dir(),
                                               "nuclei_target_{}.txt".format(ran_str))

        self.nuclei_result_path = os.path.join(File.tmp_dir(),
                                               "nuclei_result_{}.json".format(ran_str))

        self.nuclei_bin_path = File.safe_os_path_join(File.bin_path(), "nuclei")
        self.nuclei_templates_path = File.safe_os_path_join(File.bin_path(), "nuclei-templates")

    def _delete_file(self):
        try:
            os.unlink(self.nuclei_target_path)
            # 删除结果临时文件
            if os.path.exists(self.nuclei_result_path):
                os.unlink(self.nuclei_result_path)
        except Exception as e:
            logger.warning(e)

    def check_have_nuclei(self) -> bool:
        command = [self.nuclei_bin_path, "-version"]
        try:
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if pro.returncode == 0:
                return True
        except Exception as e:
            logger.debug("{}".format(str(e)))

        return False

    def _gen_target_file(self, targets: list):
        with open(self.nuclei_target_path, "w") as f:
            # for domain in targets:
            #     domain = domain.strip()
            #     if not domain:
            #         continue
            #     f.write(domain + "\n")
            f.writelines(targets)

    def dump_result(self) -> list:
        with open(self.nuclei_result_path, "r") as f:
            data = json.load(f)
            return data

    def exec_nuclei(self, silent):

        command = [self.nuclei_bin_path,
                   # "-tags cve",
                   # "-stats",
                   # "-stats-interval 60",
                   '-t /root/viper/STATICFILES/BIN/nuclei-templates/http/cves/2017/CVE-2017-10271.yaml',
                   # "-severity low,medium,high,critical",
                   # f'-t {self.nuclei_templates_path}',
                   "-duc",
                   "-severity high,critical",
                   "-type http",
                   "-l {}".format(self.nuclei_target_path),
                   "-je {}".format(self.nuclei_result_path),
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
