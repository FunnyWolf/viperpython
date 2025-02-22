import time

from External.nmap.portscanner import PortScanner
from Lib.api import is_domain
from Lib.log import logger
from WebDatabase.Interface.dataset import DataSet
from WebDatabase.documents import IPDomainDocument, PortDocument, DNSRecordDocument, ComponentDocument, ServiceDocument


class NmapAPI(object):
    def __init__(self, service_detect=True, os_detect=False,
                 port_parallelism=32, port_min_rate=64, custom_host_timeout=None, ports=None, top_ports=1000, all_ports=False):

        self.max_hostgroup = 128

        self.nmap_arguments = "-sT -n --open"
        self.max_retries = 3
        self.host_timeout = 60 * 5
        self.parallelism = port_parallelism  # 默认 32
        self.min_rate = port_min_rate  # 默认64

        if service_detect:
            self.host_timeout += 60 * 5
            self.nmap_arguments += " -sV"

        if os_detect:
            self.host_timeout += 60 * 4
            self.nmap_arguments += " -O"

        # if len(self.ports.split(",")) > 60:
        #     self.nmap_arguments += " -PE -PS{}".format(self.alive_port)
        #     self.max_retries = 2
        # else:
        #     if self.ports != "0-65535":
        #         self.nmap_arguments += " -Pn"

        ### ports

        if all_ports:
            self.max_hostgroup = 8
            self.min_rate = max(self.min_rate, 150)
            self.host_timeout += 60 * 5
            self.max_retries = 2
            port_arg = " -p 0-65535"
            top_ports_args = ""
        else:
            if ports:  # not None or []
                port_arg = f" -p {','.join(str(port) for port in ports)}"
                top_ports_args = ""
            else:
                port_arg = ""
                top_ports_args = f" --top-ports {top_ports}"
        self.nmap_arguments += port_arg
        self.nmap_arguments += top_ports_args

        # timeout rate
        self.nmap_arguments += " --max-rtt-timeout 800ms"
        self.nmap_arguments += " --min-rate {}".format(self.min_rate)
        self.nmap_arguments += " --script-timeout 6s"
        self.nmap_arguments += " --max-hostgroup {}".format(self.max_hostgroup)

        # 依据传过来的超时为准
        if custom_host_timeout is not None:
            if int(custom_host_timeout) > 0:
                self.host_timeout = custom_host_timeout
        self.nmap_arguments += " --host-timeout {}s".format(self.host_timeout)
        self.nmap_arguments += " --min-parallelism {}".format(self.parallelism)
        self.nmap_arguments += " --max-retries {}".format(self.max_retries)

    def os_match_by_accuracy(self, os_match_list):
        for os_match in os_match_list:
            accuracy = os_match.get('accuracy', '0')
            if int(accuracy) > 90:
                return os_match

        return {}

    def scan(self, targets, dataset: DataSet):
        source = "nmap"

        hosts = []
        for target in targets:
            target: dict
            hosts.append(target.get("ipdomain"))

        logger.debug("target: {}  arguments: {}".format(hosts, self.nmap_arguments))

        hosts_str = " ".join(hosts)

        nm: PortScanner = PortScanner()
        nm.scan(hosts=hosts_str, arguments=self.nmap_arguments)

        update_time = int(time.time())

        for host_ip in nm.all_hosts():
            record = nm[host_ip]
            hostnames = record.get("hostnames")
            if len(hostnames) > 1:
                print(hostnames)
                ipdomain = hostnames[0].get("name")
            elif len(hostnames) == 1:
                ipdomain = hostnames[0].get("name")
                if ipdomain == "":
                    ipdomain = host_ip
            else:
                ipdomain = host_ip

            ip = record.get("addresses").get("ipv4")

            ipdomain_object = IPDomainDocument()
            ipdomain_object.ipdomain = ipdomain
            ipdomain_object.source = source
            ipdomain_object.update_time = update_time
            dataset.ipdomainList.append(ipdomain_object)

            if is_domain(ipdomain):
                dnsrecord_obj: DNSRecordDocument = DNSRecordDocument()
                dnsrecord_obj.ipdomain = ipdomain
                dnsrecord_obj.type = "A"
                dnsrecord_obj.value = [ip]
                dnsrecord_obj.source = source
                dnsrecord_obj.update_time = update_time
                dnsrecord_obj.data = {"hostnames": record.get("hostnames"), "addresses": record.get("addresses")}
                dataset.dnsrecordList.append(dnsrecord_obj)

            tcp_info = record.get("tcp")
            for port, port_info in tcp_info.items():
                if port_info.get("state") == "open":
                    port_object = PortDocument()
                    port_object.ipdomain = ipdomain
                    port_object.port = port
                    port_object.alive = True
                    port_object.source = source
                    port_object.update_time = update_time
                    dataset.portList.append(port_object)

                    service_name = port_info.get("name")

                    service_obj = ServiceDocument()
                    service_obj.ipdomain = ipdomain
                    service_obj.port = port
                    service_obj.service = service_name
                    service_obj.version = port_info.get("version")
                    service_obj.transport = "tcp"
                    # service_obj.response = None
                    # service_obj.response_hash = None
                    service_obj.source = source
                    service_obj.data = port_info
                    service_obj.update_time = update_time
                    dataset.serviceList.append(service_obj)

                    component_object: ComponentDocument = ComponentDocument()
                    component_object.ipdomain = ipdomain
                    component_object.port = port
                    component_object.product_name = port_info.get("product")
                    component_object.product_version = port_info.get("version")
                    component_object.product_extrainfo = port_info.get("extrainfo")
                    component_object.source = source
                    component_object.update_time = update_time

                    dataset.componentList.append(component_object)

                    # os_info = ps.os_match_by_accuracy(record.get("osmatch", []))

        return dataset
