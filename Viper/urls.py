from django.urls import re_path, include
from rest_framework import routers

from Core.views import BaseAuthView, CurrentUserView, NoticesView, SettingView, HostView, HostInfoView, UUIDJsonView
from Core.views import NetworkSearchView
from Msgrpc.views import LazyLoaderView, LazyLoaderInterfaceView, CollectSandBoxInterfaceView, CollectSandBoxView
from Msgrpc.views import ServiceStatusView, PayloadView, JobView, HandlerView, SessionView, SessionIOView, RouteView
from Msgrpc.views import SocksView, TransportView, FileMsfView, FileSessionView, PortFwdView, HostFileView
from Msgrpc.views import WebDeliveryView, IPFilterView
from PostLateral.views import IntranetPortServiceView, CredentialView, VulnerabilityView
from PostModule.views import PostModuleConfigView, PostModuleActuatorView, PostModuleResultView, ProxyHttpScanView, LLMModuleView
from PostModule.views import PostModuleResultHistoryView, PostModuleAutoView
from WebDatabase.views import ProjectView, IPDomainView, WebTaskResultView, WebNoticesView, PortView, \
    OptionsView, CompanyICPView, CompanyAPPView, CompanyMediaView, ClueCompanyView, ClueFaviconView, ClueCertView

router = routers.DefaultRouter()
router.register(r'api/v1/core/baseauth', BaseAuthView, basename="BaseAuth")
router.register(r'api/v1/core/currentuser', CurrentUserView, basename="CurrentUser")
router.register(r'api/v1/core/notices', NoticesView, basename="Notice")
router.register(r'api/v1/core/setting', SettingView, basename="Setting")
router.register(r'api/v1/core/host', HostView, basename="Host")
router.register(r'api/v1/core/hostinfo', HostInfoView, basename="HostInfo")
router.register(r'api/v1/core/uuidjson', UUIDJsonView, basename="UUIDJsonView")

router.register(r'api/v1/core/networksearch', NetworkSearchView, basename="NetworkSearch")
router.register(r'api/v1/msgrpc/servicestatus', ServiceStatusView, basename="ServiceStatus")
router.register(r'api/v1/msgrpc/payload', PayloadView, basename="Payload")
router.register(r'api/v1/msgrpc/job', JobView, basename="Job")
router.register(r'api/v1/msgrpc/handler', HandlerView, basename="Handler")
router.register(r'api/v1/msgrpc/webdelivery', WebDeliveryView, basename="WebDelivery")
router.register(r'api/v1/msgrpc/session', SessionView, basename="Session")
router.register(r'api/v1/msgrpc/sessionio', SessionIOView, basename="SessionIO")
router.register(r'api/v1/msgrpc/route', RouteView, basename="Route")
router.register(r'api/v1/msgrpc/socks', SocksView, basename="Socks")
router.register(r'api/v1/msgrpc/portfwd', PortFwdView, basename="PortFwd")
router.register(r'api/v1/msgrpc/transport', TransportView, basename="Transport")
router.register(r'api/v1/msgrpc/filemsf', FileMsfView, basename="FileMsfView")
router.register(r'api/v1/msgrpc/filesession', FileSessionView, basename="FileSessionView")
router.register(r'api/v1/msgrpc/lazyloader', LazyLoaderView, basename="LazyLoaderView")
router.register(r'api/v1/msgrpc/collectsandbox', CollectSandBoxView, basename="CollectSandBoxView")
router.register(r'api/v1/msgrpc/ipfilter', IPFilterView, basename="IPFilterView")

router.register(r'api/v1/postlateral/portservice', IntranetPortServiceView, basename="IntranetPortServiceView")
router.register(r'api/v1/postlateral/credential', CredentialView, basename="CredentialView")
router.register(r'api/v1/postlateral/vulnerability', VulnerabilityView, basename="VulnerabilityView")
router.register(r'api/v1/postmodule/postmoduleconfig', PostModuleConfigView, basename="PostModuleConfig")
router.register(r'api/v1/postmodule/postmoduleactuator', PostModuleActuatorView, basename="PostModuleActuator")
router.register(r'api/v1/postmodule/postmoduleresult', PostModuleResultView, basename="PostModuleResult")
router.register(r'api/v1/postmodule/postmoduleresulthistory', PostModuleResultHistoryView,
                basename="PostModuleResultHistoryView")
router.register(r'api/v1/postmodule/postmoduleauto', PostModuleAutoView, basename="PostModuleAutoView")
router.register(r'api/v1/postmodule/proxyhttpscan', ProxyHttpScanView, basename="ProxyHttpScanView")
router.register(r'api/v1/postmodule/llmmodule', LLMModuleView, basename="LLMModuleView")
# WebDatabase
router.register(r'api/v1/webdatabase/project', ProjectView, basename="ProjectView")
router.register(r'api/v1/webdatabase/ipdomain', IPDomainView, basename="IPDomainView")
router.register(r'api/v1/webdatabase/options', OptionsView, basename="OptionsView")
router.register(r'api/v1/webdatabase/webtaskresult', WebTaskResultView, basename="WebTaskResultView")
router.register(r'api/v1/webdatabase/webnotices', WebNoticesView, basename="WebNoticesView")
router.register(r'api/v1/webdatabase/port', PortView, basename="PortView")

router.register(r'api/v1/webdatabase/companyicp', CompanyICPView, basename="CompanyICPView")
router.register(r'api/v1/webdatabase/companyapp', CompanyAPPView, basename="CompanyAPPView")
router.register(r'api/v1/webdatabase/companymedia', CompanyMediaView, basename="CompanyMediaView")
router.register(r'api/v1/webdatabase/cluecompany', ClueCompanyView, basename="ClueCompanyView")
router.register(r'api/v1/webdatabase/cluefavicon', ClueFaviconView, basename="ClueFaviconView")
router.register(r'api/v1/webdatabase/cluecert', ClueCertView, basename="ClueCertView")
# 无需认证的api
router.register(r'api/v1/d', HostFileView, basename="HostFileView")
router.register(r'api/v1/c', LazyLoaderInterfaceView, basename="LazyLoaderInterfaceView")
router.register(r'api/v1/a', CollectSandBoxInterfaceView, basename="CollectSandBoxInterfaceView")

urlpatterns = [
    re_path(r'^', include(router.urls)),
]

# from Lib.montior import MainMonitor
#
# MainMonitor().start()
