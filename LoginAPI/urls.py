from urllib.parse import urlparse
from rest_framework import routers
from django.contrib import admin
from django.urls import path
from django.conf.urls import include
from .views import LogOutApi, LoginApi, UserViewSet, CompanyLCView, ReportAccessLCView, ReportAccessRUDView, ReportLCView,CompanyDomainLCView,MSAccessTokenAPI, PlayerLCView, ReportPageApi\
    ,ReportPlayerLCView, IconLCView, ValidateCurrentToken, GoogleLoginApi, MicrosoftLoginApi, ExcelLinkApi, TagLCView, UserPopupLCView, NewReportAPI, NewReportPagesLCView, UserCurrencyLCView,\
         NewReportAccessLCView, NewReportPageAccessLCView, NewReportAccessTree, NodeChildrenAPI, SubPlayerLCView, DummyNodesAPI, index, FinalizedAPI,AccessAPI, EmailApi, NewExcelLinkApi


router = routers.DefaultRouter()
router.register('users', UserViewSet)

authUrls = [
    path("login/", LoginApi.as_view(), name="login"),
    # path("logout", UserAuthApi.LogoutApi.as_view(), name="logout"),
    # path("verify", UserAuthApi.AuthenticateCredentials.as_view(), name="verify")
]

MSUrls = [
    path("", MSAccessTokenAPI.as_view(), name = "lc")
]

ReportPageUrls = [
    path("", ReportPageApi.as_view(), name = "lc")
]

companyUrls = [
    path("", CompanyLCView.as_view(), name="lc"),
]

reportAccessUrls = [
    # modify create method to accept email
    path("", ReportAccessLCView.as_view(), name="lc"),
    path("<int:id>/", ReportAccessRUDView.as_view(), name="rud"),
]

reportUrls = [
    path("", ReportLCView.as_view(), name="lc")
]

companyDomainUrls = [
    path("", CompanyDomainLCView.as_view(), name="lc")
]

player_urls = [
    path("", PlayerLCView.as_view(), name="lc"),
]

reportPlayer_urls = [
    path('', ReportPlayerLCView.as_view(), name = 'lc')
]

icon_urls = [
    path('', IconLCView.as_view(), name = 'lc')
]

logout_urls = [
    path('', LogOutApi.as_view(), name = 'lc')
]

validate_urls = [
    path('', ValidateCurrentToken.as_view(), name = 'lc')
]

google_urls = [
    path('', GoogleLoginApi.as_view(), name = 'l')
]

ms_urls = [
    path('', MicrosoftLoginApi.as_view(), name='l')
]

excellink_urls = [
    path('', ExcelLinkApi.as_view(), name = 'l')
]

newexcellink_urls = [
    path('', NewExcelLinkApi.as_view(), name = 'l')
]

tag_urls = [
    path('', TagLCView.as_view(), name = 'l')
]

userpopup_urls = [
    path('', UserPopupLCView.as_view(), name = 'l')
]

newreport_urls = [
    path('', NewReportAPI.as_view(), name = 'l')
]

newreportpages_urls = [
    path('', NewReportPagesLCView.as_view(), name='l')
]

usercurrency_urls = [
    path('',  UserCurrencyLCView.as_view(), name="lc")
]

newreportaccess_urls = [
    path('',  NewReportAccessLCView.as_view(), name="lc")
]

newreportaccesstree_urls = [
    path('', NewReportAccessTree.as_view(), name='lc')
]

nodechildren_urls = [
    path('', NodeChildrenAPI.as_view(), name = 'lc')
]

subplayer_urls = [
    path("", SubPlayerLCView.as_view(), name="lc"),
]

dummynodes_urls = [
     path("", DummyNodesAPI.as_view(), name="lc"),
]

finalized_urls = [
    path("", FinalizedAPI.as_view(), name="lc"),
]
accessapi_urls = [
    path('',AccessAPI.as_view(), name = 'lc')
]

sendmail_urls = [
    path('',EmailApi.as_view(), name = 'lc')
]

urlpatterns = [
    path('', include(router.urls)),
    path('authorise/', include(authUrls), name='authorise'),
    path('company/', include(companyUrls), name='company'),
    path('report/', include(reportUrls), name='report'),
    path('report_access/', include(reportAccessUrls), name='report_access'),
    path('company_domain/', include(companyDomainUrls), name='company_domain'),
    path("player/", include((player_urls, "player"), namespace="player")),
    path("subplayer/", include((subplayer_urls, "subplayer"), namespace="subplayer")),
    path("MSAccessToken/", include(MSUrls), name='ms'),
    path("PageReports/", include(ReportPageUrls), name='reportpages'),
    path('ReportPlayers/', include(reportPlayer_urls), name = 'reportplayer'),
    path('icons/', include(icon_urls), name = 'icons'),
    path('logout/', include(logout_urls), name = 'logout'),
    path('validateToken/', include(validate_urls), name = 'validate'),
    path('api/v1/auth/login/google/', include(google_urls), name = 'google'),
    path('login/ms/', include(ms_urls), name = 'ms'),
    path('excel_link/', include(excellink_urls), name = 'excel'),
    path('newexcel/', include(newexcellink_urls), name = 'newexcel'),
    path('tags/', include(tag_urls), name = 'tag'),
    path('userpopup/', include(userpopup_urls), name = 'userpopup'),
    path('newreports/', include(newreport_urls), name = 'newreports'),
    path('newreportpages/', include(newreportpages_urls), name='newreportpages'),
    path('usercurrency/', include(usercurrency_urls), name='usercurrency'),
    path('newreportaccess/', include(newreportaccess_urls), name = 'newreportacess'),
    path('newreportaccesstree/', include(newreportaccesstree_urls), name = 'newreportacesstree'),
    path('nodechildren/', include(nodechildren_urls), name = 'nodechildren'),
    path('dummynodes/', include(dummynodes_urls), name = 'dummynodes'),
    path('finalized/', include(finalized_urls), name = 'finalized'),
    path('index/', index),
    path('accessapi/', include(accessapi_urls), name = 'accessapi'),
    path('sendmail/', include(sendmail_urls), name = 'sendmail')
    ]