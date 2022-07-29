from urllib.parse import urlparse
from rest_framework import routers
from django.contrib import admin
from django.urls import path
from django.conf.urls import include
from .views import LoginApi, UserViewSet, CompanyLCView, ReportAccessLCView, ReportAccessRUDView, ReportLCView,CompanyDomainLCView,MSAccessTokenAPI, PlayerLCView, ReportPageApi


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


urlpatterns = [
    path('', include(router.urls)),
    path('authorise/', include(authUrls), name='authorise'),
    path('company/', include(companyUrls), name='company'),
    path('report/', include(reportUrls), name='report'),
    path('report_access/', include(reportAccessUrls), name='report_access'),
    path('company_domain/', include(companyDomainUrls), name='company_domain'),
    path("player/", include((player_urls, "player"), namespace="player")),
    path("MSAccessToken/", include(MSUrls), name='ms'),
    path("PageReports/", include(ReportPageUrls), name='reportpages')
    ]