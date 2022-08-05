from django.contrib import admin

# Register your models here.
from .models import ClientModel, ReportModel, ReportAccessModel,CompanyDomainModel,ReportPlayerModel, IconModel,ReportPagesModel

admin.site.register(ClientModel)
admin.site.register(ReportModel)
admin.site.register(ReportAccessModel)
admin.site.register(CompanyDomainModel)
admin.site.register(ReportPlayerModel)
admin.site.register(IconModel)
admin.site.register(ReportPagesModel)