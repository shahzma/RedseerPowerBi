from django.contrib import admin
from django_mptt_admin.admin import DjangoMpttAdmin
from django.contrib.auth.admin import UserAdmin

# Register your models here.
from .models import ClientModel, ReportModel, ReportAccessModel,CompanyDomainModel,ReportPlayerModel, IconModel,ReportPagesModel,User, NewReportPagesModel, NewReportModel

# admin.site.register(User)
# admin.site.register(ClientModel)
admin.site.register(ReportModel)
admin.site.register(ReportAccessModel)
admin.site.register(CompanyDomainModel)
admin.site.register(ReportPlayerModel)
admin.site.register(IconModel)
admin.site.register(NewReportPagesModel)
# admin.site.register(ReportPagesModel)

class UserAdmin(admin.TabularInline):
    model = User
    fields = ('email', 'username', 'first_name', 'last_name', 'is_staff', 'is_active','phone', 'password')
# admin.site.register(User, UserAdmin) 

class ReportPagesAdmin(DjangoMpttAdmin):
        search_fields = ['report__report_name']
        pass


admin.site.register(ReportPagesModel, ReportPagesAdmin)    


class NewReportAdmin(DjangoMpttAdmin):
        pass


admin.site.register(NewReportModel, NewReportAdmin)  


class ReportAccessAdmin(admin.TabularInline):
    model = ReportAccessModel

class CompanyDomainAdmin(admin.TabularInline):
    model = CompanyDomainModel

class ClientAdmin(admin.ModelAdmin):
    model = ClientModel
    # fieldsets = (
    #     ('ClientDetails', {'fields':('Reports')})
    # )
    inlines = [ReportAccessAdmin, CompanyDomainAdmin, UserAdmin]

admin.site.register(ClientModel, ClientAdmin)  

