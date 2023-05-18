from django.contrib import admin
from django_mptt_admin.admin import DjangoMpttAdmin
from django.contrib.auth.admin import UserAdmin
from django.contrib.admin.widgets import FilteredSelectMultiple
from django import forms
from django.forms.models import BaseInlineFormSet


# Register your models here.
from .models import ClientModel, ReportModel, ReportAccessModel,CompanyDomainModel,ReportPlayerModel, IconModel,ReportPagesModel,User, NewReportPagesModel, NewReportModel, NewReportAccessModel, NewReportPageAccessModel, Player, PackageModel

#admin.site.register(User)
# admin.site.register(ClientModel)
admin.site.register(Player)
admin.site.register(ReportModel)
admin.site.register(ReportAccessModel)
admin.site.register(CompanyDomainModel)
admin.site.register(ReportPlayerModel)
admin.site.register(IconModel)
admin.site.register(NewReportPagesModel)
admin.site.register(NewReportPageAccessModel)
admin.site.register(NewReportAccessModel)
# admin.site.register(PackageModel)
# admin.site.register(ReportPagesModel)

class CustomUserAdmin(admin.TabularInline):
    model = User
    fields = ('email', 'username', 'first_name', 'last_name', 'is_staff', 'is_active','phone', 'password', 'gender_male')
# admin.site.register(User, UserAdmin) 
class DjangoUserAdmin(UserAdmin):
    model = User
    fieldsets = UserAdmin.fieldsets + (('Custom fields', {'fields': ('phone', 'gender_male')}),)

admin.site.register(User, DjangoUserAdmin)



class ReportPagesAdmin(DjangoMpttAdmin):
        search_fields = ['report__report_name']
        pass


admin.site.register(ReportPagesModel, ReportPagesAdmin)    


class NewReportPagesAdmin(admin.TabularInline):
    model = NewReportPagesModel

class NewReportAdmin(DjangoMpttAdmin):
    inlines = [NewReportPagesAdmin]

admin.site.register(NewReportModel, NewReportAdmin)  


class ReportAccessAdmin(admin.TabularInline):
    model = ReportAccessModel

class CompanyDomainAdmin(admin.TabularInline):
    model = CompanyDomainModel

class OptionalFilteredSelectMultiple(FilteredSelectMultiple):
    def value_from_datadict(self, data, files, name):
        values = super().value_from_datadict(data, files, name)
        if values:
            return values
        return []

class NewReportAccessForm(forms.ModelForm):
    report_pages = forms.ModelMultipleChoiceField(queryset=NewReportPagesModel.objects.all(),  widget=OptionalFilteredSelectMultiple('NewReportPagesModel', False), required=False)
    players = forms.ModelMultipleChoiceField(queryset=Player.objects.all(),  widget=OptionalFilteredSelectMultiple('Player', False),required=False)
    class Meta:
        model = NewReportAccessModel
        fields = '__all__'

class NewReportAccessAdmin(admin.StackedInline):
    model = NewReportAccessModel
    form = NewReportAccessForm

class ClientAdmin(admin.ModelAdmin):
    model = ClientModel
    # fieldsets = (
    #     ('ClientDetails', {'fields':('Reports')})
    # )
    inlines = [ReportAccessAdmin, CompanyDomainAdmin, CustomUserAdmin, NewReportAccessAdmin]

admin.site.register(ClientModel, ClientAdmin) 

class NewReportAccessPackageForm(forms.ModelForm):
    report_pages = forms.ModelMultipleChoiceField(queryset=NewReportPagesModel.objects.all(),  widget=OptionalFilteredSelectMultiple('NewReportPagesModel', False), required=False)
    players = forms.ModelMultipleChoiceField(queryset=Player.objects.all(),  widget=OptionalFilteredSelectMultiple('Player', False),required=False)
    class Meta:
        model = NewReportAccessModel
        fields = ['report_id', 'start_date', 'end_date', 'players', 'report_pages']

class NewReportAccessPackageAdmin(admin.StackedInline):
    model = NewReportAccessModel
    form = NewReportAccessPackageForm



class PackageAdmin(admin.ModelAdmin):
    model = PackageModel
    inlines = [NewReportAccessPackageAdmin]

admin.site.register(PackageModel, PackageAdmin) 


