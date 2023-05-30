from email.policy import default
from django.db import models
from django.contrib.auth.models import AbstractUser
from phonenumber_field.modelfields import PhoneNumberField
import datetime
from django import db
from mptt.models import MPTTModel, TreeForeignKey
# from django.conf import settings
# from django.contrib.sessions.models import Session
# from django.contrib.auth import user_logged_in
# from django.dispatch.dispatcher import receiver


# Create your models here.

def get_deadline():
    return datetime.datetime.today() + datetime.timedelta(days=30)


class IconModel(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=45)
    file = models.FileField(upload_to='uploads/', max_length=100, blank=True)
    
    def __str__(self):
        return self.name

    class Meta:
        managed = True
        db_table = 'icon_model'


class PackageModel(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, default=None)

    def __str__(self):
        return self.name
 
    class Meta:
        managed = True
        db_table = 'PackageModel'

# previously company model. as soon as user logs in we find his pesuod id and use it to see which reports are available
class ClientModel(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    company_email = models.EmailField(max_length=100) #pseudo email address 
    wildcard_mode = models.BooleanField(default=False)
    otp_access = models.BooleanField(default=True)
    package = models.ManyToManyField(PackageModel, blank= True, null=True)

    def __str__(self):
        return self.name
 
    class Meta:
        managed = True
        db_table = 'ClientModel'

class ReportModel(models.Model):
    id = models.AutoField(primary_key=True)
    report_name = models.CharField(max_length=100)

    def __str__(self):
        return self.report_name


class NewReportModel(MPTTModel):
    FILTER_CHOICES = [
        ('sector', 'sector'),
        ('categories', 'categories'),
        ('industry', 'industry'),
        ('1', 'player'),
        ('medical', 'medical')
    ]
    id = models.AutoField(primary_key=True)
    report_name = models.CharField(max_length=100)
    parent = TreeForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='children')
    info = models.TextField(default=None, null=True, blank=True)
    finalized = models.BooleanField(default=False)
    filter = models.CharField(default = None, blank=True, null = True, max_length=200, choices=FILTER_CHOICES)
    filter_value = models.CharField(default = None, blank=True, null = True, max_length=200)
    node_type = models.CharField(default = None, blank=True, null = True, max_length=200)
    free = models.BooleanField(default=False)
    has_link = models.BooleanField(default=True)

    def __str__(self):
        return self.report_name

    class Meta:
        managed = True
        db_table = 'new_report_model'

class Player(models.Model):
    player_id = models.AutoField(primary_key=True, auto_created=True)
    player_name = models.CharField(max_length=45)
    industry_id = models.IntegerField(default=3) #is called industry
    powerbi_page = models.CharField(max_length=2000, default=None, blank=True, null=True)
    image = models.ForeignKey('IconModel', on_delete=models.CASCADE,default=None, blank=True, null=True)
    industry_name = models.CharField(max_length=255)
    leadership = models.TextField(default=None, null=True, blank=True)
    status = models.CharField(max_length=255)
    stage = models.CharField(max_length=255)
    last_valuations = models.CharField(max_length=255)
    newreport = models.ForeignKey('NewReportModel', on_delete=models.CASCADE,default=None, blank=True, null=True)
    

    def __str__(self):
        return self.player_name

    class Meta:
        managed = False
        db_table = 'player'

class NewReportPagesModel(models.Model):
    FILTER_CHOICES = [
        ('powerbi', 'powerbi'),
        ('httpsAddress', 'httpAddress'),
        ('component', 'component'),
    ]
    id = models.AutoField(primary_key=True)
    report = models.ForeignKey('NewReportModel', on_delete=models.CASCADE)
    page_name = models.CharField(max_length=200)
    link = models.CharField(max_length=200)
    url = models.TextField(default=None, null=True, blank=True)
    embed = models.TextField(default=None, null=True, blank=True)
    powerbi_report_id = models.CharField(max_length=200, default=None, null=True, blank=True)
    report_name = models.CharField(max_length=200, default=None, null=True, blank=True)
    same_page = models.BooleanField(default=False)
    has_address = models.BooleanField(default=False)
    address = models.TextField(default=None, null=True, blank=True)
    page_type = models.CharField(default = None, blank=True, null = True, max_length=200, choices=FILTER_CHOICES)
    component = models.CharField(max_length=200, default=None, null=True, blank=True)
    component_variable = models.TextField(default=None, null=True, blank=True)
    excel_access = models.BooleanField(default=False)
    def __str__(self):
        return self.page_name

    class Meta:
        managed = True
        db_table = 'new_report_pages'

class UserCurrencyModel(models.Model):
    id = models.AutoField(primary_key=True)
    currency = models.CharField(max_length=200,default='USD', null=True, blank=True)
    # report = models.ForeignKey('NewReportModel', on_delete=models.CASCADE)
    report = models.CharField(max_length=200, default=None, null=True, blank=True)
    email = models.CharField(max_length=200,default=None, null=True, blank=True)
    year = models.CharField(max_length=200,default='FY', null=True, blank=True)
    def __str__(self):
        return self.email

    class Meta:
        managed = True
        db_table = 'user_currency_model'

# will not use arrayfields as they are suupported by postgres only. Report url is embed url. report id  
# needed in report page . drop dataset id. to get emebed token we need to use report id.
# is subsciption model
# id form reportacces model and player  toget acces fror various. existing admin report accesmodel inline make it multiselect
# report acess model 1 to many field fpr players
class ReportAccessModel(models.Model):
    id = models.AutoField(primary_key=True)
    # email = models.EmailField(max_length=100)  #real email here which is granted acess
    report_id = models.ForeignKey(ReportModel, on_delete = models.CASCADE)
    client_id = models.ForeignKey(ClientModel, on_delete=models.CASCADE)
    start_date = models.DateField(default=datetime.date.today, blank=True, null=True)
    end_date = models.DateField(default=get_deadline, blank=True, null=True)
    players = models.ManyToManyField(Player)
    # report_name = models.CharField(max_length=100)
    # ms_report_id = models.UUIDField()
    # dataset_id = models.UUIDField()
    # report_url = models.CharField(max_length=600)
    # embed_url = models.CharField(max_length=600)
    
    def __str__(self):
        return str(self.client_id)
    class Meta:
        managed = True
        db_table = 'ReportAccessModel'

class CompanyDomainModel(models.Model):
    id = models.AutoField(primary_key=True)
    domain_name = models.CharField(max_length=100)
    client_id = models.ForeignKey(ClientModel, on_delete=models.CASCADE)
    def __str__(self):
        return self.domain_name
    
    class Meta:
        managed = True
        db_table = 'CompanyDomainModel'

class ReportPlayerModel(models.Model):
    id = models.AutoField(primary_key=True)
    report = models.ForeignKey('ReportModel', on_delete=models.CASCADE)
    player = models.ForeignKey('Player', on_delete=models.CASCADE)
    
    class Meta:
        managed = True
        db_table = 'ReportPlayerModel'

class ReportPagesModel(MPTTModel):
    id = models.AutoField(primary_key=True)
    page_name = models.CharField(max_length=45)
    report = models.ForeignKey('ReportModel', on_delete=models.CASCADE)
    parent = TreeForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='children')
    icon = models.ForeignKey('IconModel', on_delete=models.CASCADE)
    link = models.CharField(max_length=45)
    url = models.TextField(default=None, null=True, blank=True)
    powerbi_report_id = models.CharField(max_length=200, default=None, null=True, blank=True)
    report_name = models.CharField(max_length=200, default=None, null=True, blank=True)
    same_page = models.BooleanField(default=False)
    order = models.IntegerField(default=1, blank = True, null=True)
    def __str__(self):
        return self.page_name

    class Meta:
        managed = True
        db_table = 'report_pages_model'

class TagModel(models.Model):
    id = models.AutoField(primary_key=True)
    tag_name = models.CharField(max_length=200)
    reports = models.ManyToManyField(ReportModel)
    class Meta:
        managed = True
        db_table = 'tag_model'

class UserPopupModel(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200 ,blank=True,null=True)
    phone = models.CharField(max_length=255,blank=True,null=True)
    email = models.CharField(max_length=200,blank=True,null=True)
    message = models.TextField(blank=True,null=True)
    class Meta:
        managed = True
        db_table = 'UserPopup_model'

class NewReportAccessModel(models.Model):
    id = models.AutoField(primary_key=True)
    client_id = models.ForeignKey(ClientModel, on_delete=models.CASCADE, blank=True, null=True)
    package_id = models.ForeignKey(PackageModel, on_delete=models.CASCADE, blank=True, null=True)
    report_id = models.ForeignKey(NewReportModel, on_delete = models.CASCADE)
    start_date = models.DateField(default=datetime.date.today, blank=True, null=True)
    end_date = models.DateField(default=get_deadline, blank=True, null=True)
    players = models.ManyToManyField(Player, blank= True, null=True)
    report_pages = models.ManyToManyField(NewReportPagesModel, blank=True, null=True)
    def __str__(self):
        return str(self.client_id)
    class Meta:
        managed = True
        db_table = 'NewReportAccessModel'


class NewReportPageAccessModel(models.Model):
    id = models.AutoField(primary_key=True)
    report_access_id = models.ForeignKey(NewReportAccessModel, on_delete=models.CASCADE)
    page_id = models.ForeignKey(NewReportPagesModel, on_delete=models.CASCADE)

    def __str__(self):
        return str(self.report_access_id)
    class Meta:
        managed = True
        db_table = 'NewReportPageAccessModel'

# class UserSession(models.Model):
#     user = models.ForeignKey(ßsettings.AUTH_USER_MODEL, on_delete=models.CASCADE)
#     session = models.OneToOneField(Session, on_delete=models.CASCADE)


# @receiver(user_logged_in)
# def remove_other_sessions(sender, user, request, **kwargs):
#     # remove other sessions
#     Session.objects.filter(usersession__user=user).delete()
    
#     # save current session
#     request.session.save()

#     # create a link from the user to the current session (for later removal)
#     UserSession.objects.get_or_create(
#         user=user,
#         session_id=request.s ession.session_key
#     )

class User(AbstractUser):
    phone = models.CharField(max_length=255,blank=True,null=True)
    client = models.ForeignKey(ClientModel , on_delete=models.CASCADE)
    counter = models.IntegerField(default=0)
    gender_male = models.BooleanField(default=True ,blank=True,null=True)

# User._meta.get_field('email')._unique = True
