from django.db import models
from django.contrib.auth.models import AbstractUser
from phonenumber_field.modelfields import PhoneNumberField
import datetime
from django import db
from mptt.models import MPTTModel, TreeForeignKey


# Create your models here.

def get_deadline():
    return datetime.datetime.today() + datetime.timedelta(days=30)

class User(AbstractUser):
    phone = models.CharField(max_length=255,blank=True,null=True)


# previously company model. as soon as user logs in we find his pesuod id and use it to see which reports are available
class ClientModel(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    company_email = models.EmailField(max_length=100) #pseudo email address 
    login_mode = models.BooleanField(default=False)

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

# will not use arrayfields as they are suupported by postgres only. Report url is embed url. report id  
# needed in report page . drop dataset id. to get emebed token we need to use report id.
class ReportAccessModel(models.Model):
    id = models.AutoField(primary_key=True)
    email = models.EmailField(max_length=100)  #real email here which is granted acess
    report_id = models.ForeignKey(ReportModel, on_delete = models.CASCADE)
    client_id = models.ForeignKey(ClientModel, on_delete=models.CASCADE)
    start_date = models.DateField(default=datetime.date.today)
    end_date = models.DateField(default=get_deadline)

    # report_name = models.CharField(max_length=100)
    # ms_report_id = models.UUIDField()
    # dataset_id = models.UUIDField()
    # report_url = models.CharField(max_length=600)
    # embed_url = models.CharField(max_length=600)
    
    def __str__(self):
        return self.email

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

class Player(models.Model):
    player_id = models.AutoField(primary_key=True, auto_created=True)
    player_name = models.CharField(max_length=45)
    industry_id = models.IntegerField(default=3) #is called industry

    class Meta:
        managed = False
        db_table = 'player'

class ReportPlayerModel(models.Model):
    id = models.AutoField(primary_key=True)
    report = models.ForeignKey('ReportModel', on_delete=models.CASCADE)
    player = models.ForeignKey('Player', on_delete=models.CASCADE)
    
    class Meta:
        managed = True
        db_table = 'ReportPlayerModel'

class IconModel(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=45)
    file = models.FileField(upload_to='uploads/', max_length=100, blank=True)
    
    def __str__(self):
        return self.name

    class Meta:
        managed = True
        db_table = 'icon_model'

class ReportPagesModel(MPTTModel):
    id = models.AutoField(primary_key=True)
    page_name = models.CharField(max_length=45)
    report = models.ForeignKey('ReportModel', on_delete=models.CASCADE)
    parent = TreeForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='children')
    icon = models.ForeignKey('IconModel', on_delete=models.CASCADE)
    link = models.CharField(max_length=45)
    order = models.IntegerField(default=1, blank = True, null=True)

    def __str__(self):
        return self.page_name

    class Meta:
        managed = True
        db_table = 'report_pages_model'
