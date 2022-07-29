# from django.contrib.auth.models import User
from asyncore import read
import re
from rest_framework.authtoken.models import Token
from rest_framework import serializers
from .models import ClientModel, ReportAccessModel, User, ReportModel, CompanyDomainModel, Player

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'phone', 'username', 'password']
        read_only_fields = ['id']

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        print(user)
        Token.objects.create(user=user)
        return user


class CompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = ClientModel
        fields = ['id', 'name', 'company_email', 'login_mode']
        read_only_fields = ['id']


class ReportModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportModel
        fields = ['id', 'report_name']
        read_only_fields = ['id']


class ReportAccessSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        report_id = rep['report_id']
        report_obj = ReportModel.objects.filter(id = report_id)[0]
        report_name = report_obj.report_name
        rep['report_name'] = report_name
        # rep['industry_name'] = Report.objects.filter(id=instance.report.id)[0].name
        return rep

    class Meta:
        model = ReportAccessModel
        fields = ['id', 'email', 'client_id', 'report_id']
        read_only_fields = ['id']


class CompanyDomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyDomainModel
        fields = ['id', 'client_id', 'domain_name']
        read_only_fields = ['id']
        
class PlayerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Player
        fields = ['player_id', 'player_name', 'industry_id']
        read_only_fields = ['player_id']        