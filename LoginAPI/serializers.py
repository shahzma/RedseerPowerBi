# from django.contrib.auth.models import User
from asyncore import read
from dataclasses import field
import re
from rest_framework.authtoken.models import Token
from rest_framework import serializers
from .models import ClientModel, ReportAccessModel, User, ReportModel, CompanyDomainModel, Player, ReportPagesModel, ReportPlayerModel, IconModel

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'phone', 'username', 'password', 'client']
        read_only_fields = ['id']

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        print(user)
        Token.objects.create(user=user)
        return user


class CompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = ClientModel
        fields = ['id', 'name', 'company_email', 'wildcard_mode']
        read_only_fields = ['id']


class ReportModelSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        return rep

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
        report_player_qs = ReportPlayerModel.objects.filter(report = report_id)
        li=[]
        for i in report_player_qs:
            li.append(i.player)
        rep['players'] = [i.player_name for i in li]
        # rep['industry_name'] = Report.objects.filter(id=instance.report.id)[0].name
        return rep

    class Meta:
        model = ReportAccessModel
        fields = ['id', 'client_id', 'report_id']
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

class ReportPlayerSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['player_name']= Player.objects.filter(player_id = rep['player'])[0].player_name
        rep['report_name']= ReportModel.objects.filter(id = rep['report'])[0].report_name
        return rep

    class Meta:
        model = ReportPlayerModel
        fields = ['player', 'report']
        read_only_fields = ['id']

class IconSerializer(serializers.ModelSerializer):
    class Meta:
        model = IconModel
        fields = ['id', 'name', 'file']
        read_only_fields = ['id']

class ReportPagesSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportPagesModel
        fields =['id','page_name','parent','icon', 'link','order']
        read_only_fields = ['id']
