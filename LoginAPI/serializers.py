# from django.contrib.auth.models import User
from asyncore import read
# from dataclasses import field
import re
from rest_framework.authtoken.models import Token
from rest_framework import serializers
from .models import ClientModel, ReportAccessModel, User, ReportModel, CompanyDomainModel, Player, ReportPagesModel, ReportPlayerModel, IconModel, TagModel, UserPopupModel, NewReportModel, NewReportPagesModel, UserCurrencyModel, NewReportAccessModel, NewReportPageAccessModel, PackageModel

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'phone', 'username', 'password', 'client', 'counter', 'gender_male']
        read_only_fields = ['id']

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        print(user)
        Token.objects.create(user=user)
        return user


class PackageSerializer(serializers.ModelSerializer):
    class Meta:
        model = PackageModel
        fields = '__all__'
        read_only_fields = ['id']

class CompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = ClientModel
        fields = ['id', 'name', 'company_email', 'wildcard_mode']
        read_only_fields = ['id']


class ReportModelSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        request = self.context['request']
        report_player_qs = ReportPlayerModel.objects.filter(report = rep['id'])
        li=[]
        for i in report_player_qs:
            li.append(i.player)
        rep['players'] = [i.player_name for i in li]
        client_id = request.query_params.get('client_id')
        if client_id:
            bought_reports_qs = ReportAccessModel.objects.filter(client_id = client_id)
            for i in bought_reports_qs:
                if int(rep['id']) == int(i.report_id.id):
                    rep['bought'] =True
        # print('rep =',rep)
        return rep

    class Meta:
        model = ReportModel
        fields = ['id', 'report_name']
        read_only_fields = ['id']


class ReportAccessSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        request = self.context['request']
        client_id = request.query_params.get('client_id')
        if client_id:
            # rep['cl_id'] = client_id
            # if rep['client_id'] == int(client_id):
            #     rep['bought'] = True
            # else:
            #     rep['bought'] = False
            print('cid=', client_id)
        else:
            print('no cid')
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
        fields = ['id', 'client_id', 'report_id', 'start_date', 'end_date']
        read_only_fields = ['id']


class CompanyDomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyDomainModel
        fields = ['id', 'client_id', 'domain_name']
        read_only_fields = ['id'] 

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
        fields = [ 'name', 'file']
        read_only_fields = ['id']


class ReportPagesSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['key'] = rep['id']
        rep['label'] = rep['page_name']
        return rep

    class Meta:
        model = ReportPagesModel
        fields =['id','page_name','parent','icon', 'link','order','url', 'powerbi_report_id', 'report_name','same_page']
        read_only_fields = ['id']

class InputSerializer(serializers.Serializer):
        code = serializers.CharField(required=False)
        error = serializers.CharField(required=False)

class TagReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportModel
        fields = ['report_name']


class TagSerializer(serializers.ModelSerializer):

    report_val = TagReportSerializer(source='reports', many=True, read_only=True)

    def to_representation(self, instance):
        # print(instance)
        rep = super().to_representation(instance)
        li = []
        for i in range(len(rep['report_val'])):
            li = li+[rep['report_val'][i]['report_name']]
        rep['reports'] = li
        return rep

    class Meta:
        model = TagModel
        fields = ['id', 'tag_name', 'report_val']
        read_only_fields = ['id']

class UserPopupSerializer(serializers.ModelSerializer):

    def to_representation(self, instance):
        return super().to_representation(instance)

    class Meta:
        model = UserPopupModel
        fields  = ['id', 'name', 'phone', 'email', 'message']
        read_only_fields = ['id']

class NewReportSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        return super().to_representation(instance)

    class Meta:
        model = NewReportModel
        fields = '__all__'
        read_only_fields = ['id']

class PlayerSerializer(serializers.ModelSerializer):
    image = IconSerializer()
    newreport= NewReportSerializer()
    class Meta:
        model = Player
        fields = '__all__'
        read_only_fields = ['player_id'] 

    
class NewReportPagesSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        data = super().to_representation(instance)
        # data['filter_type']= NewReportModel.objects.filter(id = data['report'])[0].filter
        # data['filter_value'] = NewReportModel.objects.filter(id = data['report'])[0].filter_value
        return data

    class Meta:
        model = NewReportPagesModel
        fields = '__all__'
        read_only_fields = ['id']

class UserCurrencySerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        return super().to_representation(instance)

    class Meta:
        model = UserCurrencyModel
        fields = '__all__'
        read_only_fields = ['id']

class NewReportAccessSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['report_name']= NewReportModel.objects.filter(id = rep['report_id'])[0].report_name
        return rep

    class Meta:
        model = NewReportAccessModel
        fields = '__all__'
        read_only_fields = ['id']


class NewReportPageAccessSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        return super().to_representation(instance)

    class Meta:
        model = NewReportPageAccessModel
        fields = '__all__'
        read_only_fields = ['id']

        