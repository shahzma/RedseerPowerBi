from os import access
from django.http import JsonResponse
from django.shortcuts import render
from . import models, serializers
from rest_framework import viewsets
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView, CreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
import pyotp
from django.core.mail import send_mail
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.views import status
from django.conf import settings
from twilio.rest import Client
import requests
import json


# Create your views here.
class UserViewSet(viewsets.ModelViewSet):
    queryset = models.User.objects.all()
    serializer_class = serializers.UserSerializer

class CompanyLCView(ListCreateAPIView):
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = (TokenAuthentication,)
    queryset = models.ClientModel.objects
    serializer_class = serializers.CompanySerializer

class ReportLCView(ListCreateAPIView):
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = (TokenAuthentication,)
    queryset = models.ReportModel.objects
    serializer_class = serializers.ReportModelSerializer

class ReportAccessLCView(ListCreateAPIView):
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = (TokenAuthentication,)
    queryset = models.ReportAccessModel.objects
    serializer_class = serializers.ReportAccessSerializer

    def get_queryset(self):
        query_params = self.request.query_params
        email = query_params.get("email")
        if email:
            self.queryset = self.queryset.filter(email=email)
        return self.queryset

class ReportAccessRUDView(RetrieveUpdateDestroyAPIView):
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = (TokenAuthentication,)
    queryset = models.ReportAccessModel.objects
    serializer_class = serializers.ReportAccessSerializer
    lookup_field = 'id'

class CompanyDomainLCView(ListCreateAPIView):
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = (TokenAuthentication,)
    serializer_class = serializers.CompanyDomainSerializer
    queryset = models.CompanyDomainModel.objects


class LoginApi(CreateAPIView):
    # get otp  and send it to user when he clicks submit. OTP valid for  minutes
    def get(self, request):
        # check i fphone exists
        account_sid = 'AC9bee304dbdd07c29504727cf6726a873'
        auth_token = 'df9ff816bb20c46eef8fa0a16347823b'
        # twilio_client = Client(account_sid, auth_token)
        totp = pyotp.TOTP('base32secret3232', interval=240)
        OTP = totp.now()
        print('genratedOTP = ',OTP)
        email = self.request.query_params.get('email')
        email_company_name = email.split('@')[1].split('.')[0]
        # check if email is in user database or in company database or nowhere, we are checking company first
        # bcoz after 1st login user will be registred in usertable and hence will not be able to see campany aceess report
        if models.CompanyDomainModel.objects.filter(domain_name=email_company_name).exists():
            company_domain_obj = models.CompanyDomainModel.objects.filter(domain_name=email_company_name)
            client_id = company_domain_obj[0].client_id
            print('client_id = ',client_id)
            company_obj = models.ClientModel.objects.filter(name = client_id)
            company_email = company_obj[0].company_email
            mail_status = send_mail(subject='Login OTP Redseer', message=f'Welcome Back User, Your One Time Password (OTP) for Benchmarks login is 【{OTP}】.Please DO NOT share this OTP with anyone.',from_email=settings.EMAIL_HOST_USER,recipient_list = [email], fail_silently=False)
            # mail_status = send_mail(subject='Login OTP Redseer', message=f' Your verification code is 【{OTP}】. It is valid for 3 min .',from_email=settings.EMAIL_HOST_USER,recipient_list = [email], fail_silently=False)
            # message = twilio_client.messages.create(
            #             body=f'Your verification code is 【{OTP}】. It is valid for 3 min',
            #             from_='+19705577581',
            #             to='+918791205476'
            #         )
            if mail_status==0:
                return Response({"msg": " Failed to send mail "}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'company_pseudo_email':company_email, "OTP": OTP}, status=status.HTTP_201_CREATED)
        elif models.User.objects.filter(email=email).exists():
            # mail_status = send_mail(subject='Login OTP Redseer', message=f' Your verification code is 【{OTP}】. It is valid for 3 min .',from_email=settings.EMAIL_HOST_USER,recipient_list = [email], fail_silently=False)
            mail_status = send_mail(subject='Login OTP Redseer', message=f'Welcome Back User, Your One Time Password (OTP) for Benchmarks login is 【{OTP}】.Please DO NOT share this OTP with anyone.',from_email=settings.EMAIL_HOST_USER,recipient_list = [email], fail_silently=False)
            # message = twilio_client.messages.create(
            #             body=f'Your verification code is 【{OTP}】. It is valid for 3 min',
            #             from_='+19705577581',
            #             to='+918791205476'
            #         )
            if mail_status==0:
                return Response({"msg": " Failed to send mail "}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"msg": f" The verification code has been sent to {email} Send complete .OTP = {OTP}"}, status=status.HTTP_201_CREATED)
        else:
            return Response({"msg": " Invalid Email "}, status=status.HTTP_400_BAD_REQUEST)

    # This Method verifies the OTP
    def post(self, request):
        totp = pyotp.TOTP('base32secret3232', interval=240)
        OTP = request.data.get('OTP')
        print('recieved otp = ',OTP)
        email = request.data.get('email')
        email_company_name = email.split('@')[1].split('.')[0]
        if models.User.objects.filter(email=email).exists():
            user = models.User.objects.get(email=email)
            if totp.verify(OTP):
                token = Token.objects.get(user=user) #getorcreate
                # check if user is already logged in
                return Response({'token': token.key},  status=status.HTTP_200_OK)
            else:
                return Response({"msg": " Wrong OTP "}, status=status.HTTP_400_BAD_REQUEST)
        elif models.CompanyDomainModel.objects.filter(domain_name=email_company_name).exists():
            # get or create user and corresponding token. check if username exists and convert it
            username = email.split('@')[0]
            user, created = models.User.objects.get_or_create(username=username, email = email)
            if created:
                user.set_password('123')
                user.save()
                token = Token.objects.create(user=user)
                if totp.verify(OTP):
                    return Response({'token': token.key},  status=status.HTTP_200_OK)
                else:
                    return Response({"msg": " Wrong OTP "}, status=status.HTTP_400_BAD_REQUEST)
            # else:
            #     token = Token.objects.get(user=user)
            #     if OTP == 2704:
            #         return Response({'token': token.key},  status=status.HTTP_200_OK)
            #     else:
            #         return Response({"msg": " Wrong OTP "}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"msg": " Invalid Email "}, status=status.HTTP_400_BAD_REQUEST)


class MSAccessTokenAPI(CreateAPIView):
    def get(self, request):
        query_params = self.request.query_params
        report_name = query_params['rep']
        # report_name = 'OTT_Audio'
        print('report_name=', report_name)
        # url = "https://login.microsoftonline.com/common/oauth2/token"

        # payload = "grant_type=password\r\n&username=shahzma@redseermanagement.onmicrosoft.com\r\n&password=Redseer@2022\r\n&client_id=02400d3c-8927-4b2c-b339-66ea70f63810\r\n&client_secret=50~8Q~z4-HPZRuIQCQ170E1w9ZdKEydV9~ICoblD\r\n&resource=https://analysis.windows.net/powerbi/api"
        # headers = {
        # 'Content-Type': 'application/x-www-form-urlencoded',
        # 'Cookie': 'fpc=Aus9rQPMtNtLkL7XzywalRKHPumoAQAAAHfFadoOAAAA; stsservicecookie=estsfd; x-ms-gateway-slice=estsfd'
        # }
        url = "https://login.microsoftonline.com/common/oauth2/token"
        payload = "grant_type=password\r\n&username=test@redseerconsulting.com\r\n&password=Waj179490\r\n&client_id=a9826bb1-7b52-4b3f-80f2-2ffa4d1cd578\r\n&client_secret=kIb8Q~EYAnhv274vUvwWjAVIbEiFSR5ENjhavcNe\r\n&resource=https://analysis.windows.net/powerbi/api"
        headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': 'fpc=Aus9rQPMtNtLkL7XzywalRLdloFgAQAAABHzetoOAAAA; stsservicecookie=estsfd; x-ms-gateway-slice=estsfd'
        }
        response = requests.request("POST", url, headers=headers, data=payload)
        response = response.json()
        access_token = response["access_token"]

        # workspace_url = "https://api.powerbi.com/v1.0/myorg/groups/d786d974-91ce-43e8-a52c-c0e6b402f74f/reports/"
        # workspace_payload={}
        # workspace_headers = {
        # 'Authorization': f'Bearer {access_token}'
        # }

        workspace_url = "https://api.powerbi.com/v1.0/myorg/groups/67294232-0c81-43c2-a16d-22544a0a390b/reports/"
        workspace_payload={}
        workspace_headers = {
        'Authorization': f'Bearer {access_token}'
        }

        response = requests.request("GET", workspace_url, headers=workspace_headers, data=workspace_payload)
        value=response.json()['value']
        report_id = 0
        report_url = ''
        for i in value:
            if i['name']==report_name:
                report_id = i['id']
                report_url = i['embedUrl']
        print(report_id)
        embed_url = f"https://api.powerbi.com/v1.0/myorg/groups/67294232-0c81-43c2-a16d-22544a0a390b/reports/{report_id}/GenerateToken"
        embed_payload = json.dumps({
        "accessLevel": "View",
        "allowSaveAs": "false"
        })
        embed_headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
        }
        response = requests.request("POST", embed_url, headers=embed_headers, data=embed_payload)
        print('response=', response)
        embed_token = response.json()['token']

        page_url = f"https://api.powerbi.com/v1.0/myorg/reports/{report_id}/pages"

        page_payload = ""
        page_headers = {
        'Authorization': f'Bearer {access_token}'
        }

        response = requests.request("GET", page_url, headers=page_headers, data=page_payload).json()
        response_val = response['value'][:14]
        return Response({'access_token':access_token , 'embed_token':embed_token, 'report_url':report_url,'report_id':report_id ,'pages':response_val}, status=status.HTTP_201_CREATED)
        # return Response({'access_token':access_token, 'embed_token':embed_token}, status=status.HTTP_201_CREATED)



class PlayerLCView(ListCreateAPIView):
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = (TokenAuthentication,)
    serializer_class = serializers.PlayerSerializer
    queryset = models.Player.objects

class ReportPlayerLCView(ListCreateAPIView):
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = (TokenAuthentication,)
    serializer_class = serializers.ReportPlayerSerializer
    queryset = models.ReportPlayerModel.objects

    # def get_queryset(self):
    #     return self.queryset.filter(report = self.request.query_params['report_id'])

class ReportPageApi(CreateAPIView):
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = (TokenAuthentication,)
    def get(self, request):
        rep = self.request.query_params['rep']
        report= models.ReportModel.objects.get(report_name=rep)
        # filter by reort_id and parent-id
        report_pages = models.ReportPagesModel.objects.filter(report_id=report.id).get_descendants(include_self=True)
        serializer = serializers.ReportPagesSerializer(report_pages, many=True)
        for i in serializer.data:
            if i['parent']==None:
                i['children_page_name']=[x for x in serializer.data if x['parent']==i['id']]
        res = [x for x in serializer.data if x['parent']==None]
        return JsonResponse(res, safe=False)

class IconLCView(ListCreateAPIView):
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = (TokenAuthentication,)
    queryset = models.IconModel.objects.all()
    serializer_class = serializers.IconSerializer