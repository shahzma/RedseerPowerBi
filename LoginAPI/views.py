# from django.contrib.auth.signals import user_logged_in
# from django.contrib.auth import authenticate, login, logout
from http import client
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
from django.core.mail import EmailMessage



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
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)
    queryset = models.ReportAccessModel.objects
    serializer_class = serializers.ReportAccessSerializer

    def get_queryset(self):
        query_params = self.request.query_params
        client_id = query_params.get("client_id")
        if client_id:
            # self.queryset = self.queryset.filter(client__id = client_id)
            self.queryset = self.queryset.filter(client_id = client_id)
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
        auth_token = '6af5d155c60e9aa0801380cecce6d597'
        twilio_client = Client(account_sid, auth_token)
        # totp = pyotp.TOTP('base32secret3232', interval=240)
        # OTP = totp.now()
        # counter_val = 
        # hotp = pyotp.HOTP('base32secret3232')
        # OTP = hotp.at(counter_val)
        # print('genratedOTP = ',OTP)
        email = self.request.query_params.get('email')
        email_company_name = email.split('@')[1]
        # check if email is in user database or in company database or nowhere, we are checking company first
        # bcoz after 1st login user will be registred in usertable and hence will not be able to see campany aceess report
        # company domian model corresponds to wildcad entry
        if models.CompanyDomainModel.objects.filter(domain_name=email_company_name).exists():
            totp = pyotp.TOTP('base32secret3232', interval=300)
            OTP = totp.now()
            print('genratedOTP = ',OTP)
            company_domain_obj = models.CompanyDomainModel.objects.filter(domain_name=email_company_name)
            client_name = company_domain_obj[0].client_id
            company_obj = models.ClientModel.objects.filter(name = client_name)
            company_email = company_obj[0].company_email
            company_client_id = company_obj[0].id
            print('comp_client_id=', company_client_id)
            print('comp_email=',company_email)
            msg = EmailMessage(
                'Login OTP Redseer',
                f'Welcome back User,<br>Your One Time Password (OTP) for Benchmarks login is 【{OTP}】.<br>Please DO NOT share this OTP with anyone.<br>Cheers,<br>Team Benchmarks',
                settings.EMAIL_HOST_USER,
                [email]
            )
            msg.content_subtype = "html"
            mail_status =msg.send()
            print('mail_sent')
            # mail_status = send_mail(subject='Login OTP Redseer', message=f'Welcome Back User, Your One Time Password (OTP) for Benchmarks login is 【{OTP}】.Please DO NOT share this OTP with anyone.',from_email=settings.EMAIL_HOST_USER,recipient_list = [email], fail_silently=False)
            # message = twilio_client.messages.create(
            #             body=f'Your verification code is 【{OTP}】. It is valid for 3 min',
            #             from_='+19705577581',
            #             to='+918791205476'
            #         )
            if mail_status==0:
                return Response({"msg": " Failed to send mail "}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'pseudo_email':company_email, "OTP": OTP, 'client_id':company_client_id}, status=status.HTTP_201_CREATED)
        elif models.User.objects.filter(email=email).exists():
            user = models.User.objects.filter(email=email)
            user_client_id = user[0].client_id
            company_email = models.ClientModel.objects.filter(id=user_client_id)[0].company_email
            print('company_email=', company_email)
            counter_val = user[0].counter
            hotp = pyotp.HOTP('base32secret3232')
            OTP = hotp.at(counter_val)
            print('genratedOTP = ',OTP)
            user = user[0]
            user.counter+=1
            user.save()
            mobile_num = user.phone
            msg = EmailMessage(
                'Login OTP BenchMarks',
                f'Welcome Back User, <br><br> Your One Time Password (OTP) for Benchmarks login is 【{OTP}】.<br>Please DO NOT share this OTP with anyone.<br><br>Cheers,<br>Team Benchmarks',
                settings.EMAIL_HOST_USER,
                [email]
            )
            msg.content_subtype = "html"
            mail_status = msg.send()
            # if mobile_num:
            #     message = twilio_client.messages.create(
            #                 body=f'Your verification code is 【{OTP}】. It is valid for 3 min',
            #                 from_='+18775655473',
            #                 to=str(mobile_num)
            #             )
            if mail_status==0:
                return Response({"msg": " Failed to send mail "}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'pseudo_email':company_email, 'client_id':user_client_id}, status=status.HTTP_201_CREATED)
        else:
            return Response({"msg": " Invalid Email "}, status=status.HTTP_400_BAD_REQUEST)

    # This Method verifies the OTP
    def post(self, request):
        totp = pyotp.TOTP('base32secret3232', interval=240)
        hotp = pyotp.HOTP('base32secret3232')
        OTP = request.data.get('OTP')
        print('recieved otp = ',OTP)
        email = request.data.get('email')
        email_company_name = email.split('@')[1]
        if models.User.objects.filter(email=email).exists():
            user = models.User.objects.get(email=email)
            if hotp.verify(OTP, (user.counter)-1):
                # check if session corresponding to this user exits if it does delete that and make new session
                # check for session key?. if get works then delete that token and create a new one
                # token = Token.objects.get_or_create(user=user) #getorcreate
                # print('token=', token)
                try:
                    token = Token.objects.get(user=user)
                    if token:
                        user.auth_token.delete()
                except:
                    pass
                token = Token.objects.create(user = user)
                print('token=',token)
                # check if user is already logged in
                return Response({'token': token.key},  status=status.HTTP_200_OK)
            else:
                return Response({"msg": " Wrong OTP "}, status=status.HTTP_400_BAD_REQUEST)
        elif models.CompanyDomainModel.objects.filter(domain_name=email_company_name).exists():
            # get or create user and corresponding token. check if username exists and convert it
            username = email.split('@')[0]
            client_name = models.CompanyDomainModel.objects.filter(domain_name=email_company_name)[0].client_id
            company_obj = models.ClientModel.objects.filter(name = client_name)
            company_client_id = company_obj[0].id
            user, created = models.User.objects.get_or_create(username=username, email = email, client_id = company_client_id)
            if created:
                user.set_password('123')
                user.save()
                token = Token.objects.create(user=user)
                if totp.verify(OTP):
                    return Response({'token': token.key},  status=status.HTTP_200_OK)
                else:
                    return Response({"msg": " Wrong OTP "}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"msg": " Invalid Email "}, status=status.HTTP_400_BAD_REQUEST)

# make it so that invalid previous token  does not log out current token
class LogOutApi(CreateAPIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)
    def get(self,request):
        email = self.request.query_params.get('email')
        user = models.User.objects.get(email=email)
        if user.auth_token:
            user.auth_token.delete()
        return Response({'Logged_Out': True},  status=status.HTTP_200_OK)

class ValidateCurrentToken(CreateAPIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)
    def get(self, request):
        email = self.request.query_params.get('email')
        user = models.User.objects.get(email=email)
        curr_token = Token.objects.get(user=user)
        print("curr_token=", curr_token)
        return Response({'Current_token': True},  status=status.HTTP_200_OK)

class MSAccessTokenAPI(CreateAPIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)
    def get(self, request):
        query_params = self.request.query_params
        report_name = query_params['rep']
        email = query_params['email']
        url = "https://login.microsoftonline.com/common/oauth2/token"
        payload = "grant_type=password\r\n&username=digital@redseerconsulting.com\r\n&password=Waj179490\r\n&client_id=a9826bb1-7b52-4b3f-80f2-2ffa4d1cd578\r\n&client_secret=kIb8Q~EYAnhv274vUvwWjAVIbEiFSR5ENjhavcNe\r\n&resource=https://analysis.windows.net/powerbi/api"
        headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': 'fpc=Aus9rQPMtNtLkL7XzywalRLdloFgAQAAABHzetoOAAAA; stsservicecookie=estsfd; x-ms-gateway-slice=estsfd'
        }
        response = requests.request("POST", url, headers=headers, data=payload)
        response = response.json()
        access_token = response["access_token"]

        workspace_url = "https://api.powerbi.com/v1.0/myorg/groups/67294232-0c81-43c2-a16d-22544a0a390b/reports/"
        workspace_payload={}
        workspace_headers = {
        'Authorization': f'Bearer {access_token}'
        }

        response = requests.request("GET", workspace_url, headers=workspace_headers, data=workspace_payload)
        value=response.json()['value']
        report_id = 0
        report_url = ''
        report_datasetId = 0
        for i in value:
            if i['name']==report_name:
                print('i=', i)
                report_id = i['id']
                report_url = i['embedUrl']
                report_datasetId = i['datasetId']
        print(report_id)
        print('report_datasetid=',report_datasetId)
        embed_url = f"https://api.powerbi.com/v1.0/myorg/groups/67294232-0c81-43c2-a16d-22544a0a390b/reports/{report_id}/GenerateToken"
        embed_payload = json.dumps({
        "accessLevel": "View",
        "allowSaveAs": "false",
         "identities": [{
        "userpricipalname": "user",
        "username":email,
        "roles": ["Client_Dynamic_RLS"],
        "datasets": [report_datasetId]
        }]
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


class PlayerLCView(ListCreateAPIView):
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = (TokenAuthentication,)
    serializer_class = serializers.PlayerSerializer
    queryset = models.Player.objects
    def get(self,request):
        name = self.request.query_params.get('name')
        print(name)
        player = models.Player.objects.get(player_name=name)
        return Response({'powerbi_page': player.powerbi_page},  status=status.HTTP_200_OK)

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