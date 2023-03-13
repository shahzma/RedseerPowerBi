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
from rest_framework.views import APIView
from rest_framework import status
from django.urls import reverse
from django.shortcuts import redirect
from urllib.parse import urlencode
from django.core.exceptions import ValidationError
import requests

import pandas as pd
import os
import pymysql
import namegenerator as rng
from openpyxl import workbook

import datetime
from datetime import datetime
from datetime import date
import calendar

import string
import random

import requests
import json
import msal
from dotenv import load_dotenv
import os

load_dotenv()

GOOGLE_ID_TOKEN_INFO_URL = 'https://www.googleapis.com/oauth2/v3/tokeninfo'
GOOGLE_ACCESS_TOKEN_OBTAIN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_USER_INFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo'

CLIENT_ID = 'fc1cef01-9962-458e-a314-4e31a3d10791'
TENANT_ID= '00a9ff8c-9830-4847-ae51-4579ec092cb4'
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
AUTHORITY_URL = 'https://login.microsoftonline.com/{}'.format(TENANT_ID)
RESOURCE_URL = 'https://graph.microsoft.com/'
API_VERSION = 'v1.0'
USERNAME = 'operations@redseerconsulting.com' #Office365 user's account username
PASSWORD = 'BM@OPS@123'
SCOPES = ['Sites.ReadWrite.All','Files.ReadWrite.All'] # Add other scopes/permissions as needed.

#connect to sql server
db = pymysql.connect(
        host=os.getenv("host"),
        port=3306,
        user=os.getenv('user'), 
        password = os.getenv('host_password'),
        db='content_data',
        ssl = {'ssl':{'tls': True}}
        )


def start_end_date(month):
    datetime_object = datetime.strptime(month[:3], "%b")
    month_number = datetime_object.month
    year=month[-2:]
    sd='1.'+str(month_number)+'.'+year
    SD= datetime.strptime(sd,'%d.%m.%y').strftime('%Y-%m-%d')
    end_day=calendar.monthrange(int(SD[:4]),month_number)[1]
    ed=str(end_day)+'.'+str(month_number)+'.'+year
    ED= datetime.strptime(ed,'%d.%m.%y').strftime('%Y-%m-%d')
    return(SD,ED)

def date_conversion(a):
    month_num=a[5:7]
    yr=a[:4]
    datetime_object = datetime.strptime(str(month_num), "%m")
    month_name = datetime_object.strftime("%b")
    month_conv= month_name+"'"+yr
    return month_conv

def date_dict_f(pl_id):
    s="select * from main_data where player_id='"+str(pl_id)+"';"
    cur= db.cursor()
    cur.execute(s)
    d=cur.fetchall()
    cur.close()
    date=pd.DataFrame.from_dict(d)
    if date.empty == False:
        date=date[[2,3]]
        date=date.drop_duplicates(subset={2,3})
        date=date.rename(columns={2:'start_date',3:'end_date'})
        date_dict=date.to_dict(orient='records')
        return date_dict
    else:
        return {}

# function to export different dfs in one excel file having 
def dfs_tabs(df_list, sheet_list, file_name):
    writer = pd.ExcelWriter(file_name,engine='xlsxwriter')   
    for dataframe, sheet in zip(df_list, sheet_list):
        dataframe.to_excel(writer, sheet_name=sheet, startrow=0 , startcol=0, index=False)   
    writer.save()
    
def rand_str():
    N = 7
    res = ''.join(random.choices(string.ascii_uppercase +
                                 string.digits, k=N))
    return res

# cur= db.cursor()

def upload_resumable1(file_name):
    # Creating a public client app, Aquire an access token for the user and set the header for API calls
    cognos_to_onedrive = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY_URL)
    token = cognos_to_onedrive.acquire_token_by_username_password(USERNAME,PASSWORD,SCOPES)
    header = {'Authorization': 'Bearer {}'.format(token['access_token'])}
    # download 
    response = requests.get('{}/{}/me/drive/root:/Product Data Excels (Do not Touch)/Template_for_client_output'.format(RESOURCE_URL,API_VERSION) + '/' + file_name + ':/content', headers=header)

    return response.content

def upload_resumable(local_file_name,file_name):
    # Creating a public client app, Aquire a access token for the user and set the header for API calls
    cognos_to_onedrive = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY_URL)
    token = cognos_to_onedrive.acquire_token_by_username_password(USERNAME,PASSWORD,SCOPES)
    headers = {'Authorization': 'Bearer {}'.format(token['access_token'])}
    
    onedrive_destination = '{}/{}/me/drive/root:/Data backend check/BPC'.format(RESOURCE_URL,API_VERSION)  #onedrive location to upload the local file
    p = os.getenv("loc")+local_file_name
#     p='C:/Users/KajalVerma/OneDrive - Redseer Management Consulting Private Limited/Data backend check/trial/'+local_file_name
    file_data = open(p, 'rb')
    file_path = p
    file_size = os.stat(file_path).st_size

    if file_size < 4100000:
        #Perform is simple upload to the API
        r = requests.put(onedrive_destination+"/"+file_name+":/content", data=file_data, headers=headers)

def download_url(file_name):
    # Creating a public client app, Aquire an access token for the user and set the header for API calls
    cognos_to_onedrive = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY_URL)
    token = cognos_to_onedrive.acquire_token_by_username_password(USERNAME,PASSWORD,SCOPES)
    header = {'Authorization': 'Bearer {}'.format(token['access_token'])}
    # download
    response = requests.get('{}/{}/me/drive/root:/Data backend check/BPC'.format(RESOURCE_URL,API_VERSION) + '/' + file_name + ':/content', headers=header)


    return response.url

def name_dict(req_player):
    pl_name_dict={}
    for pl in req_player:
        s="select player_name from player where player_id='"+str(pl)+"';"
        cur= db.cursor()
        cur.execute(s)
        name=cur.fetchall()
        cur.close()
        name=pd.DataFrame(name)
        req_name=name.iloc[0,0]
        pl_name_dict[pl]=req_name
    return pl_name_dict

def temp_dict(req_player):
    pl_temp_dict={}
    for pl in req_player:
        s="select template_name from player where player_id='"+str(pl)+"';"
        cur= db.cursor()
        cur.execute(s)
        name=cur.fetchall()
        cur.close()
        name=pd.DataFrame(name)
        req_name=name.iloc[0,0]
        pl_temp_dict[pl]=req_name
    return pl_temp_dict

## template required
def req_template(name):
    yls= upload_resumable1(name)
    print('yls = ',yls)
    # if not yls.startswith("~") and yls.endswith(".xlsx"):
    #     print(file)
    df_1=pd.read_excel(yls,"Sheet1", header=None, index_col=False)
    return df_1

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
        client_id = query_params.get("client_id")
        # client_id = 1
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
        # check ifphone exists
        # account_sid = 'AC9bee304dbdd07c29504727cf6726a873'
        account_sid = os.getenv("account_sid")
        auth_token = os.getenv("auth_token")
        # auth_token = '6af5d155c60e9aa0801380cecce6d597'
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
            #             from_='+18775655473',
            #             to='+918791205476'
            #         )
            if mail_status==0:
                return Response({"msg": " Failed to send mail "}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'pseudo_email':company_email, "OTP": OTP, 'client_id':company_client_id, 'unregistered':False}, status=status.HTTP_201_CREATED)
        elif models.User.objects.filter(email=email).exists():
            user = models.User.objects.filter(email=email)
            user_client_id = user[0].client_id
            user_name = user[0].first_name
            print(user[0].first_name)
            client_obj =  models.ClientModel.objects.filter(id=user_client_id)[0]
            company_email = client_obj.company_email
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
            print('email=', email)
            print('mail=',mail_status)
            if False:
                message = twilio_client.messages.create(
                            body=f'Your verification code is 【{OTP}】. It is valid for 3 min',
                            from_='+18775655473',
                            to=str(mobile_num)
                        )
            if mail_status==0:
                return Response({"msg": " Failed to send mail "}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'pseudo_email':company_email, 'client_id':user_client_id, 'unregistered':False, 'user_name':user_name, 'otp_access':client_obj.otp_access}, status=status.HTTP_201_CREATED)
        else:
            company_client_id = 9
            company_email = 'nocompany@redseerconsulting.com'
            counter_val = 0
            hotp = pyotp.HOTP('base32secret3232')
            OTP = hotp.at(counter_val)
            msg = EmailMessage(
                'Login OTP Redseer',
                f'Welcome back User,<br>Your One Time Password (OTP) for Benchmarks login is 【{OTP}】.<br>Please DO NOT share this OTP with anyone.<br>Cheers,<br>Team Benchmarks',
                settings.EMAIL_HOST_USER,
                [email]
            )
            msg.content_subtype = "html"
            mail_status =msg.send()
            print('mail_sent')
            if mail_status==0:
                # incase someone uses invalid email
                return Response({"msg": " Failed to send mail "}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'pseudo_email':company_email, "OTP": OTP, 'client_id':company_client_id, 'unregistered':True}, status=status.HTTP_201_CREATED)
            # return Response({"msg": " Invalid Email "}, status=status.HTTP_400_BAD_REQUEST)

    # This Method verifies the OTP
    def post(self, request):
        totp = pyotp.TOTP('base32secret3232', interval=300)
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
            # username = email.split('@')[0]
            first_name = request.data.get('first_name')
            last_name = request.data.get('last_name')
            phone = '+91'+str(request.data.get('phone'))
            # first_name = 'sam'
            # last_name = 'fisher'
            client_id = 9
            user, created = models.User.objects.get_or_create(username=email, email = email, client_id = client_id, phone=phone, first_name = first_name, last_name = last_name)
            if created:
                user.set_password('123')
                user.save()
                token = Token.objects.create(user=user)
                if hotp.verify(OTP,0):
                    return Response({'token': token.key},  status=status.HTTP_200_OK)
                else:
                    return Response({"msg": " Wrong OTP "}, status=status.HTTP_400_BAD_REQUEST)
            # return Response({"msg": " Invalid Email "}, status=status.HTTP_400_BAD_REQUEST)

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
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = (TokenAuthentication,)
    def get(self, request):
        query_params = self.request.query_params
        report_name = query_params['rep']
        email = query_params['email']
        url = "https://login.microsoftonline.com/common/oauth2/token"
        payload = "grant_type=password\r\n&username=1mg@redseerconsulting.com\r\n&password=Waj179490\r\n&client_id=a9826bb1-7b52-4b3f-80f2-2ffa4d1cd578\r\n&client_secret=cuV8Q~hl7__PcjsvYSxTDHraG4vcMMLTRQRtyceA\r\n&resource=https://analysis.windows.net/powerbi/api"
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
        print('value = ', value)
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

class ReportPageApi(ListCreateAPIView):
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = (TokenAuthentication,)
    def get(self, request):
        rep = self.request.query_params['rep']
        report= models.ReportModel.objects.get(report_name=rep)
        # filter by reort_id and parent-id
        report_pages = models.ReportPagesModel.objects.filter(report_id=report.id).get_descendants(include_self=True)
        serializer = serializers.ReportPagesSerializer(report_pages, many=True)
        # print('serilaizer_data=', serializer.data)
        for i in serializer.data:
            if i['parent']==None:
                i['children_page_name']=[x for x in serializer.data if x['parent']==i['id']]
                i['nodes'] = i['children_page_name']
        # filter out children data from serializer_data and keep only parent. We have already taken children in previous step
        res = [x for x in serializer.data if x['parent']==None]
        return JsonResponse(res, safe=False)

class IconLCView(ListCreateAPIView):
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = (TokenAuthentication,)
    queryset = models.IconModel.objects.all()
    serializer_class = serializers.IconSerializer


class GoogleLoginApi(APIView):

    def get(self, request, *args, **kwargs):
        input_serializer = serializers.InputSerializer(data=request.GET)
        input_serializer.is_valid(raise_exception=True)

        validated_data = input_serializer.validated_data

        code = validated_data.get('code')
        error = validated_data.get('error')

        login_url = f'{settings.BASE_FRONTEND_URL}/login'

        if error or not code:
            print(error)
            params = urlencode({'error': error})
            return redirect(f'{login_url}?{params}')

        domain = settings.BASE_BACKEND_URL
        # api_uri = reverse('api:v1:auth:login-with-google')
        # redirect_uri = f'{domain}{api_uri}'
        # redirect_uri = 'http://localhost:8001/api/v1/auth/login/google/'
        redirect_uri = 'https://api.benchmarks.digital/api/v1/auth/login/google/'
        def google_get_access_token(*, code: str, redirect_uri: str) -> str:
    # Reference: https://developers.google.com/identity/protocols/oauth2/web-server#obtainingaccesstokens
            data = {
                'code': code,
                'client_id': settings.GOOGLE_OAUTH2_CLIENT_ID,
                'client_secret': settings.GOOGLE_OAUTH2_CLIENT_SECRET,
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code'
            }

            response = requests.post(GOOGLE_ACCESS_TOKEN_OBTAIN_URL, data=data)

            if not response.ok:
                raise ValidationError('Failed to obtain access token from Google.')

            access_token = response.json()['access_token']

            return access_token

        def google_get_user_info(*, access_token: str):
            # Reference: https://developers.google.com/identity/protocols/oauth2/web-server#callinganapi
            response = requests.get(
                GOOGLE_USER_INFO_URL,
                params={'access_token': access_token}
            )

            if not response.ok:
                raise ValidationError('Failed to obtain user info from Google.')

            return response.json()

        access_token = google_get_access_token(code=code, redirect_uri=redirect_uri)

        user_data = google_get_user_info(access_token=access_token)

        profile_data = {
            'email': user_data['email'],
            'first_name': user_data.get('givenName', ''),
            'last_name': user_data.get('familyName', ''),
        }
        print(profile_data)
        email = user_data['email']
        email_company_name = email.split('@')[1]
        # 3 cases - C1 = user belongs to company and logging in firsttime
        # C2 = user in database and belongs to some company
        # C3 = user logging in first time and no company
        if models.User.objects.filter(email=email).exists():
            user = models.User.objects.get(email=email)
            user_client_id = user.client_id
            try:
                token = Token.objects.get(user=user)
                if token:
                    user.auth_token.delete()
            except:
                pass
            token = Token.objects.create(user = user)
            print('token=',token)
            company_email = models.ClientModel.objects.filter(id=user_client_id)[0].company_email
            response = redirect(f'https://api.benchmarks.digital/MainPage/?backend_token={token}&client_id={user_client_id}&email={email}&pseudo_email={company_email}')
            return response
        elif models.CompanyDomainModel.objects.filter(domain_name=email_company_name).exists():
            username = email.split('@')[0]
            company_domain_obj = models.CompanyDomainModel.objects.filter(domain_name=email_company_name)
            client_name = company_domain_obj[0].client_id
            company_obj = models.ClientModel.objects.filter(name = client_name)
            company_email = company_obj[0].company_email
            company_client_id = company_obj[0].id
            # client_name = models.CompanyDomainModel.objects.filter(domain_name=email_company_name)[0].client_id
            # company_obj = models.ClientModel.objects.filter(name = client_name)
            company_client_id = company_obj[0].id
            user, created = models.User.objects.get_or_create(username=username, email = email, client_id = company_client_id)
            if created:
                user.set_password('123')
                user.save()
                token = Token.objects.create(user=user)
                response = redirect(f'https://api.benchmarks.digital/MainPage/?backend_token={token}&client_id={company_client_id}&email={email}&pseudo_email={company_email}')
                return response
        else:
            username = email.split('@')[0]
            company_client_id = 9
            company_email = 'nocompany@redseerconsulting.com'
            user, created = models.User.objects.get_or_create(username=username, email = email, client_id = company_client_id)
            if created:
                user.set_password('123')
                user.save()
                token = Token.objects.create(user=user)
                response = redirect(f'https://api.benchmarks.digital/MainPage/?backend_token={token}&client_id={company_client_id}&email={email}&pseudo_email={company_email}')
                return response

class MicrosoftLoginApi(APIView):

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        access_token = request.data.get('access_token')
        url = "https://graph.microsoft.com/v1.0/me"

        payload={}
        headers = {
        'Authorization': f'Bearer {access_token}'
        }

        response = requests.request("GET", url, headers=headers, data=payload)

        print('resp=',response)
        if response.status_code==200:
            email_company_name = email.split('@')[1]
            # 3 cases - C1 = user belongs to company and logging in firsttime
            # C2 = user in database and belongs to some company
            # C3 = user logging in first time and no company
            if models.User.objects.filter(email=email).exists():
                user = models.User.objects.get(email=email)
                user_client_id = user.client_id
                try:
                    token = Token.objects.get(user=user)
                    if token:
                        user.auth_token.delete()
                except:
                    pass
                token = Token.objects.get_or_create(user = user)
                print('token=',type(token[0].key))
                company_email = models.ClientModel.objects.filter(id=user_client_id)[0].company_email
                # response = redirect(f'http://localhost:3000/MainPage/?backend_token={token}&client_id={user_client_id}&email={email}&pseudo_email={company_email}')
                # return response
                return Response({'token':token[0].key,'pseudo_email':company_email, 'client_id':user_client_id}, status=status.HTTP_201_CREATED)
            elif models.CompanyDomainModel.objects.filter(domain_name=email_company_name).exists():
                username = email.split('@')[0]
                company_domain_obj = models.CompanyDomainModel.objects.filter(domain_name=email_company_name)
                client_name = company_domain_obj[0].client_id
                company_obj = models.ClientModel.objects.filter(name = client_name)
                company_email = company_obj[0].company_email
                company_client_id = company_obj[0].id
                # client_name = models.CompanyDomainModel.objects.filter(domain_name=email_company_name)[0].client_id
                # company_obj = models.ClientModel.objects.filter(name = client_name)
                company_client_id = company_obj[0].id
                user, created = models.User.objects.get_or_create(username=username, email = email, client_id = company_client_id)
                if created:
                    user.set_password('123')
                    user.save()
                    token = Token.objects.get_or_create(user=user)
                    print('new_tok=', token)
                    return Response({'token':token[0],'pseudo_email':company_email, 'client_id':company_client_id}, status=status.HTTP_201_CREATED)
            else:
                username = email.split('@')[0]
                company_client_id = 9
                company_email = 'nocompany@redseerconsulting.com'
                user, created = models.User.objects.get_or_create(username=username, email = email, client_id = company_client_id)
                if created:
                    user.set_password('123')
                    user.save()
                    token = Token.objects.create(user=user)
                    print(token)
                    # passand check token value
                    return Response({'token':token.key,'pseudo_email':company_email, 'client_id':company_client_id}, status=status.HTTP_201_CREATED)

class ExcelLinkApi(APIView):
    
    def get(self, request, *args, **kwargs):
        # print('acount_sid=',os.getenv("account_sid"))
        client_id = self.request.query_params['client_id']
        report_name  = self.request.query_params['report_name']
        report_model_object = models.ReportModel.objects.filter(report_name = report_name)[0]
        report_id = report_model_object.id
        print(report_name, report_id, client_id)
        # report_id = 1
        report_access_object = models.ReportAccessModel.objects.filter(client_id = client_id, report_id = report_id)[0]
        player_queryset = report_access_object.players.all()
        start_date = report_access_object.start_date
        end_date = report_access_object.end_date
        company_list=  [i.player_id for i in player_queryset]
        print(company_list)
        def req_output(req_player):
            os.chdir(os.getenv("loc"))
            pl_name_dict=name_dict(req_player)   #makes pl ids and name dict from input player_ids
            pl_temp_dict=temp_dict(req_player)   #makes pl_ids and their corresponding template name dict from input player_ids
            
            dfs=[]
            sheets=[]
            
            for key, value in pl_name_dict.items():
                print(key)
                pl_id=key
                sheet=value
                name=pl_temp_dict[pl_id]
                file_name = name+".xlsx"                     #data File name
                df_1=req_template(file_name)  #current player template
                date_dict=date_dict_f(pl_id)   #date list for the player , coming from function
                # date filter 
                for i in date_dict:
                    if start_date is not None:
                        if str(i.get('start_date'))<str(start_date):
                            try:
                                del(i['start_date'])
                                del(i['end_date'])
                            except:
                                pass
                    if end_date is not None:
                        if str(i.get('end_date'))>str(end_date):
                            try:
                                del(i['start_date'])
                                del(i['end_date'])
                            except:
                                pass
                date_dict = list(filter(None, date_dict))
                #date_filter_end 

                s="select * from main_data where player_id='"+str(pl_id)+"';"
                cur= db.cursor()
                cur.execute(s)
                d=cur.fetchall()
                cur.close()
                dat=pd.DataFrame(d)
                if dat.empty == False:
                    dat=dat[[1,2,3,4,5]]
                    dat=dat.rename(columns={1:"pl_id",2:"start_date",3:"end_date",4:"par_id",5:"value"})
                    dat['start_date']=dat['start_date'].apply(str)
                    dat['end_date']=dat['end_date'].apply(str)
                else:
                    dat = {}
                
                c=3
                df_1[c]=" "
                for i in date_dict:
                    sd=i['start_date']
                    ed=i['end_date']
                    ed=str(ed)
                    sd=str(sd)
                    #print(sd, date_conversion(sd))
                    df_1.iat[0,c]=date_conversion(sd)    #date text conversion
                    N=len(df_1)
                    for j in range(1,N):
                        par_id=df_1.iat[j,0]
                        #print(par_id)
                        if str(par_id)=='nan':
                            continue

                        z=dat[(dat["pl_id"] == pl_id) & (dat["start_date"] == str(sd))& (dat["end_date"] == str(ed))& (dat["par_id"] == par_id)]    
                        if len(z)!=0:
                            val=z.iloc[0,4]
                            #print(val)
                            df_1.iloc[j,c]=val

                    c=c+1
                    df_1[c]=" "
                print(df_1)
                try:
                    df_1.columns = df_1.iloc[0]
                    df_1=df_1.drop(df_1.index[0])
                    df_1 = df_1.drop('par_id', axis=1)

                    dfs.append(df_1)
                except:
                    pass
                sheets.append(sheet)
            
            ran_name=rand_str()
            sheet_ran_name = ran_name+".xlsx"

            dfs_tabs(dfs, sheets, sheet_ran_name)      #it will upload the output file in local location
            
            ran_name2=rand_str()
            final_output_name = ran_name2+".xlsx"
            upload_resumable(sheet_ran_name,final_output_name) #it will upload local to onedrive folder
            download_link=download_url(final_output_name)  #it will give download url for the onedrive excel
            return download_link   
        link = req_output(company_list)

        return Response({'excel_link': link},  status=status.HTTP_200_OK)


class TagLCView(ListCreateAPIView):
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = (TokenAuthentication,)
    queryset = models.TagModel.objects
    serializer_class = serializers.TagSerializer

    # def get_queryset(self):
    #     query_params = self.request.query_params
    #     client_id = query_params.get("client_id")
        
    #     if client_id:
    #         self.queryset = self.queryset.filter(client_id = client_id)
    #     return self.queryset

class UserPopupLCView(ListCreateAPIView):
    queryset = models.UserPopupModel.objects
    serializer_class = serializers.UserPopupSerializer

class NewReportAPI(ListCreateAPIView):

    def get_tree_data(self,nodes):
        data = []
        for node in nodes:
            item = {
                'key': node.pk,
                'label': node.report_name,
                'finalized': node.finalized,
                'filter_value':node.filter_value,
                'filter': node.filter,
                'key_val': node.pk,
                'node_type': node.node_type
            }
            children = node.get_children()
            if children:
                if node.node_type == 'Platform_node':
                    # Skip this node and all its children
                    continue
                item['nodes'] = self.get_tree_data(children)
            else:
                item['nodes'] = []
            data.append(item)
        return data

    def get(self, request):
        # rep = self.request.query_params['rep']
        # need root_node to go anywhere in a tree
        # root_nodes = models.NewReportModel.objects.filter(report_name= rep)
        if 'rep' in self.request.query_params:
            rep = self.request.query_params['rep']
            root_nodes = models.NewReportModel.objects.filter(report_name=rep)
        else:
            root_nodes = models.NewReportModel.objects.filter(parent__isnull=True)

        tree_data = self.get_tree_data(root_nodes)
        res = tree_data
        return JsonResponse(res, safe=False)

class NodeChildrenAPI(APIView):
    def get(self, request, *args, **kwargs):
        key =  self.request.query_params['key']
        node = models.NewReportModel.objects.get(pk=key)

        # get the immediate children of the node
        data = []
        children = node.get_children()
        # iterate over the children
        for child_node in children:
            if child_node.node_type == 'Platform_node':
                platform_children = child_node.get_children()
                for platform_child in platform_children:
                    # create a dictionary containing the relevant attributes of the platform child node
                    platform_child_data = {
                        'key': platform_child.pk,
                        'label': platform_child.report_name,
                        'finalized': platform_child.finalized,
                        'filter_value':platform_child.filter_value,
                        'filter': platform_child.filter,
                        'key_val': platform_child.pk,
                        'name': platform_child.report_name,
                        'value': platform_child.report_name
                    }
                    # append the platform child node data to the data list
                    data.append(platform_child_data)

            # do something with each child node
            else:
                child_data = {
                    'key': child_node.pk,
                    'label': child_node.report_name,
                    'finalized': child_node.finalized,
                    'filter_value':child_node.filter_value,
                    'filter': child_node.filter,
                    'key_val': child_node.pk,
                    'name': child_node.report_name,
                    'value': child_node.report_name
                }
                # append the child node data to the data list
                data.append(child_data)
        return JsonResponse(data, safe=False)


class NewReportPagesLCView(ListCreateAPIView):
    queryset = models.NewReportPagesModel.objects
    serializer_class = serializers.NewReportPagesSerializer


    def get_queryset(self):
        report_id =  models.NewReportModel.objects.filter(report_name = self.request.query_params['rep'])[0]
        res = self.queryset.filter(report = report_id)
        ans = []
        for j in range(len(res)):
            if res[j].url and res[j].powerbi_report_id  and res[j].report_name:
                report_name = res[j].report_name
                email = 'digital@redseerconsulting.com'
                url = "https://login.microsoftonline.com/common/oauth2/token"
                payload = "grant_type=password\r\n&username=1mg@redseerconsulting.com\r\n&password=Waj179490\r\n&client_id=a9826bb1-7b52-4b3f-80f2-2ffa4d1cd578\r\n&client_secret=cuV8Q~hl7__PcjsvYSxTDHraG4vcMMLTRQRtyceA\r\n&resource=https://analysis.windows.net/powerbi/api"
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
                # print('value = ', value)
                report_id = 0
                report_url = ''
                report_datasetId = 0
                for i in value:
                    if i['name']==report_name:
                        # print('i=', i)
                        report_id = i['id']
                        report_url = i['embedUrl']
                        report_datasetId = i['datasetId']
                # print(report_id)
                # print('report_datasetid=',report_datasetId)
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
                print(res[j])
                res[j].embed=embed_token
                res[j].save()
        return res


class NewReportAccessTree(ListCreateAPIView):
    queryset = models.NewReportAccessModel.objects
    serializer_class = serializers.NewReportAccessSerializer
    def get(self, request):
        client_id  = self.request.query_params['client_id']
        if client_id:
            self.queryset = self.queryset.filter(client_id = client_id)
        return self.queryset


class UserCurrencyLCView(ListCreateAPIView):
    queryset = models.UserCurrencyModel.objects
    serializer_class = serializers.UserCurrencySerializer

    def get_queryset(self):
        query_params = self.request.query_params
        email = query_params.get("email")
        if email:
            self.queryset = self.queryset.filter(email = email)
        return self.queryset

    def create(self, request, *args, **kwargs):
        data = request.data
        print(data)
        try:
            user_curr_obj = models.UserCurrencyModel.objects.get(email = data['email'], report = data['report'])
            if data.get('currency'):
                user_curr_obj.currency = data['currency']
            if data.get('year'):
                user_curr_obj.year = data['year']
            user_curr_obj.save()
        except:
            user_curr_obj = models.UserCurrencyModel.objects.create(email = data['email'], report = data['report'], currency = data['currency'], year = data['year'])
            user_curr_obj.save()
        serializer = serializers.UserCurrencySerializer(user_curr_obj)
        return Response(serializer.data)

class NewReportAccessLCView(ListCreateAPIView):
    queryset = models.NewReportAccessModel.objects
    serializer_class = serializers.NewReportAccessSerializer

    def get_queryset(self):
        query_params = self.request.query_params
        client_id = query_params.get("client_id")
        # client_id = 1
        if client_id:
            # self.queryset = self.queryset.filter(client__id = client_id)
            self.queryset = self.queryset.filter(client_id = client_id)
        return self.queryset
    
class NewReportPageAccessLCView(ListCreateAPIView):
    queryset = models.NewReportPageAccessModel.objects
    serializer_class = serializers.NewReportPageAccessSerializer