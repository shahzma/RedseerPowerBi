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

GOOGLE_ID_TOKEN_INFO_URL = 'https://www.googleapis.com/oauth2/v3/tokeninfo'
GOOGLE_ACCESS_TOKEN_OBTAIN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_USER_INFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo'

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
                return Response({'pseudo_email':company_email, "OTP": OTP, 'client_id':company_client_id, 'unregistered':False}, status=status.HTTP_201_CREATED)
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
                return Response({'pseudo_email':company_email, 'client_id':user_client_id, 'unregistered':False}, status=status.HTTP_201_CREATED)
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
        redirect_uri = 'http://localhost:8001/api/v1/auth/login/google/'
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
            response = redirect(f'http://localhost:3000/MainPage/?backend_token={token}&client_id={user_client_id}&email={email}&pseudo_email={company_email}')
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
                response = redirect(f'http://localhost:3000/MainPage/?backend_token={token}&client_id={company_client_id}&email={email}&pseudo_email={company_email}')
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
                response = redirect(f'http://localhost:3000/MainPage/?backend_token={token}&client_id={company_client_id}&email={email}&pseudo_email={company_email}')
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
