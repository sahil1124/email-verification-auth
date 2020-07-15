from django.shortcuts import render
from rest_framework import generics,status,views
from .serializers import RegisterSerializer,EmailVerificationSerializer,LoginSerializer
from rest_framework.response import  Response
from .models import User
from rest_framework_simplejwt.tokens import RefreshToken
import jwt
from.utils import Util

from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse

from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


# Create your views here.

class RegisterView(generics.GenericAPIView):

    serializer_class=RegisterSerializer

    def post(self,request):
        user=request.data
        serializer=self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user_data=serializer.data

        user=User.objects.get(email=user_data['email'])

        token=RefreshToken.for_user(user).access_token

        current_site=get_current_site(request).domain
        relativeLink=reverse('email-verify')


        absurl="http://"+current_site+relativeLink+"?token="+str(token)
        email_body= 'Hi ' + user.username + ' Use link below to verify your Email \n'+ absurl
        data={'email_body':email_body, 'to_email':user.email, 'email_subject':'verify your Email'}

        Util.send_email(data)

        return Response(user_data,status=status.HTTP_201_CREATED)


class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer

    token_param_config=openapi.Parameter('token',in_=openapi.IN_QUERY,description='Description',type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self,request):
        token=request.GET.get('token')
        try:
            payload = jwt.decode(token,settings.SECRET_KEY)
            user=User.objects.get(id=payload['user_id'])

            if not user.is_verify:
                user.is_verify = True
                user.save()

            return Response({'email':'Successfully Activated'},status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError as identifier:
            return Response({'error':'Activation Expired'},status=status.HTTP_400_BAD_REQUEST)

        except jwt.exceptions.DecodeError as identifier:
            return Response({'error':'Invalid Token'},status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    serializer_class=LoginSerializer
    def post(self,request):
        user=request.data
        serializer=self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data,status=status.HTTP_200_OK)
