from django.http import HttpResponse
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework import permissions
from rest_framework import status
from rest_framework.response import Response
import requests
import json
# from libraryapp.models import mongo_client
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from .serializer import BaseUserSerializer,BaseUserCreateSerializer,BaseUserUpdateSerializer,BooksSerializer
from .models import BaseUser,Books
from rest_framework import status, viewsets
import libraryapp.utils as ui_utils
import re
from django.core.exceptions import PermissionDenied
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from datetime import datetime
from django.http import JsonResponse

class PublicEndpoint(permissions.BasePermission):
    def has_permission(self, request, view):
        return True


class UserViewSet(viewsets.ViewSet):
    """
    A View set for handling all the user related logic
    """
    authentication_classes = []
    permission_classes = []

    def retrieve(self, request, pk=None):
        """
        The API is only used to fetch one User object by user id.
        Args:
            request: The request body
            pk: The pk of BaseUser table

        Returns: a User object
        """
        class_name = self.__class__.__name__
        try:
            user = BaseUser.objects.get(pk=pk)
            serializer = BaseUserSerializer(user)
            return ui_utils.handle_response(class_name, data=serializer.data, success=True)
        except ObjectDoesNotExist as e:
            return ui_utils.handle_response(class_name, data=pk, exception_object=e)
        except Exception as e:
            return ui_utils.handle_response(class_name, exception_object=e, request=request)

    def update(self, request, pk=None):
        """
        API used to update one single user. The API does not update a password for a user, though you have to
        provide password in the request body. There is a separate api for updating password of the user.
        Args:
            request: A request body
            pk: pk value

        Returns: updated one object

        """
        class_name = self.__class__.__name__
        try:
            user = BaseUser.objects.get(pk=pk)
            serializer = BaseUserUpdateSerializer(user, data=request.data)
            if serializer.is_valid():
                user = serializer.save()
                return ui_utils.handle_response(class_name, data=serializer.data, success=True)
            return ui_utils.handle_response(class_name, data=serializer.errors)
        except ObjectDoesNotExist as e:
            return ui_utils.handle_response(class_name, data=pk, exception_object=e)
        except Exception as e:
            return ui_utils.handle_response(class_name, exception_object=e, request=request)

    def create(self, request):
        """
        Create one single user
        Args:
            request:  Request body

        Returns: created user
        """
        class_name = self.__class__.__name__
        
        data = request.data
        password = data['password']
        
        serializer = BaseUserCreateSerializer(data=data)
        #del serializer._id
        #data["_id"]=1
        #print(serializer)        #
        user1={}
        if validate_password(password) == 0:
            return ui_utils.handle_response(class_name, data='password should have 8 chars including a capital'
                                                                'and a special char', success=False)
        if serializer.is_valid():
            print(serializer)
            print("sdjcudcuhdbcuhdbcuh\n\n\n")
            
            user = serializer.save()
            print("sdjcudcuhdbcuhdbcu")
            refresh = RefreshToken.for_user(user)
            user1["token"]=str(refresh)
            user1["accesstoken"]=str(refresh.access_token)
            print(user1)
            return ui_utils.handle_response(class_name, data=user1, success=True)
        return ui_utils.handle_response(class_name, data=serializer.errors)
        # except Exception as e:
        #     return ui_utils.handle_response(class_name, exception_object=e, request=request)

    def list(self, request):
        """
        list all users in the system
        Args:
            request: The request body

        Returns: list all users

        """
        class_name = self.__class__.__name__
        try:
            if request.user.is_superuser:
                users = BaseUser.objects.all()
            else:
                organisation_id = request.query_params.get('organisation_id',None)
                users = []
                if organisation_id:
                    users = BaseUser.objects.filter(profile__organisation=organisation_id)
            serializer = BaseUserSerializer(users, many=True)
            return ui_utils.handle_response(class_name, data=serializer.data, success=True)
        except Exception as e:
            return ui_utils.handle_response(class_name, exception_object=e, request=request)

    def destroy(self, request, pk=None):
        """
        Deletes a single user
        Args:
            request: The Request body
            pk: pk value

        Returns: pk of object which got deleted

        """
        class_name = self.__class__.__name__
        try:
            BaseUser.objects.get(pk=pk).delete()
            return ui_utils.handle_response(class_name, data=pk, success=True)
        except ObjectDoesNotExist as e:
            return ui_utils.handle_response(class_name, data=pk, exception_object=e)
        except Exception as e:
            return ui_utils.handle_response(class_name, exception_object=e, request=request)

    
    def change_password(self, request, pk=None):
        """
        This API must be used only to change password of the user.
        Args:
            request: Request method
            pk: pk value
        Returns: changes the password of the BaseUser instance and returns a success message

        """
        class_name = self.__class__.__name__
        try:
            user = BaseUser.objects.get(pk=pk)
            new_password = request.data['password']
            password_valid = validate_password(new_password)
            # if not user.is_superuser:
            # old_input_password = request.data['old_password']
            # if not user.check_password('{}'.format(old_input_password)):
            #     return ui_utils.handle_response(class_name, data='Your Old Password is wrong', success=False)
            if password_valid == 1:
                user.set_password(new_password)
                user.save()
                return ui_utils.handle_response(class_name, data='Password changed successfully', success=True)
            else:
                return ui_utils.handle_response(class_name, data='Please make sure to have at least 1 capital letter, 1 small letter, 1 special character and minimum 8 characters.', success=False)
        except ObjectDoesNotExist as e:
            return ui_utils.handle_response(class_name, data=pk, exception_object=e)
        except Exception as e:
            return ui_utils.handle_response(class_name, exception_object=e, request=request)

def validate_password(new_password):
    # used to check whether the new password is strong enough
    valid = 1
    # if not any(x.isupper() for x in new_password):
    #     valid = 0
    # if re.match("[^a-zA-Z0-9_]", new_password):
    #     valid = 0
    if len(new_password)<8:
        valid = 0
    elif not re.search("[a-z]", new_password):         #Password should have lowercase letters.
        valid = 0
    elif not re.search("[A-Z]", new_password):         #Password should have uppercase letters.
        valid = 0
    elif not re.search("[0-9]", new_password):         #Password should have numbers.
        valid = 0
    elif not re.search("[_@$#%&*]", new_password):     #Password should have special characters like _ @ $ # % & *
        valid = 0
    elif re.search("\s", new_password):                #Password should not contain spaces.
        valid = 0
    return valid


class BooksClass(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    print("ddc",authentication_classes)
    def get(self, request):
        class_name = self.__class__.__name__
        data = Books.objects.filter()
        obj = BooksSerializer(data=data, many=True)
        if obj.is_valid():
            print(obj)
        else:
            print(obj.errors)
        #print(obj)
        return ui_utils.handle_response({}, data=obj.data, success=True) 

    def post(self, request):
        class_name = self.__class__.__name__
        data=request.data
        if request.user.usertype=="lib":
            
            data1 = Books.objects.create(
                    name=data.get("name"),author=data.get("author"),status=data.get("status"),added_by=request.user,created_time=datetime.now(),updated_time=datetime.now())
            return ui_utils.handle_response(class_name,data=data,success=True)
           
        return ui_utils.handle_response("You dont have right permissions to access the Api",success=False)
    
    def put(self, request):
        bookid=request.query_params.get("book_id")
        if request.user.usertype=="lib":
            data=request.data
            
            data["updated_time"]=datetime.now()
            data["created_time"]=datetime.now()
            if data["status"]=="available":
                data["borrowed_by"]=None
            try:
                data1 = Books.objects.filter(id=bookid).update(**data)
                return ui_utils.handle_response({},data="updated",success=True)
            except Exception as e:
                 return ui_utils.handle_response({},data=str(e),success=True)
        if request.user.usertype=="mem":
            data=request.data
            context={}
            if data.get("status"):
                if data["status"]=="available":
                    context["borrowed_by"]=None
                context["status"]=data.get("status")
                context["updated_time"]=datetime.now()
                context["borrowed_by"]=request.user
                try:
                    data1 = Books.objects.filter(id=bookid).update(**context)
                    return ui_utils.handle_response({},data="updated",success=True)
                except Exception as e:
                    return ui_utils.handle_response({},data=str(e),success=True)
    def delete(self, request):
        bookid=query_params.get("book_id")
        
        res = Books.objects.delete(id=bookid)
        
        return ui_utils.handle_response({},data="deleted",success=False)

class deleteuser(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    def delete(self,request):
        username=request.query_params.get("username")
        print(request.user.usertype)
        if str(request.user.usertype)=="lib":
            user=BaseUser.objects.filter(username=username).first()
            if user:
                if user.usertype=="mem":
                    user.delete()
                    return ui_utils.handle_response({},data="deletedbylib",success=True)
            else:
                return ui_utils.handle_response({},data="user not found or  u dont have permissions to delete this user",success=True)
        elif str(request.user.usertype)=="mem":
            user=BaseUser.objects.filter(username=request.user.username).delete()
            return ui_utils.handle_response({},data="deletedbyuser",success=True)
        
        return ui_utils.handle_response({},data="user not available or u dont have permissions to delete this user",success=True)

class BooksClass1(APIView):
    
    def get(self, request):
        class_name = self.__class__.__name__
        data = Books.objects.filter()
        obj = BooksSerializer(data, many=True)
        
        return JsonResponse( obj.data,safe=False)