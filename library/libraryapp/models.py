from django.db import models
from django.conf import settings
# Create your models here.
#from pymongo import MongoClient
# client = MongoClient('localhost', settings.MONGO_PORT, username=settings.MONGO_USER, password=settings.MONGO_PASSWORD, maxPoolSize=2, waitQueueMultiple=10)
# mongo_client = client[settings.MONGO_DB]
#mongo_client = MongoClient(settings.MONGO_CONNECTION)
# print(settings.MONGO_CONNECTION)
# mongo_client = settings.MONGO_CONNECTION

#mongo_client = settings.MONGO_CONNECTION.testDEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

from django.db import models
from pymongo.write_concern import WriteConcern
from pymodm import MongoModel, fields
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.base_user import BaseUserManager


class BaseUser(AbstractUser):
    
    user_code = models.CharField(max_length=255, default=settings.DEFAULT_USER_CODE)
    username = models.CharField(max_length=20, null=False,unique=True,primary_key=True)
    password =models.CharField(max_length=20, null=True, blank=True)
    mobile = models.CharField(max_length=20, null=True, blank=True)
    designation = models.CharField(max_length=50, null=True, blank=True)
    terms_accepted = models.BooleanField(default=False)
    emailVerifyCode = models.CharField(max_length=20, null=True, blank=True)
    emailVerifyDate = models.DateTimeField(null=True, blank=True)
    alt_mobile = models.CharField(max_length=20, null=True, blank=True)
    usertype=models.CharField(max_length=20, null=True, blank=True)
    

    class Meta:
        db_table = 'base_user'

class Books(models.Model):

    #book_id = models.DEFAULT_AUTO_FIELD(max_length=255, default=settings.DEFAULT_USER_CODE)
    name = models.CharField(max_length=20, null=True)
    author =models.CharField(max_length=20, null=True, blank=True)
    status = models.CharField(max_length=20, null=True, blank=True)
    borrowed_by = models.ForeignKey('BaseUser', null=True, blank=True, on_delete=models.CASCADE,related_name='borrowed_by')
    added_by=models.ForeignKey('BaseUser', null=True, blank=True, on_delete=models.CASCADE,related_name='added_by')
    created_time=models.DateTimeField(null=True, blank=True)
    updated_time=models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'books'

