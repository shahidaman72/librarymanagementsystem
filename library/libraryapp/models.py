from django.db import models
from django.conf import settings
# Create your models here.
from pymongo import MongoClient
# client = MongoClient('localhost', settings.MONGO_PORT, username=settings.MONGO_USER, password=settings.MONGO_PASSWORD, maxPoolSize=2, waitQueueMultiple=10)
# mongo_client = client[settings.MONGO_DB]
#mongo_client = MongoClient(settings.MONGO_CONNECTION)
mongo_client = settings.MONGO_CONNECTION.library

#mongo_client = settings.MONGO_CONNECTION.testDEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

from django.db import models
from pymongo.write_concern import WriteConcern
from pymodm import MongoModel, fields
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.base_user import BaseUserManager


class BaseUser(AbstractUser):
    """
    This is base user class that inherits AbstractBaseUser and adds an additional field.
    """
    #_id = models.BigAutoField(primary_key=False)
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