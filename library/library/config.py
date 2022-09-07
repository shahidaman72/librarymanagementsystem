import os
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
class Config():
  
    DATABASE = {
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
        'ENGINE': 'django.db.backends.sqlite3',
        'HOST': 'localhost',
        'USER': 'root',
        'PASSWORD':'',
       
    }
    # MONGO_DB = 'library'
    # MONGO_PORT = 27017
    # MONGO_USER = 'shahidshabir'
    # MONGO_PASSWORD = '123456'
    # MONGO_DB_TEST = 'mdtest'
    # BASE_URL = 'http://localhost:8000/'
    # DEFAULT_CC_EMAILS = []
    # ENV = 'local'

    # MONGO_CONNECTION = "mongodb://localhost:27017/library"