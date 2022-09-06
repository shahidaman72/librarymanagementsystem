
from django.urls import include,path
from rest_framework.routers import DefaultRouter
from . import views
urlpatterns = [

    path(r'books/', views.Books.as_view()),

]

# adding urls for Permission View Set
router = DefaultRouter()

router.register(r'^user', views.UserViewSet, basename='user')

urlpatterns += router.urls