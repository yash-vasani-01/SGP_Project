
from django.urls import path
from .views import login_,logout_,register,home,record,role

urlpatterns = [
    path('',login_,name='login'),
    path('logout/', logout_, name='logout'),
    path('register/',register,name='register'),
    path('main/',home,name='home'),
    path('record/ <int:pk>',record,name='record'),
    path('role/',role,name='role'),
     
]
