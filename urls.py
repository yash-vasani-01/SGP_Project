
from django.urls import path
from .views import login_,logout_,register,home,record,role,welcome,admin_page,faculty_page

urlpatterns = [
    path('',welcome,name='welcome'),
    path('login/',login_,name='login'),
    path('logout/', logout_, name='logout'),
    path('register/',register,name='register'),
    path('main/',home,name='home'),
    path('record/ <int:pk>',record,name='record'),
    path('role/',role,name='role'),
    path('admin_/',admin_page,name='admin_page'),
    path('faculty/',faculty_page,name='faculty_page'),
]
