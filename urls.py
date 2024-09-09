from django.urls import path
from .views import login_,logout_,register,home,record,role,welcome,admin_page,faculty_page,add_seminar_hall,get_hall_details_by_name,institute_info

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
    path('add_hall/',add_seminar_hall,name='add_hall'),
    path('get_hall_details_by_name/<str:hall_name>/<str:institute_name>/', get_hall_details_by_name, name='get_hall_details_by_name'),
    path('institute_info/<str:institute_name>/', institute_info, name='institute_info'),
    
]