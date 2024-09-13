from django.urls import path,include
from .views import login_,logout_,register,home,record,role,welcome,admin_page,faculty_page,add_seminar_hall,get_hall_details_by_name,institute_info
from . import views
from allauth.account.views import LoginView
from allauth.socialaccount.views import SignupView
from .views import CustomPasswordResetView, CustomPasswordResetConfirmView, password_reset_done

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
    path('captcha_image/', views.captcha_image, name='captcha_image'),
    path('accounts/google/login/callback/', LoginView.as_view(), name='google_login_callback'),
    path('login/', LoginView.as_view(), name='login'),
    path('google/login/', SignupView.as_view(), name='google_login'),
    path('accounts/', include('allauth.urls')),
    path('password-reset/', CustomPasswordResetView, name='password_reset'),
    path('password-reset/done/', password_reset_done, name='password_reset_done'),
    path('password-reset/confirm/<uidb64>/<token>/', CustomPasswordResetConfirmView, name='password_reset_confirm'),
]