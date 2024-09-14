from django.shortcuts import render, redirect,HttpResponse #type:ignore
from django.contrib.auth import authenticate, login, logout, get_user_model #type:ignore
from django.contrib import messages #type:ignore
from django.contrib.auth.models import User #type:ignore
from .models import data
from django.contrib.auth.decorators import login_required #type:ignore
from django.http import JsonResponse #type:ignore
from django.contrib.sessions.backends.db import SessionStore #type:ignore
from django.views.decorators.csrf import csrf_protect #type:ignore

def welcome(request):
    return render(request,'welcome.html')
def home(request):
    alldata=data.objects.all()
    return render(request,'index1.html',{'alldata':alldata})

from PIL import Image #type:ignore
from captcha.image import ImageCaptcha #type:ignore
from io import BytesIO
import base64

def generate_captcha() -> tuple:
    captcha_text = 'Ragunath'  # or you can take input from user also by input()
    captcha: ImageCaptcha = ImageCaptcha(
        width=200,
        height=50,
        fonts=['C:/Windows/Fonts/arial.ttf'],
        font_sizes=(40, 50, 60),
    )
    data: BytesIO = captcha.generate(captcha_text)
    image = Image.open(data)
    buffer = BytesIO()
    image.save(buffer, format='PNG')
    encoded_image = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return encoded_image, captcha_text

def captcha_image(request):
    encoded_image = request.session.get('captcha_image')
    if encoded_image:
        image = base64.b64decode(encoded_image)
        return HttpResponse(image, content_type='image/png')
    return HttpResponse('Captcha not found', status_code=404)


@csrf_protect
def login_(request):
    # Check if the user is already authenticated
    encoded_image, captcha_text = generate_captcha()
    request.session['captcha_text'] = captcha_text
    request.session['captcha_image'] = encoded_image
    
    if request.user.is_authenticated:
        user_status = data.objects.filter(email=request.user.email).first()
        if user_status:
            if 1 in user_status.status and 2 in user_status.status:
                return redirect('role')
            # Redirect based on user status
            elif 1 in user_status.status:  # Assuming 1 is for Admin
                return redirect('admin_page')
            elif 2 in user_status.status:  # Assuming 2 is for Faculty
                return redirect('faculty_page')
        else:
            messages.error(request, "User status not found!")
            return redirect('welcome')  # Redirect to a safe page

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        captcha_text = request.session.get('captcha_text')
        user_captcha = request.POST.get('captcha')
        
        if captcha_text and user_captcha.lower() == captcha_text.lower():
            user = authenticate(request, username=username, password=password)
            if user is not None and user.is_active:  # Check if user is active
                user_status = data.objects.filter(email=user.email).first()
                if user_status:
                    # Check if user has the required status
                    if 1 in user_status.status and 2 in user_status.status:
                        login(request, user)
                        return redirect('role')  # Redirect to role selection if both statuses are present
                    else:
                        login(request, user)
                        messages.success(request, "Successful log in")
                        return redirect('home')  # Redirect to home if user has appropriate status
                else:
                    messages.error(request, "User status not found!")
                    return redirect('login')
            else:
                messages.error(request, "Log in failed! Check your credentials and try again.")
                return redirect('login')
        else:
            messages.error(request, 'Invalid captcha')
            return redirect('login')
    return render(request, 'index.html')

from django.contrib.auth.tokens import default_token_generator #type:ignore
from django.core.mail import send_mail #type:ignore
from django.shortcuts import render, redirect #type:ignore
from django.contrib.auth.models import User #type:ignore
from django.urls import reverse #type:ignore
from .forms import PasswordResetForm #type:ignore

def password_reset_request(request):
    if request.method == "POST":
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            users = User.objects.filter(email=email)
            if users.exists():
                user = users.first()
                token = default_token_generator.make_token(user)
                reset_url = request.build_absolute_uri(
                    reverse('password_reset_confirm', kwargs={'uid': user.id, 'token': token})
                )
                send_mail(
                    subject="Password Reset Request",
                    message=f"Click the link to reset your password: {reset_url}",
                    from_email="chaudharivirjibhai84.com",
                    recipient_list=[email],
                    fail_silently=False,
                )
                messages.success(request, "A password reset link has been sent to your email.")
                return redirect('login')
    else:
        form = PasswordResetForm()
    
    return render(request, 'password_reset_form.html', {'form': form})

from django.contrib.auth.views import PasswordResetConfirmView #type:ignore
from django.contrib import messages #type:ignore
from django.urls import reverse_lazy #type:ignore

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    success_url = reverse_lazy('login')

    def form_valid(self, form):
        messages.success(self.request, 'Your password has been successfully changed. You can now log in.')
        return super().form_valid(form)


from django.contrib.auth.tokens import default_token_generator #type:ignore
from django.contrib.auth import get_user_model #type:ignore
from django.shortcuts import render, redirect #type:ignore
from django.utils.http import urlsafe_base64_decode #type:ignore
from django.contrib.auth.hashers import make_password #type:ignore

User = get_user_model()

def password_reset_confirm(request, uid, token):
    user = User.objects.get(pk=uid)
    if default_token_generator.check_token(user, token):
        if request.method == "POST":
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            if new_password == confirm_password:
                user.password = make_password(new_password)
                user.save()
                return redirect('password_reset_complete_close_tab')
        return render(request, 'password_reset_confirm.html', {'validlink': True})
    else:
        return render(request, 'password_reset_confirm.html', {'validlink': False})




def password_reset_complete_close_tab(request):
    # This template sets a flag in localStorage to show the popup
    return render(request, 'password_reset_complete_close_tab.html')




def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST['confirm_password']

        # Validate password using CustomPasswordValidator
        password_validator = CustomPasswordValidator()
        
        try:
            # Validate password rules
            password_validator.validate(password)
        except ValidationError as e:
            messages.error(request, e.messages[0])
            return redirect('register')

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('register')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect('register')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email is already registered.")
            return redirect('register')

        # If all validations pass, create the user
        newuser = User.objects.create_user(username, email, password)
        newuser.save()
        messages.success(request, "Your account has been created successfully")
        return redirect('login')

    return render(request, 'register.html')


        
def logout_(request):
    logout(request)
    messages.success(request,'You are Logged Out success')
    return redirect('login')


def record(request,pk):
    user_data=data.objects.get(id=pk)
    return render(request,'record.html',{'user_data':user_data})

@login_required
def role(request):
    print("Accessing role view")  
    user_role=request.user
    user_role_data=data.objects.filter(email=user_role.email).first()
    
    if request.method=="POST":
        select_role=request.POST.get('role')
        print(f"Selected role: {select_role}")
        
        if select_role=="Admin" and 1 in user_role_data.status:
            return redirect('admin_page')
        elif select_role=="Faculty" and 2 in user_role_data.status:
            return redirect("faculty_page")
        
    return render(request,'choose_role.html')
@login_required
def admin_page(request):
    user_data=data.objects.filter(email=request.user.email).first()
    if 1  not in user_data.status:
        messages.error(request, "Access denied. Admins only.")
        return redirect('login')
    return render(request,'admin_.html')

@login_required
def faculty_page(request):
    user_data=data.objects.filter(email=request.user.email).first()
    if 2  not in user_data.status:
        messages.error(request, "Access denied. Faculty only.")
        return redirect('login')
    return render(request,'faculty_.html')
def role(request):
    print("Accessing role view")  
    user_role=request.user
    user_role_data=data.objects.filter(email=user_role.email).first()
    
    if request.method=="POST":
        select_role=request.POST.get('role')
        print(f"Selected role: {select_role}")
        
        if select_role=="Admin" and 1 in user_role_data.status:
            return redirect('admin_page')
        elif select_role=="Faculty" and 2 in user_role_data.status:
            return redirect("faculty_page")
        
    return render(request,'choose_role.html')
@login_required
def admin_page(request):
    user_data=data.objects.filter(email=request.user.email).first()
    if 1  not in user_data.status:
        messages.error(request, "Access denied. Admins only.")
        return redirect('login')
    return render(request,'admin_.html')

@login_required
def faculty_page(request):
    user_data=data.objects.filter(email=request.user.email).first()
    if 2  not in user_data.status:
        messages.error(request, "Access denied. Faculty only.")
        return redirect('login')
    return render(request,'faculty_.html')


from django.contrib import messages #type:ignore
from django.shortcuts import redirect, render #type:ignore
from .models import SeminarHall

def add_seminar_hall(request):
    if request.method == 'POST':
        institute_name = request.POST.get('institute_name')
        hall_name = request.POST.get('hall_name')
        location = request.POST.get('location')
        capacity = request.POST.get('capacity')
        audio_system = request.POST.get('audio_system') == 'on'
        projector = request.POST.get('projector') == 'on'
        internet_wifi = request.POST.get('wifi') == 'on'

        # Check if the hall with the same name exists in the same institute
        if SeminarHall.objects.filter(institute_name=institute_name, hall_name=hall_name).exists():
            return render(request, 'add_hall.html', {
            'message': "A seminar hall with this name already exists in the selected institute."})

        # If no duplicate found, create a new seminar hall
        SeminarHall.objects.create(
            institute_name=institute_name,
            hall_name=hall_name,
            location=location,
            capacity=capacity,
            audio_system=audio_system,
            projector=projector,
            internet_wifi=internet_wifi
        )

        return render(request, 'add_hall.html', {
            'message': "Seminar hall details added successfully!"
        })
    
    return render(request, 'add_hall.html',)

def institute_info(request, institute_name):
    halls = SeminarHall.objects.filter(institute_name=institute_name)
    return render(request, 'hall_information.html', {
        'institute_name': institute_name,
        'halls': halls,
    })
    
def get_hall_details_by_name(request, hall_name, institute_name):
    halls = SeminarHall.objects.filter(hall_name=hall_name, institute_name=institute_name)
    if halls.exists():
        hall = halls.first()  
        data = {
            'location': hall.location,
            'capacity': hall.capacity,
            'projector': hall.projector,
            'audio': hall.audio_system,
            'wifi': hall.internet_wifi,
        }
        return JsonResponse(data)
    else:
        return JsonResponse({'error': 'Hall not found'}, status=404)
