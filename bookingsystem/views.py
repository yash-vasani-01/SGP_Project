from django.shortcuts import render, redirect,HttpResponse
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib import messages
from django.contrib.auth.models import User
from .models import data
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.contrib.sessions.backends.db import SessionStore
from django.views.decorators.csrf import csrf_protect

def welcome(request):
    return render(request,'welcome.html')
def home(request):
    alldata=data.objects.all()
    return render(request,'index1.html',{'alldata':alldata})

from PIL import Image
from captcha.image import ImageCaptcha
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


from django.contrib.auth.tokens import default_token_generator

from .forms import CustomPasswordResetForm
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.db.models import Q

def CustomPasswordResetView(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            users = User.objects.filter(Q(email__iexact=email) | Q(username__iexact=email))
            if users.exists():
                # Send password reset email
                for user in users:
                    # Use Django's built-in password reset functionality
                    user.email_user('Password reset', 'Someone asked for password reset for your account. Click the link below:')
                    # You can customize the email content and subject here
                return HttpResponse('Password reset email sent successfully!')
            else:
                return HttpResponse('No user found with that email address.')
    else:
        form = PasswordResetForm()
    return render(request, 'password_reset.html', {'form': form})
def password_reset_done(request):
    return render(request, 'password_reset_done_email_sent.html')

def CustomPasswordResetConfirmView(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                return redirect('login')
        else:
            form = SetPasswordForm(user)
        return render(request, 'password_reset_confirm.html', {'form': form})
    else:
        return render(request, 'password_reset_confirm_invalid.html')

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

from django.core.exceptions import ValidationError
from .validators import CustomPasswordValidator

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


from django.contrib import messages
from django.shortcuts import redirect, render
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
