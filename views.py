from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib import messages
from django.contrib.auth.models import User
from .models import data,admin_data,SeminarHall,BookingRequest
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.core.exceptions import ValidationError
from .validators import CustomPasswordValidator


def welcome(request):
    return render(request,'welcome.html')
def home(request):
    alldata=data.objects.all()
    return render(request,'index1.html',{'alldata':alldata})
def login_(request):
    # Check if the user is already authenticated
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

        # Authenticate using the provided username and password
        user = authenticate(request, username=username, password=password)

        if user is not None:
            user_status = data.objects.filter(email=user.email).first()
            if user_status:
                # Check if user has the required status
                if 1 in user_status.status and 2 in user_status.status:
                    login(request, user)
                    return redirect('role')  # Redirect to role selection if both statuses are present
                elif 1 in user_status.status :
                    login(request, user)
                    messages.success(request, "Successful log in")
                    return redirect('admin_page')  # Redirect to home if user has appropriate status
                elif 2 in user_status.status :
                    login(request, user)
                    messages.success(request, "Successful log in")
                    return redirect('faculty_page')  # Redirect to home if user has appropriate status
            else:
                messages.error(request, "User status not found!")
                return redirect('login')
        else:
            messages.error(request, "Log in failed! Check your credentials and try again.")
            return redirect('login')

    return render(request, 'index.html')

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
    
    return render(request, 'add_hall.html')

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
    
def institute_info(request, institute_name):
    halls = SeminarHall.objects.filter(institute_name=institute_name)
    return render(request, 'hall_information.html', {
        'institute_name': institute_name,
        'halls': halls,
    })
    
    
    
from datetime import datetime

def book_hall(request, hall_name, institutename):
    if request.method == 'POST':
        date = request.POST.get('date')
        start_time = request.POST.get('start_time')
        end_time = request.POST.get('end_time')

        # Convert start_time and end_time to datetime.time objects
        try:
            start_time = datetime.strptime(start_time, '%H:%M').time()
            end_time = datetime.strptime(end_time, '%H:%M').time()
        except ValueError:
            messages.error(request, 'Invalid time format. Please use HH:MM format.')
            return render(request, 'faculty_.html', {
                'message': "Invalid time format. Please use HH:MM format."
            })

        try:
            # Fetch the specific hall for the selected institute
            hall = SeminarHall.objects.get(hall_name=hall_name, institute_name=institutename)
        except SeminarHall.DoesNotExist:
            messages.error(request, 'The selected hall does not exist in this institute.')
            return render(request, 'faculty_.html', {
                'message': "The selected hall does not exist in this institute."
            })

        try:
            # Fetch the admin responsible for the institute
            admin = admin_data.objects.get(institute_name=hall.institute_name)
        except admin_data.DoesNotExist:
            messages.error(request, 'Admin for this institute does not exist.')
            return render(request, 'faculty_.html', {
                'message': "Admin for this institute does not exist."
            })

        # Fetch the current requester (faculty)
        requester = data.objects.get(username=request.user.username)

        # Check if the hall is already booked for the requested date and time
        existing_bookings = BookingRequest.objects.filter(
            institute_name=hall.institute_name,
            hall_name=hall.hall_name,
            date=date,
            status='pending'
        )

        # Check for overlapping time slots
        for booking in existing_bookings:
            existing_start = booking.start_time
            existing_end = booking.end_time

            # Convert existing booking times to datetime.time for comparison
            if (start_time < existing_end and end_time > existing_start):
                messages.error(request, 'The hall is not available for the requested time slot.')
                return render(request, 'faculty_.html', {
                    'message': "The hall is not available for the requested time slot."
                })

        # If no overlap, create a new booking request
        booking = BookingRequest(
            institute_name=hall.institute_name,
            hall_name=hall.hall_name,
            date=date,
            start_time=start_time,
            end_time=end_time,
            status='pending',
            requester_name=requester.username,
            admin=admin
        )
        booking.save()
        messages.success(request, 'Your booking request has been submitted!')
        return render(request, 'faculty_.html', {
            'message': "Your booking request has been submitted!"
        })

    # Fetch the hall to display on the page
    try:
        hall = SeminarHall.objects.get(hall_name=hall_name, institute_name=institutename)
    except SeminarHall.DoesNotExist:
        hall = None  # If no hall is found, pass None

    return render(request, 'book_hall.html', {'hall': hall})
