from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib import messages
from django.contrib.auth.models import User
from .models import data



def home(request):
    alldata=data.objects.all()
    return render(request,'index1.html',{'alldata':alldata})
def login_(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        print(username)

        User = get_user_model()

        # Try to get the user with the given email
        try:
            user = User.objects.get(email=email)
            username = user.username
        except User.DoesNotExist:
            user = None

        # Authenticate with the fetched username and password
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            print(username,user.username)
            user_status = data.objects.filter(email=user.email).first()
            print(user_status,user.username,email)
            if user_status:
                print(f"User status: {user_status.status}") 
             
                if 1 in user_status.status and 2 in user_status.status:
                        return redirect('role')
                else:
                    login(request, user)
                    print(user_status.status)
                    messages.success(request, "Successful log in")
                    return redirect('home')
            else:
                messages.error(request, "User status not found!")
                return redirect('login')
        else:
            messages.error(request, "Log in failed! Try again!")
            return redirect('login')
    else:
        return render(request, 'index.html')

def register(request):
    if request.method=='POST':
        username=request.POST['username']
        email = request.POST.get('email')
        password = request.POST.get('password')
        comfirm_password=request.POST['comfirm_password']
        if password != comfirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('register')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect('register')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email is already registered.")
            return redirect('register')
        
        newuser=User.objects.create_user(username,email,password)
        newuser.save()
        messages.success(request,"Your Account has been Created Successfully")
        return redirect('login')
    return render(request,'register.html')
        
def logout_(request):
    logout(request)
    messages.success(request,'You are Logged Out success')
    return redirect('login')


def record(request,pk):
    user_data=data.objects.get(id=pk)
    return render(request,'record.html',{'user_data':user_data})


def role(request):
    return render(request,'choose_role.html')