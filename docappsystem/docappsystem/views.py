from django.shortcuts import render,redirect,HttpResponse
from dasapp.EmailBackEnd import EmailBackEnd
from django.contrib.auth import  logout,login
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from dasapp.models import CustomUser
from django.contrib.auth import get_user_model

User = get_user_model()

def BASE(request):
    return render(request,'base.html')

def LOGIN(request):
    return render(request,'login.html')

def doLogout(request):
    logout(request)
    return redirect('login')

def doLogin(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        user = EmailBackEnd.authenticate(request,
                                         username=email,
                                         password=password
                                         )
        if user!=None:
            login(request,user)

            user_type = user.user_type
            
            # Khởi tạo mặc định để chống lỗi 500 nếu user_type bị sai lệch
            response = redirect('login') 

            if user_type == '1':
                 response = redirect('admin_home')
            elif user_type == '2':
                 response = redirect('doctor_home')
            elif user_type == '3':
                 response = HttpResponse("This is User panel")
            
            # Không cần if response nữa vì chắc chắn response luôn là một HttpResponse
            response['X-Login-Status'] = 'success'
            return response
            
        else:
                messages.error(request,'Email or Password is not valid')
                resp = redirect('login')
                # [NEW] Set header để Nginx biết login thất bại
                resp['X-Login-Status'] = 'failed'
                return resp
    else:
            messages.error(request,'Email or Password is not valid')
            resp = redirect('login')
            resp['X-Login-Status'] = 'failed'
            return resp

login_required(login_url='/')
def PROFILE(request):
    user = CustomUser.objects.get(id = request.user.id)
    context = {
        "user":user,
    }
    return render(request,'profile.html',context)

@login_required(login_url = '/')
def PROFILE_UPDATE(request):
    if request.method == "POST":
        profile_pic = request.FILES.get('profile_pic')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        username = request.POST.get('username')
        print(profile_pic)
        

        try:
            customuser = CustomUser.objects.get(id = request.user.id)
            customuser.first_name = first_name
            customuser.last_name = last_name
            

            
            if profile_pic !=None and profile_pic != "":
               customuser.profile_pic = profile_pic
            customuser.save()
            messages.success(request,"Your profile has been updated successfully")
            return redirect('profile')

        except:
            messages.error(request,"Your profile updation has been failed")
    return render(request, 'profile.html')

def CHANGE_PASSWORD(request):
     context ={}
     ch = User.objects.filter(id = request.user.id)
     
     if len(ch)>0:
            data = User.objects.get(id = request.user.id)
            context["data"]:data             # type: ignore
     if request.method == "POST":        
        current = request.POST["cpwd"]
        new_pas = request.POST['npwd']
        user = User.objects.get(id = request.user.id)
        un = user.username
        check = user.check_password(current)
        if check == True:
          user.set_password(new_pas)
          user.save()
          messages.success(request,'Password Change  Succeesfully!!!')
          user = User.objects.get(username=un)
          login(request, user)
        else:
          messages.success(request,'Current Password wrong!!!')
          return redirect("change_password")
     return render(request,'change-password.html')
