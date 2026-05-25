from django.shortcuts import render,redirect,HttpResponse
from dasapp.EmailBackEnd import EmailBackEnd
from django.contrib.auth import  logout,login
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from dasapp.models import CustomUser
from django.contrib.auth import get_user_model
import redis  # [NEW] Để kết nối Redis

User = get_user_model()

# [NEW] Helper function để ghi nhận brute-force từ Django
def record_login_attempt(request, success=False):
    """
    Ghi nhận login attempt vào Redis để Nginx có thể tracking.
    - Success: Ghi nhận timestamp thành công (NOT reset counter!)
    - Failed: Ghi nhận attempt (Nginx sẽ làm việc này)
    """
    try:
        client_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', ''))
        if ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        r = redis.Redis(host='redis', port=6379, db=0, socket_connect_timeout=2, socket_timeout=2)
        
        if success:
            # [FIXED] Không xóa counter nữa!
            # Chỉ ghi nhận success time để tracking
            success_key = f"brute_force:success:{client_ip}"
            r.set(success_key, "1", ex=900)  # TTL = 15 phút (BRUTE_FORCE_WINDOW)
            print(f"[LOGIN_TRACKING] Login SUCCESS for IP {client_ip} - counter preserved")
        else:
            # Nginx sẽ xử lý ghi nhận failed attempt
            pass
            
        r.close()
    except Exception as e:
        print(f"[LOGIN_TRACKING] Redis error: {e}")
        pass

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
            record_login_attempt(request, success=True)  # [NEW] Ghi nhận success

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
          login(request,user)
        else:
          messages.success(request,'Current Password wrong!!!')
          return redirect("change_password")
     return render(request,'change-password.html')