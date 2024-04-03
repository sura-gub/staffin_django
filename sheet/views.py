from telnetlib import LOGOUT
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import RegisterAll
from .models import RegisterAll,Branch,AddDepartment,AddDepartmentHead,Attendance,PayrollMaathangi,EmpLeaves,WorkFromHome,Visiters,AddPermission,PermissionAdd,ExcelToDB,Holiday,AttnNotes,AddLocation,AddSalary,Wallpaper,Enable,AddLoan,AddClockin  
from django.views.decorators.http import require_GET
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.db.models import Count
from django.views.decorators.cache import cache_control

from django.contrib.sessions.backends.db import SessionStore



from decorators import department_required

# from django.views.decorators.csrf import csrf_exempt
# import json
from django.views.decorators.csrf import csrf_exempt

def get_department_names(request):
    data = AddDepartment.objects.values('id', 'nm')
    return JsonResponse(list(data), safe=False)


def get_branch_names1(request):
    branch = Branch.objects.values( 'branch_name')
    print(f" data grgr {branch}")
    return JsonResponse(list(branch), safe=False)    



from django.utils import timezone
def LoginPage(request):
    current_date = datetime.now().date()
    print(f"current_date:{current_date}")
    # Step 2: Check the "registerall" table for users with the same DOB as the current date
    users_with_birthday = RegisterAll.objects.filter(dob__month=current_date.month, dob__day=current_date.day)
    print(f"users_with_birthday: {users_with_birthday}")
    # Assuming you want to pass the current user to the template
    return render(request, 'loginpage.html', { 'users_with_birthday': users_with_birthday})

@csrf_exempt
def get_nm(request):
    if request.method == 'POST':
        username = request.POST.get('username', '')
        
        try:
            user = RegisterAll.objects.filter(user_id=username).first()  # Use filter() and first()
            if user:
                nm = user.nm
                return JsonResponse({'nm': nm})
            else:
                return JsonResponse({'error': 'User not found'}, status=404)
        except RegisterAll.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def indexadministrator(request):
    return render(request, 'index_administrator.html')


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def indexhr(request):
    return render(request, 'index_hr.html')


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def error_page(request):
    return render(request, 'error_404.html')


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def indexemp(request):
    if 'username' in request.session:
        current_user = request.session['username']
        # Get the last record for the current user
        last_record = Visiters.objects.filter(user=current_user,).order_by('-log_in_dt_tm')[1:2].first()
        if last_record:
            log_in_tm = last_record.log_in_tm
            log_out_tm = last_record.log_out_tm
            log_dt = last_record.log_dt
            log_out_dt = last_record.log_out_dt
            # Add any additional fields you want to retrieve
            print(f'log_in_tm :{log_in_tm}')
            print(f'log_out_tm :{log_out_tm}')
            print(f'log_dt :{log_dt}')
            print(f'log_out_dt :{log_out_dt}')
            return render(request, 'index_emp.html', {
                'current_user': current_user,
                'log_in_tm': log_in_tm,
                'log_out_tm': log_out_tm,
                'log_dt': log_dt,
                'log_out_dt': log_out_dt,
            })
        else:
            # Handle the case when there is no matching record
            return render(request, 'index_emp.html')
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')
        
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def changepass(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()  
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value    
    return render(request, 'changepass.html',{'current_user': current_user , 'branches': branches,'default_branch':default_branch})

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
# @department_required('emp')
def changepass_emp(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value    
    return render(request, 'changepass_emp.html',{'current_user': current_user,'default_branch':default_branch})

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
# @department_required('ad')
def changepass_adm(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value    
    return render(request, 'changepass_adm.html',{'current_user': current_user,'default_branch':default_branch})



@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def register_admin(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request, 'register_admin.html', {'current_user': current_user , 'branches': branches,'default_branch':default_branch}) 


# @cache_control(no_cache=True, must_revalidate=True, no_store=True)
# def add_branch(request):
#     return render(request,'add_branch.html') 
 

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def employee_admin(request):
      if 'username' in request.session:
          current_user = request.session['username']
          default_branch = request.session['default_branch_id']
          branches = Branch.objects.all()
      else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
      return render(request,'employee_admin.html', {'current_user': current_user , 'branches': branches ,'default_branch':default_branch})


@cache_control(no_cache=True, must_revalidate=True, no_store=True) 
@department_required('SAD') 
def traniee_admin(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request,'traniee_admin.html', {'current_user': current_user ,'branches': branches,'default_branch':default_branch})


@cache_control(no_cache=True, must_revalidate=True, no_store=True) 
@department_required('SAD') 
def employee_view(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request,'employee_view.html', {'current_user': current_user,'default_branch':default_branch})

@cache_control(no_cache=True, must_revalidate=True, no_store=True) 
@department_required('SAD')
def admin_view(request):   
    if 'username' in request.session:
        current_user = request.session['username']
        
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request,'admin_view.html', {'current_user': current_user})

@department_required('SAD')
def add_attendance(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()

    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request,'add_attendance.html', {'current_user': current_user , 'branches': branches,'default_branch':default_branch})



from datetime import datetime, timedelta
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def indexadmin(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        nm_value = request.session.get('nm', '')
        current_year = datetime.now().year
        current_month = datetime.now().strftime('%B')
        current_month1 = datetime.now().month
        
        # Count user_id occurrences where depart is 'emp'
        user_attendance_counts = Attendance.objects.filter(depart='emp', yr=current_year, mnth=current_month1).values('user_id').annotate(count=Count('user_id'))
        # Prepare a dictionary to store user_id counts
        user_attendance_counts_dict = {user_count['user_id']: user_count['count'] for user_count in user_attendance_counts}
        user_leave_counts = EmpLeaves.objects.filter(depart='emp', lev_typ='LOP', yr=current_year, mnth=current_month1).values('user_id').annotate(count=Count('user_id'))

        #branch_counts = RegisterAll.objects.exclude(Q(branch_name='marthandam') | Q(depart__in=['ad', 'trainee'])).values('branch_name').annotate(count=Count('branch_name'))
        branch_counts = RegisterAll.objects.exclude(Q(branch_name='marthandam') | Q(depart__in=['ad', 'trainee'])).filter(depart='emp').values('branch_name').annotate(count=Count('branch_name'))



        branch_counts_dict = {branch_count['branch_name']: branch_count['count'] for branch_count in branch_counts}
        # Prepare a dictionary to store user_id counts
        user_leave_counts_dict = {user_count['user_id']: user_count['count'] for user_count in user_leave_counts}

        first_day_of_month = date(current_year, current_month1, 1)
        # Calculate yesterday's date
        yesterday1 = date.today() - timedelta(days=1)
        # Filter records from the start of the month to yesterday
        current_month_holidays = Holiday.objects.filter(
            Q(holiday_date__range=(first_day_of_month, yesterday1))
        )
        # current_month_holidays = Holiday.objects.filter(year=current_year, month=current_month)

        current_date = datetime.now().date()
        current_month_birthday = RegisterAll.objects.filter(
        Q(dob__month=current_date.month, dob__day__gte=current_date.day)   # For today and future days in the current month         
        ).values('user_id', 'nm', 'dob')

        current_month_anniversary = RegisterAll.objects.filter(
        Q(doj__month=current_date.month, doj__day__gte=current_date.day)   # For today and future days in the current month         
        ).values('user_id', 'nm', 'doj')
          
        # Calculate the count of holiday records in the current month and year
        current_month_holidays_count = current_month_holidays.count()
        yesterday = datetime.now() - timedelta(days=1)
        days_in_current_month = yesterday.day
        # Calculate the count of users with 100% attendance
        users_with_100_percent_attendance = [user_id for user_id, attendance_count in user_attendance_counts_dict.items() if
                                             user_id not in user_leave_counts_dict and attendance_count == days_in_current_month - current_month_holidays_count]
        # list=users_with_100_percent_attendance
        users_with_100_percent_attendance_names = RegisterAll.objects.filter(user_id__in=users_with_100_percent_attendance).values('user_id', 'nm')
        # Prepare a dictionary to store user names
        users_with_100_percent_attendance_dict = {user['user_id']: user['nm'] for user in users_with_100_percent_attendance_names}
        branches = Branch.objects.all()
        param = {
            'current_user': current_user,
            'branch_counts_dict': branch_counts_dict,
            'nm_value': nm_value,
            'branches': branches,
            'user_attendance_counts_dict': user_attendance_counts_dict,
            'user_leave_counts_dict': user_leave_counts_dict,
            'current_month_holidays': current_month_holidays_count,
            'days_in_current_month': days_in_current_month,
            'month_tot_att_days': days_in_current_month - current_month_holidays_count,
            'users_with_100_percent_attendance': users_with_100_percent_attendance,

            'current_month_birthday': current_month_birthday,
            'current_month_anniversary': current_month_anniversary,

            'users_with_100_percent_attendance_names': users_with_100_percent_attendance_dict,
            'default_branch':default_branch,
            
        }
        print(f'yuyghbjnkmy:{param}')
        return render(request, 'index_admin.html', param)
    else:
        return redirect('loginpage')


    
def process_selected_branch(request):
    if 'username' in request.session:
        if request.method == 'GET':
            selected_branch_id = request.GET.get('selected_branch')

            # Check if "All Branches" is selected
            if selected_branch_id == "All":
                # Remove specific branch-related session data
                request.session.pop('selected_branch_id', None)
                request.session.pop('admin_code', None)
                request.session.pop('employee_code', None)
                request.session.pop('trainee_code', None)
                request.session.pop('office_name', None)
                # Store "All" in the session
                request.session['selected_all'] = selected_branch_id
                request.session.save()
                print(f"request.session['selected_all'] {request.session['selected_all']}")
                
                return HttpResponse(status=200)

            else:
                # Fetch data for the selected branch
                try:
                    branch = Branch.objects.get(branch_name=selected_branch_id)
                    admin_code = branch.admin_code
                    employee_code = branch.employee_code
                    trainee_code = branch.trainee_code
                    office_name = branch.office_name
                except Branch.DoesNotExist:
                    print(f"Branch with ID {selected_branch_id} does not exist.")
                    return HttpResponse(status=404)

                # Store the selected branch data in the session
                request.session['selected_branch_id'] = selected_branch_id
                request.session['admin_code'] = admin_code
                request.session['employee_code'] = employee_code
                request.session['trainee_code'] = trainee_code
                request.session['office_name'] = office_name
                request.session.pop('selected_all', None)  # Remove 'selected_all' if needed

                request.session.save()

                return HttpResponse(status=200)
    else:
        return HttpResponse(status=403)



  
# Create your views here.
from django.utils import timezone
from datetime import datetime
 
from django.shortcuts import render, redirect, get_object_or_404
from django.http import Http404
import hashlib


import base64
key = "staffin"
def decrypt(ciphertext, key):
    key = hashlib.sha256(key.encode()).digest()
    ciphertext_bytes = base64.b64decode(ciphertext)
    iv = ciphertext_bytes[:16]
    ciphertext_bytes = ciphertext_bytes[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_bytes = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
    return plaintext_bytes.decode()

def login_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            user = RegisterAll.objects.get(user_id=username)
            ciphertext = user.pwd
            print(f"ciphertext {ciphertext}")
            # Decrypt the password
            decrypted_password = decrypt(ciphertext, key)
            print(f"decrypted_password {decrypted_password}")

            print(f"decrypted_password {decrypted_password}")
            if password == decrypted_password:
                # Store user details in session
                request.session['username'] = username
                request.session['nm'] = user.nm
                request.session['depart'] = user.depart

                # Activate the Indian time zone
                timezone.activate('Asia/Kolkata')
                current_datetime = timezone.localtime(timezone.now())
                date = current_datetime.date()
                formatted_time = current_datetime.strftime("%H:%M:%S")
                log_in_dt_tm = f"{date} {formatted_time}"

                default_branch = Branch.objects.first()
                if default_branch:
                    request.session['default_branch_id'] = default_branch.branch_name
                    request.session['default_office_name'] = default_branch.office_name
                    request.session['admin_co'] = default_branch.admin_code
                    request.session['employee_co'] = default_branch.employee_code
                    request.session['trainee_co'] = default_branch.trainee_code
                else:
                    # Handle the case where no default branch is found
                    request.session['default_branch_id'] = None
                    request.session['default_office_name'] = None
                    request.session['admin_co'] = None
                    request.session['employee_co'] = None
                    request.session['trainee_co'] = None

                Visiters.objects.create(
                    user=username,
                    log_in_tm=formatted_time,
                    log_dt=date,
                    log_in_dt_tm=log_in_dt_tm,
                    log_mnth=current_datetime.month,
                    log_yr=current_datetime.year,
                    ip=request.META.get('REMOTE_ADDR'),
                    loctn='Nagercoil'
                )

                # Redirect based on the 'depart' value
                if user.depart == 'ad':
                    return redirect('index_emp')
                elif user.depart == 'SAD':
                    return redirect('index_admin')
                elif user.depart == 'ads':
                    return redirect('index_administrator')
                elif user.depart == 'emp':
                    return redirect('index_emp')
                elif user.depart == 'hr':
                    return redirect('index_hr')
                else:
                    messages.error(request, 'Invalid department.')
            else:
                messages.error(request, 'Username or password is incorrect.')
        except RegisterAll.DoesNotExist:
            messages.error(request, 'Username or password is incorrect.')

    return render(request, 'loginpage.html')



# def login_user(request):
#     if request.method == 'POST':
#         username = request.POST.get('username')
#         password = request.POST.get('password')

#         try:
#                 user = RegisterAll.objects.get(user_id=username,pwd=password)
       
#                 # Store user details in session
#                 request.session['username'] = username
#                 request.session['nm'] = user.nm
#                 request.session['depart'] = user.depart

#                 # Activate the Indian time zone
#                 timezone.activate('Asia/Kolkata')
#                 current_datetime = timezone.localtime(timezone.now())
#                 date = current_datetime.date()
#                 formatted_time = current_datetime.strftime("%H:%M:%S")
#                 log_in_dt_tm = f"{date} {formatted_time}"

#                 default_branch = Branch.objects.first()
#                 if default_branch:
#                     request.session['default_branch_id'] = default_branch.branch_name
#                     request.session['default_office_name'] = default_branch.office_name
#                     request.session['admin_co'] = default_branch.admin_code
#                     request.session['employee_co'] = default_branch.employee_code
#                     request.session['trainee_co'] = default_branch.trainee_code
#                 else:
#                     # Handle the case where no default branch is found
#                     request.session['default_branch_id'] = None
#                     request.session['default_office_name'] = None
#                     request.session['admin_co'] = None
#                     request.session['employee_co'] = None
#                     request.session['trainee_co'] = None

#                 Visiters.objects.create(
#                     user=username,
#                     log_in_tm=formatted_time,
#                     log_dt=date,
#                     log_in_dt_tm=log_in_dt_tm,
#                     log_mnth=current_datetime.month,
#                     log_yr=current_datetime.year,
#                     ip=request.META.get('REMOTE_ADDR'),
#                     loctn='Nagercoil'
#                 )

#                 # Redirect based on the 'depart' value
#                 if user.depart == 'ad':
#                     return redirect('index_emp')
#                 elif user.depart == 'SAD':
#                     return redirect('index_admin')
#                 elif user.depart == 'ads':
#                     return redirect('index_administrator')
#                 elif user.depart == 'emp':
#                     return redirect('index_emp')
#                 elif user.depart == 'hr':
#                     return redirect('index_hr')
#                 else:
#                     messages.error(request, 'Invalid department.')
            
#         except RegisterAll.DoesNotExist:
#             messages.error(request, 'Username or password is incorrect.')

#     return render(request, 'loginpage.html')


# from django.contrib.auth.hashers import check_password
# def login_user(request):
#     if request.method == 'POST':
#         username = request.POST.get('username')
#         password = request.POST.get('password')
#         try:
#             user = RegisterAll.objects.get(user_id=username)
#             if check_password(password, user.pwd):
#                 # Store user details in session
#                 request.session['username'] = username
#                 request.session['nm'] = user.nm
#                 request.session['depart'] = user.depart
#                 # Activate the Indian time zone
#                 timezone.activate('Asia/Kolkata')
#                 current_datetime = timezone.localtime(timezone.now())
#                 date = current_datetime.date()
#                 print(f"date {date}")
#                 formatted_time = current_datetime.strftime("%H:%M:%S")  # Corrected time format
#                 log_in_dt_tm = f"{date} {formatted_time}"
#                 default_branch = Branch.objects.first()
#                 if default_branch:
#                     request.session['default_branch_id'] = default_branch.branch_name
#                     request.session['default_office_name'] = default_branch.office_name
#                     request.session['admin_co'] = default_branch.admin_code
#                     request.session['employee_co'] = default_branch.employee_code
#                     request.session['trainee_co'] = default_branch.trainee_code
#                 else:
#                     # Handle the case where no default branch is found
#                     request.session['default_branch_id'] = None
#                     request.session['default_office_name'] = None
#                     request.session['admin_co'] = None
#                     request.session['employee_co'] = None
#                     request.session['trainee_co'] = None
#                 Visiters.objects.create(
#                     user=username,
#                     log_in_tm=formatted_time,
#                     log_dt=date,
#                     log_in_dt_tm=log_in_dt_tm,
#                     log_mnth=current_datetime.month,
#                     log_yr=current_datetime.year,
#                     ip=request.META.get('REMOTE_ADDR'),
#                     loctn='Nagercoil'
#                 )
#                 # Redirect based on the 'depart' value
#                 if user.depart == 'ad':
#                     return redirect('index_emp')
#                 elif user.depart == 'SAD':
#                     return redirect('index_admin')
#                 elif user.depart == 'ads':
#                     return redirect('index_administrator')
#                 elif user.depart == 'emp':
#                     return redirect('index_emp')
#                 elif user.depart == 'hr':
#                     return redirect('index_hr')
#                 else:
#                     messages.error(request, 'Invalid department.')
#             else:
#                 # Password is incorrect
#                 messages.error(request, 'Username or password is incorrect.')
#         except RegisterAll.DoesNotExist:
#             messages.error(request, 'Username or password is incorrect.')
#     return render(request, 'loginpage.html')


# def verify_password(entered_password, stored_hashed_password):
#     # Check if the entered password matches the stored hashed password
#     return bcrypt.checkpw(entered_password.encode(), stored_hashed_password.encode())

# def login_user(request):
#     if request.method == 'POST':
#         username = request.POST.get('username')
#         password = request.POST.get('password')

#         try:
#             user = RegisterAll.objects.get(user_id=username)
#             stored_hashed_password = user.pwd

#             if verify_password(password, stored_hashed_password):
#                 # Store user details in session
#                 request.session['username'] = username
#                 request.session['nm'] = user.nm
#                 request.session['depart'] = user.depart

#                 # Activate the Indian time zone
#                 timezone.activate('Asia/Kolkata')
#                 current_datetime = timezone.localtime(timezone.now())
#                 date = current_datetime.date()
#                 print(f"date {date}")
#                 formatted_time = current_datetime.strftime("%H:%M:%S")  # Corrected time format
#                 log_in_dt_tm = f"{date} {formatted_time}"

#                 default_branch = Branch.objects.first()
#                 if default_branch:
#                     request.session['default_branch_id'] = default_branch.branch_name
#                     request.session['default_office_name'] = default_branch.office_name
#                     request.session['admin_co'] = default_branch.admin_code
#                     request.session['employee_co'] = default_branch.employee_code
#                     request.session['trainee_co'] = default_branch.trainee_code
#                 else:
#                     # Handle the case where no default branch is found
#                     request.session['default_branch_id'] = None
#                     request.session['default_office_name'] = None
#                     request.session['admin_co'] = None
#                     request.session['employee_co'] = None
#                     request.session['trainee_co'] = None

#                 Visiters.objects.create(
#                     user=username,
#                     log_in_tm=formatted_time,
#                     log_dt=date,
#                     log_in_dt_tm=log_in_dt_tm,
#                     log_mnth=current_datetime.month,
#                     log_yr=current_datetime.year,
#                     ip=request.META.get('REMOTE_ADDR'),
#                     loctn='Nagercoil'
#                 )

#                 # Redirect based on the 'depart' value
#                 if user.depart == 'ad':
#                     return redirect('index_emp')
#                 elif user.depart == 'SAD':
#                     return redirect('index_admin')
#                 elif user.depart == 'ads':
#                     return redirect('index_administrator')
#                 elif user.depart == 'emp':
#                     return redirect('index_emp')
#                 elif user.depart == 'hr':
#                     return redirect('index_hr')
#                 else:
#                     messages.error(request, 'Invalid department.')
#             else:
#                 messages.error(request, 'Username or password is incorrect.')
#         except RegisterAll.DoesNotExist:
#             messages.error(request, 'Username or password is incorrect.')

#     return render(request, 'loginpage.html')    
def encrypt(new_password1, key):
    key = hashlib.sha256(key.encode()).digest()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext_bytes = cipher.encrypt(pad(new_password1.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext_bytes).decode()
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def change_password(request):
    if not request.session.get('username'):
        return redirect('loginpage')

    if request.method == 'POST':
        old_password = request.POST['oldpassword']
        new_password1 = request.POST['newpassword']
        confirm_password = request.POST['confirmpwd']

        user = RegisterAll.objects.get(user_id=request.session['username'])
        ciphertext = user.pwd

        # Decrypt the stored password
        decrypted_password = decrypt(ciphertext, key)
        

        if decrypted_password == old_password:
            if new_password1 == confirm_password:
                 # Encrypt the new password
                ciphertext = encrypt(new_password1, key)
                # Update the password in the RegisterAll table
                RegisterAll.objects.filter(user_id=request.session['username']).update(pwd=ciphertext)

                messages.success(request, 'Password changed successfully.')
                # Logout the user
                logout_view(request)
                return redirect('loginpage')
            else:
                messages.error(request, 'New passwords do not match.')
        else:
            messages.error(request, 'Old password does not match.')

    return render(request, 'changepass.html')

# @cache_control(no_cache=True, must_revalidate=True, no_store=True)
# def change_password_emp(request):
#     if not request.session.get('username'):
#         return redirect('loginpage')

#     if request.method == 'POST':
#         old_password = request.POST['oldpassword']
#         new_password = request.POST['newpassword']
#         confirm_password = request.POST['confirmpwd']

#         user = RegisterAll.objects.get(user_id=request.session['username'])

#         if user.pwd == old_password:
#             if new_password == confirm_password:
#                 # Update the password in the RegisterAll table
#                 RegisterAll.objects.filter(user_id=request.session['username']).update(pwd=new_password)

#                 messages.success(request, 'Password changed successfully.')
#                 # Logout the user
#                 logout_view(request)
#                 return redirect('loginpage')
#             else:
#                 messages.error(request, 'New passwords do not match.')
#         else:
#             messages.error(request, 'Old password does not match.')

#     return render(request, 'changepass_emp.html')
# decrypted = decrypt(ciphertext, key)


def encrypt(new_password, key):
    key = hashlib.sha256(key.encode()).digest()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext_bytes = cipher.encrypt(pad(new_password.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext_bytes).decode()
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def change_password_emp(request):
    if not request.session.get('username'):
        return redirect('loginpage')

    if request.method == 'POST':
        old_password = request.POST.get('oldpassword')
        new_password = request.POST.get('newpassword')
        confirm_password = request.POST.get('confirmpwd')

        user = RegisterAll.objects.get(user_id=request.session['username'])
        ciphertext = user.pwd

        # Decrypt the stored password
        decrypted_password = decrypt(ciphertext, key)  # Assuming key is defined elsewhere

        if decrypted_password == old_password:
            if new_password == confirm_password:
                # Encrypt the new password
                ciphertext = encrypt(new_password, key)
                # Update the password in the RegisterAll table
                RegisterAll.objects.filter(user_id=request.session['username']).update(pwd=ciphertext)

                messages.success(request, 'Password changed successfully.')
                # Logout the user
                logout_view(request)
                return redirect('loginpage')
            else:
                messages.error(request, 'New passwords do not match.')
        else:
            messages.error(request, 'Old password does not match.')

    return render(request, 'changepass_emp.html')



@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def change_password_adm(request):
    if not request.session.get('username'):
        return redirect('loginpage')

    if request.method == 'POST':
        old_password = request.POST['oldpassword']
        new_password = request.POST['newpassword']
        confirm_password = request.POST['confirmpwd']

        user = RegisterAll.objects.get(user_id=request.session['username'])

        if user.pwd == old_password:
            if new_password == confirm_password:
                # Update the password in the RegisterAll table
                RegisterAll.objects.filter(user_id=request.session['username']).update(pwd=new_password)

                messages.success(request, 'Password changed successfully.')
                # Logout the user
                logout_view(request)
                return redirect('loginpage')
            else:
                messages.error(request, 'New passwords do not match.')
        else:
            messages.error(request, 'Old password does not match.')

    return render(request, 'changepass_adm.html')


# from datetime import datetime
# from django.utils import timezone
# def logout_view(request):
#     if 'username' in request.session:
#         user = request.session['username']
#         # Clear the session
#         request.session.clear()
#         request.session.save()
#         # Get the current local time
#         current_datetime = datetime.now()
#         formatted_time = current_datetime.strftime("%I:%M:%S")
#         print(f'formatted_time : {formatted_time}')
#         log_out_dt_tm = current_datetime
#         print(f'current_datetime : {current_datetime}')
#         print(f'log_out_dt_tm : {log_out_dt_tm}')
#         # Get the last entry for the user
#         last_entry = Visiters.objects.filter(user=user).order_by('-log_in_dt_tm').first()
#         if last_entry:
#             # Update the logout time and save the entry
#             last_entry.log_out_tm = formatted_time
#             last_entry.log_out_dt = current_datetime.date()
#             last_entry.log_out_dt_tm = current_datetime
#             last_entry.save()
#         # Redirect to the login page
#         return redirect('loginpage')
#     else:
#         # If the 'username' key is not present, redirect to the login page
#         return redirect('loginpage')

def logout_view(request):
    if 'username' in request.session:
        user = request.session['username']
        # Clear the session
        request.session.clear()
        request.session.save()
        # Activate the Indian time zone
        timezone.activate('Asia/Kolkata')
        # Get the current time in Indian time zone
        current_datetime = timezone.localtime(timezone.now())
        formatted_time = current_datetime.strftime("%H:%M:%S")  # Adding AM/PM to the time format
        date = current_datetime.date()
        
        print(f"date: {date}")
        print(f'formatted_time: {formatted_time}')
        log_out_dt_tm = f"{date} {formatted_time}"
        print(f'current_datetime: {current_datetime}')
        print(f'log_out_dt_tm: {log_out_dt_tm}')
        
        # Get the last entry for the user
        last_entry = Visiters.objects.filter(user=user).order_by('-log_in_dt_tm').first()
        if last_entry:
            # Update the logout time and save the entry
            last_entry.log_out_tm = formatted_time
            last_entry.log_out_dt = date
            last_entry.log_out_dt_tm = log_out_dt_tm
            last_entry.save()
        # Redirect to the login page
        return redirect('loginpage')
    else:
        # If the 'username' key is not present, redirect to the login page
        return redirect('loginpage')
    
from datetime import datetime
# from django.utils import timezone
def logout(request):
    if 'username' in request.session:
        user = request.session['username']
        
        # Clear the session
        request.session.clear()
        request.session.save()
        
        # Get the current local time
        current_datetime = datetime.now()
        log_out_dt_tm = current_datetime
        
        print(f'current_datetime : {current_datetime}')
        print(f'log_out_dt_tm : {log_out_dt_tm}')
        
        # Get the last entry for the user
        last_entry = Visiters.objects.filter(user=user).order_by('-log_in_dt_tm').first() 

        if last_entry:
            # Update the logout time and save the entry
            last_entry.log_out_tm = current_datetime.time()
            last_entry.log_out_dt = current_datetime.date()
            last_entry.log_out_dt_tm = current_datetime
            last_entry.save()
        
        # Redirect to the login page
        return redirect('loginpage')
    else:
        # If the 'username' key is not present, redirect to the login page
        return redirect('loginpage')



# def logout(request):
#     # Check if the 'username' key exists in the session
#     if 'username' in request.session:
#         user = request.session['username']
        
#         # Clear the entire session
#         # request.session.clear()
#         # # Save the session
#         # request.session.save()
#         # current_datetime = timezone.localtime(timezone.now())
#         # log_out_dt_tm = datetime.combine(current_datetime.date(), current_datetime.now().time())
#         # print(f'log_out_dt_tm : {log_out_dt_tm}')
#         # # Get the last entry for the user
#         # last_entry = Visiters.objects.filter(user=user).order_by('-log_in_dt_tm').first()
#         # if last_entry:
#         #     # Update the logout time and save the entry
#         #     last_entry.log_out_tm = current_datetime.now().time()
#         #     last_entry.log_out_dt_tm = log_out_dt_tm
#         #     last_entry.save()

#         request.session.clear()
#         # Save the session
#         request.session.save()
#         current_datetime = timezone.localtime(timezone.now())
#         print(f'current_datetime : {current_datetime}')
#         log_out_dt_tm = datetime.combine(current_datetime.date(), current_datetime.now().time())
#         print(f'log_out_dt_tm : {log_out_dt_tm}')
#         # Get the last entry for the user
#         last_entry = Visiters.objects.filter(user=user).order_by('-log_in_dt_tm').first() 

#         if last_entry:
#             # Update the logout time and save the entry
#             last_entry.log_out_tm = current_datetime.now().time()
#             last_entry.log_out_dt_tm = log_out_dt_tm
#             last_entry.save()
# # Redirect to the login page
#         # Redirect to the login page
#         return redirect('loginpage')
#     else:
#         # If the 'username' key is not present, redirect to the login page
#         return redirect('loginpage')
    


""" ADD DEPARTMENT """
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def add_depart(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    # if request.method=='POST':
    #     nm=request.POST['departmentName']
    #     # Check if department with the same name already exists
    #     if AddDepartment.objects.filter(nm=nm).exists():
    #         messages.error(request, 'Department with this name already exists')
    #         return redirect('add_depart')
    #     new_nm=AddDepartment(nm=nm)
    #     new_nm.save()
    #     messages.success(request, 'Department added successfully')
    #     return redirect('add_depart')
        # return render(request,'add_depart.html')
    data=AddDepartment.objects.all()
    if(data!=''):
        #
        return render(request,'add_depart.html',{'data':data, 'current_user': current_user , 'branches': branches,'default_branch':default_branch})
    else:
        return render(request,'add_depart.html')
        

def delete_depart(request, id):
    data = AddDepartment.objects.get(id=id)
    data.delete()
    # messages.error(request,"Deleted successsfully!!")
    return redirect('add_depart')

def update_department(request, department_id):
    if request.method == 'POST':
        new_name = request.POST.get('new_name')
        # Check if the updated department name already exists
        existing_department = AddDepartment.objects.filter(nm=new_name).exclude(id=department_id).first()
        if existing_department:
            # If the department name already exists, return an error response
            return JsonResponse({'success': False, 'error': 'Department name already exists'})
        # Update the department name
        department = get_object_or_404(AddDepartment, pk=department_id)
        department.nm = new_name
        department.save()
        # Return a success response
        return JsonResponse({'success': True})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})


@csrf_exempt
@csrf_exempt
def check_existence_view(request):
    if request.method == 'POST':
        value_to_check = request.POST.get('value', None)
        # Check if the value exists in the 'nm' field of the AddDepartment model
        exists_in_database = AddDepartment.objects.filter(nm=value_to_check).exists()
        if not exists_in_database:
            # If the value doesn't exist, add it to the database
            new_department = AddDepartment(nm=value_to_check)
            messages.success(request, 'Department added successfully')
            new_department.save()
        response_data = {'exists': exists_in_database}
        return JsonResponse(response_data)
    return JsonResponse({'error': 'Invalid request method'})

""" ADD DEPARTMENT HEAD/TL """
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def departmenthead(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    
    selected_branch_id = None
    if 'selected_branch_id' in request.session:
        selected_branch_id = request.session['selected_branch_id']
        default_branch = request.session['default_branch_id']
        
    select_all = None
    if 'selected_all' in request.session:
        select_all = request.session['selected_all']
        
    if request.method == 'POST':
        dept = request.POST.get('departmentHead', '')
        desig = request.POST.get('designation', '')
        emp_id = request.POST['emp_id']
        name = request.POST['name']
        branch_name = request.POST['branch']
        
        newadd_depart = AddDepartmentHead(dept=dept, desig=desig, emp_id=emp_id, name=name, branch=branch_name)
        newadd_depart.save()
        messages.success(request, 'Department Head added successfully')
        return redirect('departmenthead')
    
    if select_all:
        newadd_depart = AddDepartmentHead.objects.all()
    elif selected_branch_id:
        newadd_depart = AddDepartmentHead.objects.filter(branch=selected_branch_id)
    else:
        newadd_depart = AddDepartmentHead.objects.filter(branch=default_branch)

    return render(request, 'department_head.html', {'newadd_depart': newadd_depart, 'current_user': current_user, 'branches': branches ,'branch_name': selected_branch_id , 'default_branch':default_branch})






def update_department_head(request, id):
    if request.method == 'POST':
        # Get the existing department record
        department = get_object_or_404(AddDepartmentHead, id=id)

        # Get the updated values from the request
        updated_department_name = request.POST.get('updatedDepartmentName')
        designation = request.POST.get('designation')
        employee_id = request.POST.get('employeeid')
        name = request.POST.get('name')
        branch = request.POST.get('branch')

        # Update the fields with new values
        department.dept = updated_department_name
        department.desig = designation
        department.emp_id = employee_id
        department.name = name
        department.branch = branch
        
        # Save the changes
        department.save()
        
        # Return a success response
        return JsonResponse({'success': True})
    else:
        # Return an error response for non-POST requests
        return JsonResponse({'success': False, 'error': 'Invalid request method'})

def delete(request,id):
     data = AddDepartmentHead.objects.get(id=id)
     data.delete()
     messages.error(request,"Deleted successsfully!!")
     return redirect('departmenthead')


""" ADD BRANCH """
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def add_branch(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    if request.method == 'POST':
        office = request.POST['office_name']
        branch = request.POST['branch_name']
        location = request.POST['location']
        adminid = request.POST['adminid']
        employeeid = request.POST['employeeid']
        traineeid = request.POST['traineeid']
        office_number = request.POST['office_number']
        # Check if the combination already exists
        existing_branch = Branch.objects.filter(admin_code=adminid, employee_code=employeeid, trainee_code=traineeid).first()
        if existing_branch:
            # If the combination already exists, add a message to the Django messages framework
            messages.error(request, 'Combination already exists. Please enter unique codes.')
            return redirect('add_branch')
        if Branch.objects.filter(Q(admin_code=adminid) | Q(employee_code=employeeid) | Q(trainee_code=traineeid)).exists():
            messages.error(request, 'Admin ID, Employee ID, and Trainee ID should not be repeated.')
            return redirect('add_branch')
        # Check if admin, employee, and trainee IDs are unique and distinct
        existing_ids = set(Branch.objects.values_list('admin_code', flat=True)) | \
                    set(Branch.objects.values_list('employee_code', flat=True)) | \
                    set(Branch.objects.values_list('trainee_code', flat=True))
        if adminid in existing_ids or employeeid in existing_ids or traineeid in existing_ids:
            messages.error(request, 'Admin ID, Employee ID, and Trainee ID must be unique.')
            return redirect('add_branch')
            # Check if admin code is the same for employee and trainee
        if adminid == employeeid and adminid == traineeid:
            messages.error(request, 'Admin ID, Employee ID, and Trainee ID must be different.')
            return redirect('add_branch')
                # Check if admin code is the same for employee and trainee
        if adminid == employeeid or adminid == traineeid or employeeid == traineeid:
            messages.error(request, 'Admin ID, Employee ID, and Trainee ID must be different.')
            return redirect('add_branch')
        existing_office_name=Branch.objects.filter(office_name=office).first()
        if existing_office_name:
            messages.error(request, 'Office name already exist.')
            return redirect('add_branch')
        existing_branch_name=Branch.objects.filter(branch_name=branch).first()
        if existing_branch_name:
            messages.error(request, 'Branch name already exist.')
            return redirect('add_branch')
        # If the combination does not exist, proceed to add the new branch
        add_branch = Branch(office_name=office, branch_name=branch, addr=location, admin_code=adminid, employee_code=employeeid, trainee_code=traineeid,office_number=office_number)
        add_branch.save()
        messages.success(request, 'Branch added successfully')
        return redirect('add_branch')
    add_branch = Branch.objects.all()
    return render(request, 'add_branch.html', {'add_branch': add_branch, 'current_user': current_user , 'branches': branches, 'default_branch':default_branch})




def update_branch(request, id):
    if request.method == 'POST':
        # Fetch the branch with the given id
        branch = get_object_or_404(Branch, id=id)
        # Get the data from the request
        updated_office_name = request.POST.get('updatedOfficeName')
        office_number = request.POST.get('officeNumber')
        branch_name = request.POST.get('branchName')
        branch_name1 = request.POST.get('branchName1')
        print(f'branch_name1 : {branch_name1}')
        location = request.POST.get('location')
        admin_id = request.POST.get('adminId')
        employee_code = request.POST.get('employeeCode')
        trainee_code = request.POST.get('traineeCode')
        # Check if the combination already exists
        existing_branch = Branch.objects.filter(admin_code=admin_id, employee_code=employee_code, trainee_code=trainee_code).exclude(id=id).first()
        existing_admin_code = Branch.objects.filter(admin_code=admin_id).exclude(id=id).first()
        existing_employee_code = Branch.objects.filter(employee_code=employee_code).exclude(id=id).first()
        existing_trainee_code = Branch.objects.filter( trainee_code=trainee_code).exclude(id=id).first()
        existing_office_name = Branch.objects.filter( office_name=updated_office_name).exclude(id=id).first()
        # Check if admin, employee, and trainee IDs are unique and distinct
        existing_ids = set(Branch.objects.exclude(id=id).values_list('admin_code', flat=True)) | \
               set(Branch.objects.exclude(id=id).values_list('employee_code', flat=True)) | \
               set(Branch.objects.exclude(id=id).values_list('trainee_code', flat=True))
                # Check if admin, employee, and trainee IDs are unique and distinct
        print(f'Existing_Ids :{existing_ids}')
        if admin_id in existing_ids or employee_code in existing_ids or trainee_code in existing_ids:
            return JsonResponse({'success': False, 'error': 'Already exists. Please enter unique codes'})
        if admin_id == employee_code and admin_id == trainee_code:
            return JsonResponse({'success': False, 'error': 'Already exists. Please enter unique codes'})
                # Check if admin code is the same for employee and trainee
        if admin_id == employee_code or admin_id == trainee_code or employee_code == trainee_code:
            return JsonResponse({'success': False, 'error': 'Already exists. Please enter unique codes'})
        if existing_branch:
            # If the combination already exists, add a message and return an error response
            return JsonResponse({'success': False, 'error': 'Already exists. Please enter unique codes'})
        if existing_admin_code:
            # If the combination already exists, add a message and return an error response
            return JsonResponse({'success': False, 'error': 'Already exists. Please enter unique Admin code'})
        if existing_employee_code:
            # If the combination already exists, add a message and return an error response
            return JsonResponse({'success': False, 'error': 'Already exists. Please enter unique Employee code'})
        if existing_trainee_code:
            # If the combination already exists, add a message and return an error response
            return JsonResponse({'success': False, 'error': 'Already exists. Please enter unique Trainee code'})
        if existing_trainee_code:
            # If the combination already exists, add a message and return an error response
            return JsonResponse({'success': False, 'error': 'Already exists. Please enter unique Trainee code'})
        if existing_office_name:
            # If the combination already exists, add a message and return an error response
            return JsonResponse({'success': False, '': 'Already exists. Please enter unique Office name'})
        # existing_branch_number = Branch.objects.filter(office_number=office_number).exclude(id=id).first()
        # if existing_branch_number:
        #     return JsonResponse({'success': False, '': 'Office number already exists'})
        existing_office_name = Branch.objects.filter(office_name=updated_office_name).exclude(id=id).first()
        if existing_office_name:
            return JsonResponse({'success': False, '': 'Office name already exists'})
        existing_branch_name = Branch.objects.filter(branch_name=branch_name).exclude(id=id).first()
        if existing_branch_name:
            return JsonResponse({'success': False, '': 'Branch name already exists'})
        # If no conflicts are found, proceed with the update
        branch.office_name = updated_office_name
        branch.office_number = office_number
        branch.branch_name = branch_name
        branch.addr = location
        branch.admin_code = admin_id
        branch.employee_code = employee_code
        branch.trainee_code = trainee_code
        branch.save()
        # Update the related RegisterAll model
        register_all_instances = RegisterAll.objects.filter(branch_name=branch_name1)
        for register_all_instance in register_all_instances:
            register_all_instance.branch_name = branch_name
            register_all_instance.save()
        return JsonResponse({'success': True})
    else:
        # Return an error response for non-POST requests
        return JsonResponse({'success': False, 'error': 'Invalid request method'})

def delete_branch(request,id):
     data = Branch.objects.get(id=id)
     data.delete()
     messages.error(request,"Deleted successsfully!!")
     return redirect('add_branch')


def get_companies(request):
    companies = Branch.objects.values_list('office_name', flat=True)
    companies_list = list(companies)
    return JsonResponse({'companies': companies_list}, safe=False)




def get_department(request):
    departments = AddDepartmentHead.objects.values_list('dept', flat=True)
    department_list = list(departments)
    return JsonResponse({'departments': department_list}, safe=False)




def get_employee_codes_by_company(request):
    selected_company = request.GET.get('company', None)
    print(f"company: {selected_company}")

    try:
        # Retrieve the user_id from the registerall table based on the selected company
        employee_user_info = RegisterAll.objects.filter(company=selected_company,depart='emp').order_by('-user_id').values('user_id').first()
        print(f"last_generated_code: {employee_user_info}")

        # If no code is found in the session, set a default value
        last_generated_code = 1000  # Default value


        # If user_info is not None, extract the user_id and update last_generated_code
        if employee_user_info:
            user_id_str = employee_user_info['user_id']
            if len(user_id_str) == 7:
                last_generated_code = int(user_id_str[3:])
            elif len(user_id_str) == 8:
                last_generated_code = int(user_id_str[4:]) 
            elif len(user_id_str) == 6:
                last_generated_code = int(user_id_str[2:]) 
            elif len(user_id_str) == 9:
                last_generated_code = int(user_id_str[5:])
              # Extract numeric part and convert to int
            

        # Increment the last generated code for the new one
        new_generated_code = last_generated_code + 1

        # Fetch employee codes based on the selected company
        employee_codes = Branch.objects.filter(office_name=selected_company).values_list('employee_code', flat=True)
        print(f"codes: {employee_codes}")

        # Convert employee_codes queryset to a list
        employee_codes_list = list(employee_codes)

        # Append the new generated code
        employee_codes_list.append(new_generated_code)

        return JsonResponse({'employee_codes': employee_codes_list, 'random_code': new_generated_code}, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)



def get_admin_codes_by_company(request):
    selected_company = request.GET.get('company', None)
    print(f"company: {selected_company}")
    try:
        # Retrieve the user_id from the registerall table based on the selected company
        admin_user_info = RegisterAll.objects.filter(company=selected_company,depart='ad').order_by('-user_id').values('user_id').first()
        print(f"last_generated_code_admin: {admin_user_info}")
        # If no code is found in the session, set a default value
        last_generated_code = 1000  # Default value
        # If user_info is not None, extract the user_id and update last_generated_code
        if admin_user_info:
            user_id_str = admin_user_info['user_id']
            if len(user_id_str) == 7:
                last_generated_code = int(user_id_str[3:])
            elif len(user_id_str) == 8:
                last_generated_code = int(user_id_str[4:]) 
            elif len(user_id_str) == 6:
                last_generated_code = int(user_id_str[2:]) 
            elif len(user_id_str) == 9:
                last_generated_code = int(user_id_str[5:])             # Extract numeric part and convert to int
        # Increment the last generated code for the new one
        new_generated_code = last_generated_code + 1
        print(f"new_generated_code {new_generated_code}")
        # Fetch employee codes based on the selected company
        employee_codes = Branch.objects.filter(office_name=selected_company).values_list('admin_code', flat=True)
        print(f"codes: {employee_codes}")
        # Convert employee_codes queryset to a list
        employee_codes_list = list(employee_codes)
        
        # Append the new generated code
        employee_codes_list.append(new_generated_code)
        return JsonResponse({'employee_codes': employee_codes_list, 'random_code': new_generated_code}, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

    

def get_office_number(request):
    selected_company = request.GET.get('company', None)
    print(f"company: {selected_company}")

    try:
        # Fetch office numbers based on the selected company
        office_numbers = Branch.objects.filter(office_name=selected_company).values_list('office_number', flat=True)
        print(f"office numbers: {office_numbers}")

        # Convert queryset to a list
        office_number_list = list(office_numbers)

        return JsonResponse({'office_numbers': office_number_list}, safe=False)
    except Exception as e:
        print(f"Error: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)
    

def get_branch_name(request):
    selected_company = request.GET.get('company', None)
    print(f"company ghjygh: {selected_company}")

    try:
        # Fetch office numbers based on the selected company
        branch_name = Branch.objects.filter(office_name=selected_company).values_list('branch_name', flat=True)
        print(f"branch_name: {branch_name}")

        # Convert queryset to a list
        branch_name_list = list(branch_name)

        return JsonResponse({'branch_name': branch_name_list}, safe=False)
    except Exception as e:
        print(f"Error: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)



      

import json
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
@csrf_exempt  # Use csrf_exempt for simplicity in this example; in a production setting, handle CSRF properly
@require_POST
def get_department_info(request):
    try:
        data = json.loads(request.body)
        selected_department = data.get('department', None)
        selected_branch_id = request.session.get('selected_branch_id')
        default_branch = request.session.get('default_branch_id')
        
        if selected_department is not None:
            if selected_branch_id is not None:
                employees = AddDepartmentHead.objects.filter(dept=selected_department, branch=selected_branch_id)
            else:
                employees = AddDepartmentHead.objects.filter(dept=selected_department, branch=default_branch)
            
            # Create a list to store the employee information
            employee_info = []
            for employee in employees:
                # Append relevant information to the list
                employee_info.append({
                    'name': employee.name,
                    'desig': employee.desig,
                    # Add other fields as needed
                })
            return JsonResponse(employee_info, safe=False)
        else:
            # Handle the case where the selected department is not provided
            return JsonResponse({'error': 'Department not provided'}, status=400)
    except json.JSONDecodeError:
        # Handle the case where the request body is not valid JSON
        return JsonResponse({'error': 'Invalid JSON in request body'}, status=400)


import os
import random
import string

from django.core.files.storage import default_storage

def random_string(length=10):
    """Generate a random string of letters and digits."""
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choices(letters_and_digits, k=length))



from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64


key = "staffin"

def encrypt(plaintext, key):
    key = hashlib.sha256(key.encode()).digest()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext_bytes).decode()


from django.core.files.storage import default_storage
import datetime
def empinsert(request):
    if request.method == 'POST':
        depart = request.POST.get('emp', 'emp')
        nm = request.POST['name']
        frontname = request.POST['frontname']
        # full_name = frontname + nm
        # print(f"full_name {full_name}")
        user_id = request.POST['employeeCode']


        pwd = request.POST['password']
        ciphertext = encrypt(pwd, key)
        print("Encrypted:", ciphertext)

        # hashed_password = hash_password(pwd)
        mob = request.POST['mobilenumber']
        # addr = request.POST['address']
        if 'address' in request.POST:
            addr = request.POST['address']
        # Check if the address field is empty
        if not addr:
            addr = ""
        em_depart = request.POST.get('departmentHead')
        em_depart_hed = request.POST['userDepartmentHead']
        em_depart_tl = request.POST['userDepartmentTL']
        # no_of_cl = request.POST['nocl']
        if 'nocl' in request.POST:
            no_of_cl = request.POST['nocl']
        # Check if the address field is empty
        if not no_of_cl:
            no_of_cl = ""
        # email = request.POST['email']
        if 'email' in request.POST:
            email = request.POST['email']
        # Check if the address field is empty
        if not email:
            email = ""
        pic = request.FILES.get('profile')  # Corrected to request.FILES
        # permi = request.POST['permission']
        if 'permission' in request.POST:
            permi = request.POST['permission']
            # Check if the permission field is empty
            if not permi:
                permi = "0:0:0"
            else:
                try:
                    # Attempt to parse the time value
                    parse_time(permi)
                except ValueError:
                    # Handle the case where the time format is invalid
                    permi = "0:0:0"
        team_ld = int(request.POST.get('team_ld', 0))
        # dsig = request.POST['designation']
        if 'designation' in request.POST:
            dsig = request.POST['designation']
        # Check if the address field is empty
        if not dsig:
            dsig = ""

        workfrom_time = request.POST['workfrom']
        workfrom_period = request.POST.get('workfrom_period')
        numberSelect = request.POST.get('numberSelect')

        workfrom_combined = f"{workfrom_time}:{numberSelect} {workfrom_period}"
        print(f"workfrom_combined {workfrom_combined}")
        

        workto_time = request.POST['workto']
        workto_period = request.POST.get('workto_period')
        worktoSelect = request.POST.get('worktoSelect')
        workto_combined = f"{workto_time}:{worktoSelect} {workto_period}"
        print(f"workfrom_combined {workto_combined}")

    # Combine time and period into a single string
        # workfrom_combined = f"{workfrom_time} {workfrom_period}"
        # workto_combined = f"{workto_time} {workto_period}"

    # Convert the combined strings to time objects
        workfrom_time_obj = datetime.strptime(workfrom_combined, '%I:%M %p').time()
        workto_time_obj = datetime.strptime(workto_combined, '%I:%M %p').time()

    # Combine time and period into a single string
        # workfrom_combined = f"{workfrom_time} {workfrom_period}"
        # workto_combined = f"{workto_time} {workto_period}"


        

    # Convert the combined strings to time objects
        # workfrom_time_obj = datetime.strptime(workfrom_combined, '%I:%M %p').time()
        # workto_time_obj = datetime.strptime(workto_combined, '%I:%M %p').time()
        # workfrom_time_obj = datetime.strptime(workfrom_combined, '%H:%M %p').time()
        # workto_time_obj = datetime.strptime(workto_combined, '%H:%M %p').time()
        # sala = request.POST['salary']
        if 'salary' in request.POST:
            sala = request.POST['salary']
        # Check if the address field is empty
        if not sala:
            sala = "0"
        # doj = request.POST['doj']
        doj = request.POST.get('doj')

        # Check if doj is provided
        if doj:
            # If provided, use the input date
            doj = doj
        else:
            # If not provided, use the default value '2000-01-01'
            doj = '2000-01-01'    
        pf_cd = request.POST['pfcode']
            
            
        
        locca = ""  # Initialize locca to an empty string
        if 'locationDropdown' in request.POST:
            locca = request.POST.get('locationDropdown')
            print(f"locca {locca}")
        # Check if the address field is empty
        if not locca:
            locca = ""

        bank = request.POST['bank']
        acc_no = request.POST['account']
        ifsc = request.POST['ifsc']
        # dob = request.POST['dob']
        dob = request.POST.get('dob')

        # Check if dob is provided
        if dob:
            # If provided, use the input date
            dob = dob
        else:
            # If not provided, use the default value '2000-01-01'
            dob = '2000-01-01'
       
       
            
        pf_amt = int(request.POST.get('pf_amt', 0))
        
        
        sd_amt = int(request.POST.get('sd_amt', 0))
        
        company = request.POST.get('companyName')
        # fath_nm = request.POST['fathername']
        if 'fathername' in request.POST:
            fath_nm = request.POST['fathername']
        # Check if the address field is empty
        if not fath_nm:
            fath_nm = ""
        # blood = request.POST['blood']
        if 'blood' in request.POST:
            blood = request.POST['blood']
        else:
            blood = ""


        if 'insu' in request.POST:
            insu_amt = request.POST['insu']
        if not insu_amt:
            insu_amt = "0"

        # hm_mob = request.POST['homemobile']
        if 'homemobile' in request.POST:
            hm_mob = request.POST['homemobile']
        if not hm_mob:
            hm_mob = "0"    
        offc_mob = request.POST['officeNumber']
        pass_chg = int(request.POST.get('pass_chg', 0))
        # insu_amt = int(request.POST.get('insu_amt', 0))
        esi_amt = int(request.POST.get('esi_amt', 0))
        # other_deduct = request.POST['deduction']
       
        other_deduct = request.POST.get('other_deduct', 0)
        
        # acti = '0'
        acti = int(request.POST.get('acti', 0))
        gender = request.POST.get('gender') 
        print(f"gender {gender}")

        if 'pan' in request.POST:
            pan_num = request.POST['pan']
        if not pan_num:
            pan_num = ""  

        if 'aadhar' in request.POST:
            aadhar_num = request.POST['aadhar']
        if not aadhar_num:
            aadhar_num = ""

        if 'bankbranch' in request.POST:
            branch = request.POST['bankbranch']
        if not branch:
            branch = ""      

        if 'employee_contri' in request.POST:
            employee_contri = request.POST['employee_contri']
        if not employee_contri:
            employee_contri = ""      

        if 'employer_contri' in request.POST:
            employer_contri = request.POST['employer_contri']
        if not employer_contri:
            employer_contri = ""      

        reliving_dt = request.POST.get('reliving_dt', '0001-01-01')
        rejoin_dt = request.POST.get('rejoin_dt', '0001-01-01')
        print(f"reliving_dt {reliving_dt}")

        

        reg_dt = timezone.now()
        branch_name = request.POST.get('branchName')
        current_month = datetime.now().month
        current_year = datetime.now().year
        newadd_emp = RegisterAll(depart=depart, nm=nm, user_id=user_id, pwd=ciphertext, mob=mob, addr=addr, em_depart=em_depart,
                                 em_depart_hed=em_depart_hed,em_depart_tl=em_depart_tl, no_of_cl=no_of_cl, email=email, permi=permi,
                                 team_ld=team_ld, dsig=dsig, work_frm=workfrom_time_obj, work_to=workto_time_obj, sala=sala,
                                 doj=doj, pf_cd=pf_cd, locca=locca, bank=bank, acc_no=acc_no, ifsc=ifsc,pic=pic,
                                 dob=dob, pf_amt=pf_amt, sd_amt=sd_amt, company=company, fath_nm=fath_nm,
                                 blood=blood, hm_mob=hm_mob, pass_chg=pass_chg, insu_amt=insu_amt,offc_mob=offc_mob,other_deduct=other_deduct,
                                 esi_amt=esi_amt, acti=acti, reg_dt=reg_dt, mnth=current_month, yr=current_year,branch_name=branch_name , gender=gender , pan_num=pan_num , aadhar_num=aadhar_num , branch=branch ,employee_contri=employee_contri,employer_contri=employer_contri ,mr_mrs_ms= frontname,reliving_dt=reliving_dt,rejoin_dt=rejoin_dt)

        # Check if a profile picture is provided
        if pic:
            # Generate a random filename
            random_filename = f'{random_string()}.png'

            # Build the file path
            file_path = f'static/upload/{random_filename}'

            # Save the uploaded file
            with default_storage.open(file_path, 'wb') as destination:
                for chunk in pic.chunks():
                    destination.write(chunk)

            # Update the 'pic' field in the model with the file path
            newadd_emp.pic = random_filename
        else:
            newadd_emp.pic = 'images.png'
        newadd_emp.save()

        messages.success(request, 'Employee Register successfully')
        return redirect('employee_admin')
        
    # Render your form template for GET requests
    return render(request, 'employee_admin.html')

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def employee_view(request):
    context = {}
    if 'username' in request.session:
        current_user = request.session.get('username')
        default_branch = request.session['default_branch_id']
        select_all = request.session.get('selected_all', False)
        branches = Branch.objects.all()

        # Check if selected_branch_id is in the session
        if 'selected_branch_id' in request.session:
            selected_branch_id = request.session['selected_branch_id']
        elif default_branch:
            selected_branch_id = default_branch  # If not, default to default_branch
        else:
            select_all = True    # If not, default to default_branch

        try:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.employee_code[:3]
        except Branch.DoesNotExist:
            return HttpResponse(status=404)
        
        try:
            branch_default = Branch.objects.get(branch_name=default_branch)
            default_branch_employee_code = branch_default.employee_code[:3]
        except Branch.DoesNotExist:
            return HttpResponse(status=404)
        
        # Filter employees based on the selected branch or default branch
        if 'selected_branch_id' in request.session:
            employees = RegisterAll.objects.filter(depart='emp', user_id__startswith=selected_branch_employee_code)

        elif select_all:
            employees = RegisterAll.objects.filter(depart='emp')
        else:
            employees = RegisterAll.objects.filter(depart='emp', user_id__startswith=default_branch_employee_code)    
        # else:
        #     employees = RegisterAll.objects.filter(depart='emp', user_id__startswith=default_branch_employee_code)

        context = {
            'employee': employees,
            'current_user': current_user,
            'selected_branch_id': selected_branch_id,
            'branches': branches,
            'default_branch': default_branch
        }
        return render(request, 'employee_view.html', context)
    else:
        return redirect('loginpage')


# def employee_view(request):
#     if 'username' in request.session:
#         current_user = request.session.get('username')
#         default_branch = request.session['default_branch_id']
#         branches = Branch.objects.all()

#         if 'selected_branch_id' in request.session:
#             selected_branch_id = request.session['selected_branch_id']
#             default_branch = request.session['default_branch_id']

#             try:
#                 branch = Branch.objects.get(branch_name=selected_branch_id)
#                 selected_branch_employee_code = branch.employee_code[:3]
#             except Branch.DoesNotExist:
#                 return HttpResponse(status=404)

#             employees = RegisterAll.objects.filter(depart='emp', user_id__startswith=selected_branch_employee_code)

#             context = {
#                 'employee': employees,
#                 'current_user': current_user,
#                 'selected_branch_id': selected_branch_id,
#                 'branches': branches,
#                 'default_branch':default_branch
#             }
#             return render(request, 'employee_view.html', context)
#         else:
#             # If no branch is selected, retrieve all employees without filtering
#             employees = RegisterAll.objects.filter(depart='emp')

#             context = {
#                 'employee': employees,
#                 'current_user': current_user,
#                 'branches': branches,
#                 'default_branch':default_branch
#             }
#             return render(request, 'employee_view.html', context)
#     else:
#         return redirect('loginpage')





@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def admin_view(request):
    context = {}
    
    if 'username' in request.session:
        current_user = request.session.get('username')
        default_branch = request.session.get('default_branch_id')
        select_all = request.session.get('selected_all', False)  # Set default value to False if 'selected_all' is not in session
        branches = Branch.objects.all()

        # Check if selected_branch_id is in the session
        if 'selected_branch_id' in request.session:
            selected_branch_id = request.session['selected_branch_id']
        elif default_branch:
            selected_branch_id = default_branch  # If not, default to default_branch
        else:
            select_all = True  # If neither selected_branch_id nor default_branch is set, select all

        try:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.admin_code[:3]
        except Branch.DoesNotExist:
            return HttpResponse(status=404)

        try:
            branch_default = Branch.objects.get(branch_name=default_branch)
            default_branch_employee_code = branch_default.admin_code[:3]
        except Branch.DoesNotExist:
            return HttpResponse(status=404)

        # Filter admin for selected branch or default branch
        if 'selected_branch_id' in request.session:
            admin = RegisterAll.objects.filter(depart='ad', user_id__startswith=selected_branch_employee_code)
        elif select_all:
            admin = RegisterAll.objects.filter(depart='ad')
        else:
            admin = RegisterAll.objects.filter(depart='ad', user_id__startswith=default_branch_employee_code)

        context = {
            'admin': admin,
            'current_user': current_user,
            'selected_branch_id': selected_branch_id,
            'branches': branches,
            'default_branch': default_branch
        }

    return render(request, 'admin_view.html', context)



# def admin_view(request):
#     context = {}
    
#     if 'username' in request.session:
#         current_user = request.session.get('username')
#         default_branch = request.session.get('default_branch_id')
#         branches = Branch.objects.all()

#         # Check if selected_branch_id is in the session
#         if 'selected_branch_id' in request.session:
#             selected_branch_id = request.session['selected_branch_id']
#         else:
#             selected_branch_id = default_branch  # If not, default to default_branch

#         try:
#             branch = Branch.objects.get(branch_name=selected_branch_id)
#             selected_branch_employee_code = branch.employee_code[:3]
#         except Branch.DoesNotExist:
#             return HttpResponse(status=404)

#         try:
#             branch_default = Branch.objects.get(branch_name=default_branch)
#             default_branch_employee_code = branch_default.employee_code[:3]
#         except Branch.DoesNotExist:
#             return HttpResponse(status=404)

#         # Filter admin for selected branch or default branch
#         if 'selected_branch_id' in request.session:
#             admin = RegisterAll.objects.filter(depart='ad', user_id__startswith=selected_branch_employee_code)
#         else:
#             admin = RegisterAll.objects.filter(depart='ad', user_id__startswith=default_branch_employee_code)

#         context = {
#             'admin': admin,
#             'current_user': current_user,
#             'selected_branch_id': selected_branch_id,
#             'branches': branches,
#             'default_branch': default_branch
#         }

#     return render(request, 'admin_view.html', context)



from django.shortcuts import render, redirect, get_object_or_404

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def trainee_view(request):
    context = {}
    if 'username' in request.session:
        current_user = request.session.get('username')
        default_branch = request.session['default_branch_id']
        select_all = request.session.get('selected_all', False) 
        branches = Branch.objects.all()

        # Check if selected_branch_id is in the session
        if 'selected_branch_id' in request.session:
            selected_branch_id = request.session['selected_branch_id']
        elif default_branch:
            selected_branch_id = default_branch  # If not, default to default_branch
        else:
            select_all = True 

        try:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.trainee_code[:3]
            print(f"selected_branch_employee_code trainee {selected_branch_employee_code}")
        except Branch.DoesNotExist:
            return HttpResponse(status=404)

        try:
            branch_default = Branch.objects.get(branch_name=default_branch)
            default_branch_employee_code = branch_default.trainee_code[:3]
        except Branch.DoesNotExist:
            return HttpResponse(status=404)

        # Filter trainees for selected branch or default branch
        if 'selected_branch_id' in request.session:
            trainee_data = RegisterAll.objects.filter(depart='trainee', user_id__startswith=selected_branch_employee_code)

        elif select_all:
            trainee_data = RegisterAll.objects.filter(depart='trainee')
        else:
            trainee_data = RegisterAll.objects.filter(depart='trainee', user_id__startswith=default_branch_employee_code)    
        # else:
        #     trainee_data = RegisterAll.objects.filter(depart='trainee', user_id__startswith=default_branch_employee_code)

        context = {
            'data': trainee_data,
            'current_user': current_user,
            'branches': branches,
            'default_branch': default_branch
        }
        return render(request, 'view_traniee.html', context)
    else:
        return redirect('loginpage')


# def trainee_view(request):
    

#     if 'username' in request.session:
#         current_user = request.session.get('username')
#         default_branch = request.session['default_branch_id']

#         branches = Branch.objects.all()

#         if 'selected_branch_id' in request.session:
#             selected_branch_id = request.session['selected_branch_id']
#             default_branch = request.session['default_branch_id']

#             try:
#                 branch = Branch.objects.get(branch_name=selected_branch_id)
#                 selected_branch_employee_code = branch.employee_code[:3]
#             except Branch.DoesNotExist:
#                 return HttpResponse(status=404)

#             trainee_data = RegisterAll.objects.filter(depart='trainee', user_id__startswith=selected_branch_employee_code)

#             context = {
#                 'data': trainee_data,
#                 'current_user': current_user,
#                 'selected_branch_id': selected_branch_id,
#                 'branches': branches,
#                 'default_branch':default_branch
#             }
#             return render(request, 'view_traniee.html', context)
#         else:
#             # If no branch is selected, retrieve all employees without filtering
#             trainee_data = RegisterAll.objects.filter(depart='trainee')


#         context = {
#                 'data': trainee_data,
#                 'current_user': current_user,
#                 'branches': branches,
#                 'default_branch':default_branch
#             }
#     return render(request, 'view_traniee.html', context)
    
from django.utils.dateparse import parse_time


def admininsert(request):
    if request.method == 'POST':
        depart = request.POST.get('ad', 'ad')
        nm = request.POST['name']
        frontname = request.POST['frontname']
        user_id = request.POST['employeeCode']
        pwd = request.POST['password']
        ciphertext = encrypt(pwd, key)
        print("Encrypted:", ciphertext)
        
        mob = request.POST['mobilenumber']
        if 'address' in request.POST:
            addr = request.POST['address']
        # Check if the address field is empty
        if not addr:
            addr = ""
        em_depart = request.POST.get('departmentHead')
        em_depart_hed = request.POST['userDepartmentHead']
        em_depart_tl = request.POST['userDepartmentTL']
        # no_of_cl = request.POST['nocl']
        if 'nocl' in request.POST:
            no_of_cl = request.POST['nocl']
        # Check if the address field is empty
        if not no_of_cl:
            no_of_cl = ""
        # email = request.POST['email']
        if 'email' in request.POST:
            email = request.POST['email']
        # Check if the address field is empty
        if not email:
            email = ""
        pic = request.FILES.get('profile')  # Corrected to request.FILES
        # permi = request.POST['permission']

        if 'permission' in request.POST:
            permi = request.POST['permission']
            # Check if the permission field is empty
            if not permi:
                permi = "0:0:0"
            else:
                try:
                    # Attempt to parse the time value
                    parse_time(permi)
                except ValueError:
                    # Handle the case where the time format is invalid
                    permi = "0:0:0"

        team_ld = int(request.POST.get('team_ld', 0))
        # dsig = request.POST['designation']
        if 'designation' in request.POST:
            dsig = request.POST['designation']
        # Check if the address field is empty
        if not dsig:
            dsig = ""
        workfrom_time = request.POST['workfrom']
        workfrom_period = request.POST.get('workfrom_period')
        numberSelect = request.POST.get('numberSelect')

        workfrom_combined = f"{workfrom_time}:{numberSelect} {workfrom_period}"
        print(f"workfrom_combined {workfrom_combined}")
        

        workto_time = request.POST['workto']
        workto_period = request.POST.get('workto_period')
        worktoSelect = request.POST.get('worktoSelect')
        workto_combined = f"{workto_time}:{worktoSelect} {workto_period}"
        print(f"workfrom_combined {workto_combined}")

    # Combine time and period into a single string
        # workfrom_combined = f"{workfrom_time} {workfrom_period}"
        # workto_combined = f"{workto_time} {workto_period}"

    # Convert the combined strings to time objects
        workfrom_time_obj = datetime.strptime(workfrom_combined, '%I:%M %p').time()
        workto_time_obj = datetime.strptime(workto_combined, '%I:%M %p').time()
        # workfrom_time_obj = datetime.strptime(workfrom_combined, '%H:%M %p').time()
        # workto_time_obj = datetime.strptime(workto_combined, '%H:%M %p').time()
        # sala = request.POST['salary']
        if 'salary' in request.POST:
            sala = request.POST['salary']
        # Check if the address field is empty
        if not sala:
            sala = "0"
        doj = request.POST.get('doj')

        # Check if doj is provided
        if doj:
            # If provided, use the input date
            doj = doj
        else:
            # If not provided, use the default value '2000-01-01'
            doj = '2000-01-01'
        pf_cd = request.POST['pfcode']
        locca = ""  # Initialize locca to an empty string
        if 'locationDropdown' in request.POST:
            locca = request.POST.get('locationDropdown')
        # Check if the address field is empty
        if not locca:
            locca = ""
        bank = request.POST['bank']
        acc_no = request.POST['account']
        ifsc = request.POST['ifsc']
            # Assuming your DateField is named 'dob' in your model
        dob = request.POST.get('dob')

        # Check if dob is provided
        if dob:
            # If provided, use the input date
            dob = dob
        else:
            # If not provided, use the default value '2000-01-01'
            dob = '2000-01-01'
        # pf_amt = request.POST['pfamount']

        
        pf_amt = int(request.POST.get('pf_amt', 0))
        
        
        sd_amt = int(request.POST.get('sd_amt', 0))
        
        company = request.POST.get('companyName')
        # fath_nm = request.POST['fathername']
        if 'fathername' in request.POST:
            fath_nm = request.POST['fathername']
        # Check if the address field is empty
        if not fath_nm:
            fath_nm = ""
        # blood = request.POST['blood']
        if 'blood' in request.POST:
            blood = request.POST['blood']
        else:
            blood = ""
        # hm_mob = request.POST['homemobile']
        if 'homemobile' in request.POST:
            hm_mob = request.POST['homemobile']
        if not hm_mob:
            hm_mob = "0"
        offc_mob = request.POST['officeNumber']
        pass_chg = int(request.POST.get('pass_chg', 0))
        # insu_amt = int(request.POST.get('insu_amt', 0))
        esi_amt = int(request.POST.get('esi_amt', 0))
        # other_deduct = request.POST['deduction']

        if 'insu' in request.POST:
            insu_amt = request.POST['insu']
        if not insu_amt:
            insu_amt = "0"

        
        other_deduct = request.POST.get('other_deduct', 0)
         

        acti = int(request.POST.get('active', 0))
        # acti = 'active'


        gender = request.POST.get('gender') 
        print(f"gender {gender}")

        if 'pan' in request.POST:
            pan_num = request.POST['pan']
        if not pan_num:
            pan_num = ""  

        if 'aadhar' in request.POST:
            aadhar_num = request.POST['aadhar']
        if not aadhar_num:
            aadhar_num = ""

        if 'bankbranch' in request.POST:
            branch = request.POST['bankbranch']
        if not branch:
            branch = ""      

        if 'employee_contri' in request.POST:
            employee_contri = request.POST['employee_contri']
        if not employee_contri:
            employee_contri = ""      

        if 'employer_contri' in request.POST:
            employer_contri = request.POST['employer_contri']
        if not employer_contri:
            employer_contri = ""  

        reliving_dt = request.POST.get('reliving_dt', '0001-01-01')
        rejoin_dt = request.POST.get('rejoin_dt', '0001-01-01')
        print(f"reliving_dt {reliving_dt}")


        reg_dt = timezone.now()
        branch_name = request.POST.get('branchName')
        current_month = datetime.now().month
        current_year = datetime.now().year
        newadd_adm = RegisterAll(depart=depart, nm=nm, user_id=user_id, pwd=ciphertext, mob=mob, addr=addr, em_depart=em_depart,
                                 em_depart_hed=em_depart_hed,em_depart_tl=em_depart_tl, no_of_cl=no_of_cl, email=email, permi=permi,
                                 team_ld=team_ld, dsig=dsig, work_frm=workfrom_time_obj, work_to=workto_time_obj, sala=sala,
                                 doj=doj, pf_cd=pf_cd, locca=locca, bank=bank, acc_no=acc_no, ifsc=ifsc,pic=pic,
                                 dob=dob, pf_amt=pf_amt, sd_amt=sd_amt, company=company, fath_nm=fath_nm,
                                 blood=blood, hm_mob=hm_mob, pass_chg=pass_chg, insu_amt=insu_amt,offc_mob=offc_mob,other_deduct=other_deduct,
                                 esi_amt=esi_amt, acti=acti, reg_dt=reg_dt, mnth=current_month, yr=current_year,branch_name=branch_name ,gender=gender , pan_num=pan_num, aadhar_num=aadhar_num,branch=branch,employee_contri=employee_contri,employer_contri=employer_contri,mr_mrs_ms=frontname , reliving_dt=reliving_dt,rejoin_dt=rejoin_dt)

        # Check if a profile picture is provided
    #     if pic:
    #         # Build the file path
    #         file_path = f'static/upload/{pic.name}'

    #         # Save the uploaded file
    #         with default_storage.open(file_path, 'wb') as destination:
    #             for chunk in pic.chunks():
    #                 destination.write(chunk)

    #         # Update the 'pic' field in the model with the file path
    #         newadd_adm.pic = f'{pic.name}'
    #     else:
    # # If no profile picture is provided, you may want to handle this case
    # # For example, set a default value or handle it based on your requirements
    #        newadd_adm.pic = 'images.png'  # Set to a default value or handle as needed    
        # Check if a profile picture is provided
        if pic:
            # Generate a random filename
            random_filename = f'{random_string()}.png'

            # Build the file path
            file_path = f'static/upload/{random_filename}'

            # Save the uploaded file
            with default_storage.open(file_path, 'wb') as destination:
                for chunk in pic.chunks():
                    destination.write(chunk)

            # Update the 'pic' field in the model with the file path
            newadd_adm.pic = random_filename
        else:
            newadd_adm.pic = 'images.png'

        newadd_adm.save()

        messages.success(request, 'Admin Register successfully')
        return redirect('register_admin')

    # Render your form template for GET requests
    return render(request, 'register_admin.html')

def get_trainee_codes_by_company(request):
    selected_company = request.GET.get('company', None)
    print(f"company trainee: {selected_company}")
    
    try:
        # Retrieve the user_id from the registerall table based on the selected company
        employee_user_info = RegisterAll.objects.filter(company=selected_company,depart='trainee').order_by('-user_id').values('user_id').first()
        print(f"last_generated_code_admin trainee: {employee_user_info}")
        # If no code is found in the session, set a default value
        last_generated_code = 1000  # Default value
        # If user_info is not None, extract the user_id and update last_generated_code
        if employee_user_info:
            user_id_str = employee_user_info['user_id']
            print(f"user_id_str {user_id_str}")
            if len(user_id_str) == 7:
                last_generated_code = int(user_id_str[3:])
            elif len(user_id_str) == 11:
                last_generated_code = int(user_id_str[7:])      # Extract numeric part and convert to int
            elif len(user_id_str) == 10:
                last_generated_code = int(user_id_str[6:])      # Extract numeric part and convert to int
            elif len(user_id_str) == 9:
                last_generated_code = int(user_id_str[5:])
            elif len(user_id_str) == 8:
                last_generated_code = int(user_id_str[4:]) 
            elif len(user_id_str) == 12:
                last_generated_code = int(user_id_str[8:])             
                
        # Increment the last generated code for the new one
        new_generated_code = last_generated_code + 1
        # Fetch employee codes based on the selected company
        print(f"new_generated_code {new_generated_code}")
        employee_codes = Branch.objects.filter(office_name=selected_company).values_list('trainee_code', flat=True)
        print(f"codes: {employee_codes}")
        # Convert employee_codes queryset to a list
        employee_codes_list = list(employee_codes)
        # Append the new generated code
        employee_codes_list.append(new_generated_code)
        return JsonResponse({'employee_codes': employee_codes_list, 'random_code': new_generated_code}, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def trainee_insert(request):
    if request.method == 'POST':
        depart = request.POST.get('trainee','trainee')
        nm = request.POST['name']
        frontname = request.POST['frontname']
        user_id = request.POST['employeeCode']
        pwd = request.POST['password']
        ciphertext = encrypt(pwd, key)
        print("Encrypted:", ciphertext)
        mob = request.POST['mobilenumber']
        # addr = request.POST['address']
        if 'address' in request.POST:
            addr = request.POST['address']
        # Check if the address field is empty
        if not addr:
            addr = ""
        em_depart = request.POST.get('departmentHead')
        em_depart_hed = request.POST['userDepartmentHead']
        em_depart_tl = request.POST['userDepartmentTL']
        # no_of_cl = request.POST['nocl']
        if 'nocl' in request.POST:
            no_of_cl = request.POST['nocl']
        # Check if the address field is empty
        if not no_of_cl:
            no_of_cl = ""
        # email = request.POST['email']
        if 'email' in request.POST:
            email = request.POST['email']
        # Check if the address field is empty
        if not email:
            email = ""    
        pic = request.FILES.get('profile') 
        # permi = request.POST['permission']
        if 'permission' in request.POST:
            permi = request.POST['permission']
            # Check if the permission field is empty
            if not permi:
                permi = "0:0:0"
            else:
                try:
                    # Attempt to parse the time value
                    parse_time(permi)
                except ValueError:
                    # Handle the case where the time format is invalid
                    permi = "0:0:0"

        team_ld = int(request.POST.get('team_ld', 0))        
        # dsig = request.POST['designation']
        if 'designation' in request.POST:
            dsig = request.POST['designation']
        # Check if the address field is empty
        if not dsig:
            dsig = ""
        workfrom_time = request.POST['workfrom']
        workfrom_period = request.POST.get('workfrom_period')
        numberSelect = request.POST.get('numberSelect')

        workfrom_combined = f"{workfrom_time}:{numberSelect} {workfrom_period}"
        print(f"workfrom_combined {workfrom_combined}")
        

        workto_time = request.POST['workto']
        workto_period = request.POST.get('workto_period')
        worktoSelect = request.POST.get('worktoSelect')
        workto_combined = f"{workto_time}:{worktoSelect} {workto_period}"
        print(f"workfrom_combined {workto_combined}")

    # Combine time and period into a single string
        # workfrom_combined = f"{workfrom_time} {workfrom_period}"
        # workto_combined = f"{workto_time} {workto_period}"

    # Convert the combined strings to time objects
        workfrom_time_obj = datetime.strptime(workfrom_combined, '%I:%M %p').time()
        workto_time_obj = datetime.strptime(workto_combined, '%I:%M %p').time()
        # workto_period = request.POST.get('workto_period')

    # Combine time and period into a single string
        # workfrom_combined = f"{workfrom_time} {workfrom_period}"
        # workto_combined = f"{workto_time} {workto_period}"

    # Convert the combined strings to time objects
        # workfrom_time_obj = datetime.strptime(workfrom_combined, '%I:%M %p').time()
        # workto_time_obj = datetime.strptime(workto_combined, '%I:%M %p').time()
        # workfrom_time_obj = datetime.strptime(workfrom_combined, '%H:%M %p').time()
        # workto_time_obj = datetime.strptime(workto_combined, '%H:%M %p').time()
        # sala = request.POST['salary']
        if 'salary' in request.POST:
            sala = request.POST['salary']
        # Check if the address field is empty
        if not sala:
            sala = "0"
        # doj = request.POST['doj']
        doj = request.POST.get('doj')

        # Check if doj is provided
        if doj:
            # If provided, use the input date
            doj = doj
        else:
            # If not provided, use the default value '2000-01-01'
            doj = '2000-01-01'    
        pf_cd = request.POST['pfcode']
        locca = ""  # Initialize locca to an empty string
        if 'locationDropdown' in request.POST:
            locca = request.POST.get('locationDropdown')
        # Check if the address field is empty
        if not locca:
            locca = ""
        officeno = request.POST['officeNumber']
        bank = request.POST['bank']
        acc_no = request.POST['account']
        ifsc = request.POST['ifsc']
        # dob = request.POST['dob']
        dob = request.POST.get('dob')

        # Check if dob is provided
        if dob:
            # If provided, use the input date
            dob = dob
        else:
            # If not provided, use the default value '2000-01-01'
            dob = '2000-01-01'
        # pf_amt = request.POST['pfamount']
        
        pf_amt = int(request.POST.get('pf_amt', 0))
        
        
        sd_amt = int(request.POST.get('sd_amt', 0))
        
        company = request.POST.get('companyName')
        # fath_nm = request.POST['fathername']
        if 'fathername' in request.POST:
            fath_nm = request.POST['fathername']
        # Check if the address field is empty
        if not fath_nm:
            fath_nm = ""
        # blood = request.POST['blood']
        if 'blood' in request.POST:
            blood = request.POST['blood']
        else:
            blood = ""  
        # hm_mob = request.POST['homemobile']
        if 'homemobile' in request.POST:
            hm_mob = request.POST['homemobile']
        if not hm_mob:
            hm_mob = "0"    
        pass_chg = int(request.POST.get('pass_chg', 0))
        insu_amt = int(request.POST.get('insu_amt', 0))
        esi_amt = int(request.POST.get('esi_amt', 0))
        # other_deduct = request.POST['deduction']
       
        other_deduct = request.POST.get('other_deduct', 0)
       
        acti = int(request.POST.get('acti', 0))
        # acti = 'active'

        if 'insu' in request.POST:
            insu_amt = request.POST['insu']
        if not insu_amt:
            insu_amt = "0"  

        gender = request.POST.get('gender') 
        print(f"gender {gender}")

        if 'pan' in request.POST:
            pan_num = request.POST['pan']
        if not pan_num:
            pan_num = ""  

        if 'aadhar' in request.POST:
            aadhar_num = request.POST['aadhar']
        if not aadhar_num:
            aadhar_num = ""

        if 'bankbranch' in request.POST:
            branch = request.POST['bankbranch']
        if not branch:
            branch = ""      

        if 'employee_contri' in request.POST:
            employee_contri = request.POST['employee_contri']
        if not employee_contri:
            employee_contri = ""      

        if 'employer_contri' in request.POST:
            employer_contri = request.POST['employer_contri']
        if not employer_contri:
            employer_contri = ""

        reliving_dt = request.POST.get('reliving_dt', '0001-01-01')
        rejoin_dt = request.POST.get('rejoin_dt', '0001-01-01')
        print(f"reliving_dt {reliving_dt}")

        reg_dt = timezone.now()
        branch_name = request.POST.get('branchName')
        current_month = datetime.now().month
        current_year = datetime.now().year

        newadd_traniee = RegisterAll(
            depart=depart,
            nm=nm,
            user_id=user_id,
            pwd=ciphertext,
            mob=mob,
            addr=addr,
            em_depart=em_depart,
            em_depart_hed=em_depart_hed,
            em_depart_tl=em_depart_tl,
            no_of_cl=no_of_cl,
            email=email,
            pic=pic,
            permi=permi,
            team_ld=team_ld,
            dsig=dsig,
            work_frm=workfrom_time_obj,
            work_to=workto_time_obj,
            sala=sala,
            doj=doj,
            pf_cd=pf_cd,
            locca=locca,
            offc_mob=officeno, 
            bank=bank,
            acc_no=acc_no,
            ifsc=ifsc,
            dob=dob,
            pf_amt=pf_amt,
            sd_amt=sd_amt,
            company=company,
            fath_nm=fath_nm,
            blood=blood,
            hm_mob=hm_mob,
            pass_chg=pass_chg,
            insu_amt=insu_amt,
            esi_amt=esi_amt,
            acti=acti,
            other_deduct=other_deduct,
            reg_dt=reg_dt,
            mnth=current_month,
            yr=current_year,
            branch_name=branch_name,gender=gender,pan_num=pan_num,aadhar_num=aadhar_num,branch=branch,employee_contri=employee_contri,employer_contri=employer_contri,mr_mrs_ms=frontname, reliving_dt=reliving_dt,rejoin_dt=rejoin_dt
        )
    #     if pic:
    #         # Build the file path
    #         file_path = f'static/upload/{pic.name}'

    #         # Save the uploaded file
    #         with default_storage.open(file_path, 'wb') as destination:
    #             for chunk in pic.chunks():
    #                 destination.write(chunk)

    #         # Update the 'pic' field in the model with the file path
    #         newadd_traniee.pic = f'{pic.name}'
    #     else:
    # # If no profile picture is provided, you may want to handle this case
    # # For example, set a default value or handle it based on your requirements
    #        newadd_traniee.pic = 'images.png'    
        # Check if a profile picture is provided
        if pic:
            # Generate a random filename
            random_filename = f'{random_string()}.png'

            # Build the file path
            file_path = f'static/upload/{random_filename}'

            # Save the uploaded file
            with default_storage.open(file_path, 'wb') as destination:
                for chunk in pic.chunks():
                    destination.write(chunk)

            # Update the 'pic' field in the model with the file path
            newadd_traniee.pic = random_filename
        else:
            newadd_traniee.pic = 'images.png'

        newadd_traniee.save()

        messages.success(request, 'Trainee Register successfully')
        return redirect('traniee_admin')

    # Render your form template for GET requests
    return render(request, 'traniee_admin.html')

@csrf_exempt
@require_POST
def delete_tr(request, id):
    try:
        data = get_object_or_404(RegisterAll, id=id)
        data.delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)




@csrf_exempt
@require_POST
def delete_ad(request, id):
    try:
        data = get_object_or_404(RegisterAll, id=id)
        data.delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    

@csrf_exempt
@require_POST
def delete_emp(request, id):
    try:
        data = get_object_or_404(RegisterAll, id=id)
        data.delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)



def fetch_branch(request):
    branch = Branch.objects.values_list('branch_name', flat=True)
    branch_list = list(branch)
    return JsonResponse({'branch': branch_list}, safe=False)


def fetch_employee_data(request):
    branch_name = request.GET.get('branch_name')
    print(f"branch_name {branch_name}")
    
    if branch_name == 'All':
        employees = RegisterAll.objects.exclude(depart='SAD').values('nm', 'user_id', 'depart', 'work_frm', 'work_to')
        print(f"employees {employees}")
    else:
        employees = RegisterAll.objects.filter(branch_name=branch_name).exclude(depart='SAD').values('nm', 'user_id', 'depart', 'work_frm', 'work_to')
    
    employees_list = list(employees)
    print("branch:", employees_list)
    return JsonResponse({'employee': employees_list}, safe=False)







from datetime import timedelta
from datetime import datetime
from django.db import transaction

@csrf_exempt
def insert_attendance_data(request):
    try:
        if request.method == 'POST':
            data = json.loads(request.body.decode('utf-8'))
            print(f"Body content: {data}")

            # Extract necessary information from the JSON data
            selected_employees = data.get('employees', [])
            date = data.get('date', '')

            with transaction.atomic():  # Use atomic transaction
                # Perform the insertion or update into the attendance table
                for employee in selected_employees:
                    clk_in = int(employee.get('clk_in', 0))
                    clk_out = int(employee.get('clk_out', 0))
                    work_frm = employee.get('work_frm', '')

                    work_frm_time = datetime.strptime(work_frm, "%H:%M:%S").strftime("%H:%M:%S")

                    clk_in_dt_tm_time = f"{date} {work_frm_time}"

                    work_to = employee.get('work_to', '')

                    # Handle time without AM/PM designation
                    work_out_time = datetime.strptime(work_to, "%H:%M:%S").strftime("%H:%M:%S")

                    clk_out_dt_tm_time = f"{date} {work_out_time}"

                    clk_in_tm = work_frm_time
                    clk_out_tm = work_out_time

                    # Convert the time difference to total hours
                    clk_in_tm = datetime.strptime(clk_in_dt_tm_time, "%Y-%m-%d %H:%M:%S")
                    clk_out_tm = datetime.strptime(clk_out_dt_tm_time, "%Y-%m-%d %H:%M:%S")

                    # Calculate the time difference
                    time_difference = clk_out_tm - clk_in_tm

                    # Convert the time difference to total hours
                    tot_hr = time_difference.total_seconds() / 3600
                    tot_hr_str = str(timedelta(seconds=time_difference.total_seconds()))
                    print(f"tot_hr:{tot_hr}")
                    month = datetime.strptime(date, "%Y-%m-%d").month
                    year = datetime.strptime(date, "%Y-%m-%d").year

                    late_resn_status = int(employee.get('late_resn_status', 0))

                    # Check if a record already exists for the same user_id and date
                    existing_attendance = Attendance.objects.filter(
                        user_id=employee.get('user_id', ''),
                        date=date
                    ).first()

                    if existing_attendance:
                        # Update the existing record
                        existing_attendance.clk_in = clk_in
                        existing_attendance.clk_out = clk_out
                        existing_attendance.clk_in_tm = clk_in_tm
                        existing_attendance.clk_out_tm = clk_out_tm
                        existing_attendance.clk_in_dt_tm = clk_in_dt_tm_time
                        existing_attendance.clk_out_dt_tm = clk_out_dt_tm_time
                        existing_attendance.tot_hr = tot_hr_str
                        existing_attendance.late_resn_status = late_resn_status
                        existing_attendance.save()
                    else:
                        # Insert a new record if it doesn't exist
                        attendance = Attendance(
                            user_id=employee.get('user_id', ''),
                            depart=employee.get('depart', ''),
                            work_frm=employee.get('work_frm', ''),
                            work_to=employee.get('work_to', ''),
                            clk_in=clk_in,
                            clk_out=clk_out,
                            date=date,
                            clk_in_tm=clk_in_tm,
                            clk_out_tm=clk_out_tm,
                            clk_in_dt_tm=clk_in_dt_tm_time,
                            clk_out_dt_tm=clk_out_dt_tm_time,
                            tot_hr=tot_hr_str,
                            mnth=month,
                            yr=year,
                            late_resn_status=late_resn_status,
                        )
                        attendance.save()

                # Return a success response after processing all employees
                response_data = {'message': 'Attendance data inserted or updated successfully.'}
                return JsonResponse(response_data)

        else:
            # Return an error response if the request method is not POST
            response_data = {'error': 'Invalid request method. Only POST is allowed.'}
            return JsonResponse(response_data, status=405)  # Method Not Allowed

    except Exception as e:
        # Handle other exceptions and return an error response
        response_data = {'error': str(e)}
        return JsonResponse(response_data, status=500)



@csrf_exempt
def insert_attendance_time(request):
    try:
        if request.method == 'POST':
            # Retrieve JSON data from the request body using the json.loads method
            data = json.loads(request.body.decode('utf-8'))
            print(f"yufvghfg: {data}")

            # Extract necessary information from the JSON data
            selected_employees = data.get('employees', [])
            
                    
            with transaction.atomic():  # Use atomic transaction
                # Perform the insertion or update into the attendance table
                for employee in selected_employees:
                    clk_in = int(employee.get('clk_in', 0))
                    clk_out = int(employee.get('clk_out', 0))
                    date = data.get('date', '')
            
                    print(f'date:,{date}')
                    workfrom_time = data.get('work_frm_', '')
                    numberSelect = data.get('numberSelect', '')
                    workfrom_period = data.get('work_frm_time', '')

                    workto_time = data.get('work_to_', '')
                    worktoSelect = data.get('worktoSelect', '')
                    workto_period = data.get('work_to_time', '')

                    # Remove trailing spaces from time strings
                    workfrom_time = workfrom_time.strip()
                    workto_time = workto_time.strip()

                    workfrom_combined = f"{workfrom_time}:{numberSelect} {workfrom_period}"
                    workto_combined = f"{workto_time}:{worktoSelect} {workto_period}"

                    # Convert the combined strings to time objects
                    workfrom_time_obj = datetime.strptime(workfrom_combined, '%I:%M %p').time()
                    workto_time_obj = datetime.strptime(workto_combined, '%I:%M %p').time()

                    print(f"intime:{workfrom_time_obj}")
                    # Combine time and period into a single string
                    print(f"outtime:{workto_time_obj}")

                    clk_in_dt_tm_time = f"{date} {workfrom_time_obj}"
                    print(f"clk_in_dt_tm_time:{clk_in_dt_tm_time}")
                    clk_out_dt_tm_time = f"{date} {workto_time_obj}"
                    print(f"clk_out_dt_tm_time:{clk_out_dt_tm_time}")

                    workfrom_time_obj = datetime.strptime(clk_in_dt_tm_time, "%Y-%m-%d %H:%M:%S")
                    workto_time_obj = datetime.strptime(clk_out_dt_tm_time, "%Y-%m-%d %H:%M:%S")

                    # Calculate the time difference
                    time_difference = workto_time_obj - workfrom_time_obj

                    # Convert the time difference to total hours
                    tot_hr_seconds = time_difference.total_seconds()
                    tot_hr = timedelta(seconds=tot_hr_seconds)
                    tot_hr_str = str(tot_hr)
                    print(f"tot_hr_str:{tot_hr_str}")

                    select_datetime = datetime.strptime(date, "%Y-%m-%d")
                    month = select_datetime.month
                    year = select_datetime.year
                    late_resn_status = int(employee.get('late_resn_status', 0))
                    
                    # Check if a record already exists for the same user_id and date
                    existing_attendance = Attendance.objects.filter(
                        user_id=employee.get('user_id', ''),
                        date=date
                    ).first()

                    if existing_attendance:
                        # Update the existing record
                        existing_attendance.clk_in = clk_in
                        existing_attendance.clk_out = clk_out
                        existing_attendance.clk_in_tm = workfrom_time_obj
                        existing_attendance.clk_out_tm = workto_time_obj
                        existing_attendance.clk_in_dt_tm = clk_in_dt_tm_time
                        existing_attendance.clk_out_dt_tm = clk_out_dt_tm_time
                        existing_attendance.tot_hr = tot_hr_str
                        existing_attendance.late_resn_status = late_resn_status
                        existing_attendance.save()
                    else:
                        # Insert a new record if it doesn't exist
                        attendance = Attendance(
                            user_id=employee.get('user_id', ''),
                            depart=employee.get('depart', ''),
                            work_frm=employee.get('work_frm', ''),
                            work_to=employee.get('work_to', ''),
                            clk_in=clk_in,
                            clk_out=clk_out,
                            date=date,
                            clk_in_tm=workfrom_time_obj,
                            clk_out_tm=workto_time_obj,
                            clk_in_dt_tm=clk_in_dt_tm_time,
                            clk_out_dt_tm=clk_out_dt_tm_time,
                            tot_hr=tot_hr_str,
                            mnth=month,
                            yr=year,
                            late_resn_status=late_resn_status,
                        )
                        attendance.save()

                # Return a success response after processing all employees
                response_data = {'message': 'Attendance data inserted or updated successfully.'}
                return JsonResponse(response_data)

        else:
            # Return an error response if the request method is not POST
            response_data = {'error': 'Invalid request method. Only POST is allowed.'}
            return JsonResponse(response_data, status=405)  # Method Not Allowed

    except Exception as e:
        # Handle other exceptions and return an error response
        response_data = {'error': str(e)}
        return JsonResponse(response_data, status=500)





@csrf_exempt
def insert_attendance_mng(request):
    try:
        if request.method == 'POST':
            # Retrieve JSON data from the request body using the json.loads method
            data = json.loads(request.body.decode('utf-8'))
            print(f"morning: {data}")

            # Extract necessary information from the JSON data
            selected_employees = data.get('employees', [])
                    
            with transaction.atomic():  # Use atomic transaction
                # Perform the insertion or update into the attendance table
                for employee in selected_employees:
                    clk_in = int(employee.get('clk_in', 0))
                    clk_out = int(employee.get('clk_out', 0))
                    date = data.get('date', '')
            
                    print(f'date: {date}')
                    work_to = employee.get('work_to', '')
                    print(f'work_to: {work_to}')
                    clk_out_tm_str = employee.get('work_to', '')
                    print(f'clk_out_tm: {clk_out_tm_str}')

                    workfrom_time = data.get('work_frm_', '')
                    numberSelect = data.get('numberSelect', '')
                    workfrom_period = data.get('work_frm_time', '')
                    workfrom_time = workfrom_time.strip()
                    workfrom_combined = f"{workfrom_time}:{numberSelect} {workfrom_period}"
                    workfrom_time_obj = datetime.strptime(workfrom_combined, '%I:%M %p').time()
                    print(f'clk_in_tm: {workfrom_time_obj}')

                    clk_in_dt_tm = f"{date} {workfrom_time_obj}"
                    print(f'clk_in_dt_tm: {clk_in_dt_tm}')
                    clk_out_dt_tm = f"{date} {clk_out_tm_str}"
                    print(f'clk_out_dt_tm: {clk_out_dt_tm}')

                    # Convert string representations to datetime objects
                    clk_in_dt_tm_obj = datetime.strptime(clk_in_dt_tm, "%Y-%m-%d %H:%M:%S")
                    clk_out_dt_tm_obj = datetime.strptime(clk_out_dt_tm, "%Y-%m-%d %H:%M:%S")

                    # Calculate the time difference
                    time_difference = clk_out_dt_tm_obj - clk_in_dt_tm_obj

                    # Convert the time difference to total hours
                    tot_hr_seconds = time_difference.total_seconds()
                    tot_hr = timedelta(seconds=tot_hr_seconds)
                    tot_hr_str = str(tot_hr)
                    print(f"tot_hr_str: {tot_hr_str}")

                    select_datetime = datetime.strptime(date, "%Y-%m-%d")
                    month = select_datetime.month
                    year = select_datetime.year
                    late_resn_status = int(employee.get('late_resn_status', 0))

                    # Check if a record already exists for the same user_id and date
                    existing_attendance = Attendance.objects.filter(
                        user_id=employee.get('user_id', ''),
                        date=date
                    ).first()

                    if existing_attendance:
                        # Update the existing record
                        existing_attendance.work_frm = employee.get('work_frm', '')
                        existing_attendance.work_to = work_to
                        existing_attendance.clk_in = clk_in
                        existing_attendance.clk_out = clk_out
                        existing_attendance.clk_in_tm = workfrom_time_obj
                        existing_attendance.clk_out_tm = clk_out_tm_str
                        existing_attendance.clk_in_dt_tm = clk_in_dt_tm
                        existing_attendance.clk_out_dt_tm = clk_out_dt_tm
                        existing_attendance.tot_hr = tot_hr_str
                        existing_attendance.late_resn_status = late_resn_status
                        existing_attendance.save()
                    else:
                        # Insert a new record if it doesn't exist
                        attendance = Attendance(
                            user_id=employee.get('user_id', ''),
                            depart=employee.get('depart', ''),
                            work_frm=employee.get('work_frm', ''),
                            work_to=work_to,
                            clk_in=clk_in,
                            clk_out=clk_out,
                            date=date,
                            clk_in_tm=workfrom_time_obj,
                            clk_out_tm=clk_out_tm_str,
                            clk_in_dt_tm=clk_in_dt_tm,
                            clk_out_dt_tm=clk_out_dt_tm,
                            tot_hr=tot_hr_str,
                            mnth=month,
                            yr=year,
                            late_resn_status=late_resn_status,
                        )
                        attendance.save()

                # Return a success response after processing all employees
                response_data = {'message': 'Attendance data inserted or updated successfully.'}
                return JsonResponse(response_data)

        else:
            # Return an error response if the request method is not POST
            response_data = {'error': 'Invalid request method. Only POST is allowed.'}
            return JsonResponse(response_data, status=405)  # Method Not Allowed

    except Exception as e:
        # Handle other exceptions and return an error response
        response_data = {'error': str(e)}
        return JsonResponse(response_data, status=500)
    

@csrf_exempt
def insert_attendance_evg(request):
    try:
        if request.method == 'POST':
            # Retrieve JSON data from the request body using the json.loads method
            data = json.loads(request.body.decode('utf-8'))
            print(f"evening: {data}")

            # Extract necessary information from the JSON data
            selected_employees = data.get('employees', [])

            with transaction.atomic():  # Use atomic transaction
                # Perform the insertion or update into the attendance table
                for employee in selected_employees:
                    clk_in = int(employee.get('clk_in', 0))
                    clk_out = int(employee.get('clk_out', 0))
                    date = data.get('date', '')
                    
                    print(f'date: {date}')
                    work_frm = employee.get('work_frm', '')
                    print(f'work_frm: {work_frm}')
                    
                    workto_time = data.get('work_to_', '')
                    worktoSelect = data.get('worktoSelect', '')
                    workto_period = data.get('work_to_time', '')
                    workto_time = workto_time.strip()
                    workto_combined = f"{workto_time}:{worktoSelect} {workto_period}"
                    workto_time_obj = datetime.strptime(workto_combined, '%I:%M %p').time()
                    print(f'clk_out_tm: {workto_time_obj}')
                   
                    clk_in_dt_tm = f"{date} {work_frm}"
                    print(f"infdtrd: {clk_in_dt_tm}")
                    clk_out_dt_tm = f"{date} {workto_time_obj}"
                    print(f'outghcfgxfd: {clk_out_dt_tm}')

                    clk_in_dt_tm_obj = datetime.strptime(clk_in_dt_tm, "%Y-%m-%d %H:%M:%S")
                    clk_out_dt_tm_obj = datetime.strptime(clk_out_dt_tm, "%Y-%m-%d %H:%M:%S")

                    # Calculate the time difference
                    time_difference = clk_out_dt_tm_obj - clk_in_dt_tm_obj

                    # Convert the time difference to total hours
                    tot_hr_seconds = time_difference.total_seconds()
                    tot_hr = timedelta(seconds=tot_hr_seconds)
                    tot_hr_str = str(tot_hr)
                    print(f"tot_hr_str: {tot_hr_str}")

                    select_datetime = datetime.strptime(date, "%Y-%m-%d")
                    month = select_datetime.month
                    year = select_datetime.year
                    late_resn_status = int(employee.get('late_resn_status', 0))

                    # Check if a record already exists for the same user_id and date
                    existing_attendance = Attendance.objects.filter(
                        user_id=employee.get('user_id', ''),
                        date=date
                    ).first()

                    if existing_attendance:
                        # Update the existing record
                        existing_attendance.work_frm = work_frm
                        existing_attendance.work_to = employee.get('work_to', '')
                        existing_attendance.clk_in = clk_in
                        existing_attendance.clk_out = clk_out
                        existing_attendance.clk_in_tm = clk_in_dt_tm_obj
                        existing_attendance.clk_out_tm = workto_time_obj
                        existing_attendance.clk_in_dt_tm = clk_in_dt_tm
                        existing_attendance.clk_out_dt_tm = clk_out_dt_tm
                        existing_attendance.tot_hr = tot_hr_str
                        existing_attendance.late_resn_status = late_resn_status
                        existing_attendance.save()
                    else:
                        # Insert a new record if it doesn't exist
                        attendance = Attendance(
                            user_id=employee.get('user_id', ''),
                            depart=employee.get('depart', ''),
                            work_frm=work_frm,
                            work_to=employee.get('work_to', ''),
                            clk_in=clk_in,
                            clk_out=clk_out,
                            date=date,
                            clk_in_tm=clk_in_dt_tm_obj,
                            clk_out_tm=workto_time_obj,
                            clk_in_dt_tm=clk_in_dt_tm,
                            clk_out_dt_tm=clk_out_dt_tm,
                            tot_hr=tot_hr_str,
                            mnth=month,
                            yr=year,
                            late_resn_status=late_resn_status
                        )
                        attendance.save()

                # Return a success response after processing all employees
                response_data = {'message': 'Attendance data inserted or updated successfully.'}
                return JsonResponse(response_data)

        else:
            # Return an error response if the request method is not POST
            response_data = {'error': 'Invalid request method. Only POST is allowed.'}
            return JsonResponse(response_data, status=405)  # Method Not Allowed

    except Exception as e:
        # Handle other exceptions and return an error response
        response_data = {'error': str(e)}
        return JsonResponse(response_data, status=500)
    
    




    # Define fields_to_include globally
fields_to_include = {
    'pic': 'Picture',
    # 'depart': 'Department',
    'nm': 'Name',
    'user_id': 'User ID',
    'pwd': 'Password',
    'mob': 'Mobile',
    'email': 'Email',
'fath_nm': 'Father/Spouse Name',
'dob': 'Date of Birth',
    'addr': 'Address',
     'hm_mob': 'Home Mobile',
    'blood': 'Blood Group',
    'em_depart': ' Department',
    'em_depart_hed': ' Department Head',
    'em_depart_tl': 'Employee Department Tl',
   
    
    'reg_dt': 'Registration Date',
    # 'mnth': 'Month',
    # 'yr': 'Year',
    'permi': 'Permission',
    # 'team_ld': 'Team Leader',
   
'doj': 'Date of Joining',

    'offc_mob': 'Office Mobile',
    'work_frm': 'Work From',
    'work_to': 'Work To',
    
     'no_of_cl': 'Number of Cl',

    'pf_cd': 'UAN',
    'locca': 'Location',
    'bank': 'Bank',
    'acc_no': 'Account Number',
    'ifsc': 'IFSC Code',
    # 'acti': 'Active',
     'dsig': 'Designation',
    'other_deduct': 'Other Deductions',
    'pf_amt': 'PF Amount',
    'sd_amt': 'SD Amount',
    'company': 'Company',
    
    
   
    
    # 'pass_chg': 'Password Change',
    'insu_amt': 'Insurance Amount',
    'esi_amt': 'ESI Amount',
    'sala': 'Salary',

    
    
}
# Admin Get Details And Update
@csrf_exempt
def get_admin_details(request, admin_id):
    try:
        admin = RegisterAll.objects.get(id=admin_id, depart='ad')

        # Split the fields into two parts
        half_length = len(fields_to_include) // 2
        fields_part1 = dict(list(fields_to_include.items())[:half_length+1])
        fields_part2 = dict(list(fields_to_include.items())[half_length+1:])

        # Create a dictionary with custom labels and values for the first part
        details = [{'label': fields_part1[field], 'value': getattr(admin, field)} for field in fields_part1]

        # Create a dictionary with custom labels and values for the second part
        details1 = [{'label': fields_part2[field], 'value': getattr(admin, field)} for field in fields_part2]

        # Add more details as needed
        return JsonResponse({'details': details, 'details1': details1}, safe=False)
    except RegisterAll.DoesNotExist:
        return JsonResponse({'error': 'Admin not found'}, status=404)
    

# Define field_mapping globally
field_mapping = {
    'picture': 'pic',
    # 'department': 'depart',
    'name': 'nm',
    'user id': 'user_id',
    'password': 'pwd',
    'mobile': 'mob',
    'address': 'addr',
    'department': 'em_depart',
    'department head': 'em_depart_hed',
     'employee department tl': 'em_depart_tl',
    'number of cl': 'no_of_cl',
    'email': 'email',
    'registration date': 'reg_dt',
    # 'month': 'mnth',
    # 'year': 'yr',
    'permission': 'permi',
    # 'team leader': 'team_ld',
    'designation': 'dsig',  # Updated mapping for 'Designation'
    'work from': 'work_frm',
    'work to': 'work_to',
    'office mobile': 'offc_mob',
    'date of joining': 'doj',
    'UAN': 'pf_cd',
    'location': 'locca',
    'bank': 'bank',
    'account number': 'acc_no',
    'ifsc code': 'ifsc',
    # 'active': 'acti',
    'date of birth': 'dob',
    'other deductions': 'other_deduct',
    'pf amount': 'pf_amt',
    'sd amount': 'sd_amt',
    'company': 'company',
    'Father/Spouse Name': 'fath_nm',
    'blood group': 'blood',
    'home mobile': 'hm_mob',
   
    # 'password change': 'pass_chg',
    'insurance amount': 'insu_amt',
    'esi amount': 'esi_amt',
     'salary': 'sala',
   
}
from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def update_admin_details(request, admin_id):
    if request.method == 'POST':
        try:
            # ... (existing code)
            details = json.loads(request.POST.get('details', '[]'))
            details1 = json.loads(request.POST.get('details1', '[]'))
            if 'Picture' in request.FILES:
                image_data = request.FILES['Picture']
                print(f'picture: {image_data.name}')

            # Assuming you have an admin instance, replace this with your logic to get the admin instance
            admin = RegisterAll.objects.get(id=admin_id)

            # Update fields in the admin object based on details
            for detail in details:
                field_name = detail.get('label', '').lower()
                update_value = detail.get('updatedValue')
                update_admin_field(admin, field_mapping, field_name, update_value)

            # Update fields in the admin object based on details1
            for detail in details1:
                field_name = detail.get('label', '').lower()
                update_value = detail.get('updatedValue')
                update_admin_field(admin, field_mapping, field_name, update_value)

            # Check if 'Picture' is present in request.FILES before processing
            if 'Picture' in request.FILES:
                # Update the 'pic' field if image data is present
                image_data = request.FILES['Picture']
                file_path = f'static/upload/{image_data.name}'

                # Save the uploaded file
                with default_storage.open(file_path, 'wb') as destination:
                    for chunk in image_data.chunks():
                        destination.write(chunk)

                # Update the 'pic' field in the model with the file path
                admin.pic = f'{image_data.name}'

            # Save the changes to the admin instance
            admin.save()

            return JsonResponse({'success': 'Data updated successfully'})

        except Exception as e:
            print(f'Error updating admin details: {str(e)}')
            return JsonResponse({'error': f'Error updating admin details: {str(e)}'}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


def update_admin_field(admin, field_mapping, field_name, update_value):
    field_name = field_name.lower()
    print(f'Processing field: {field_name}, update_value: {update_value}')

    if field_name in field_mapping:
        model_field = field_mapping[field_name]
        if hasattr(admin, model_field):
            setattr(admin, model_field, update_value)
        else:
            print(f"Field '{model_field}' does not exist in the model.")
    else:
        print(f"Field '{field_name}' is not mapped in field_mapping.")



# Employee Get And Update Details

@csrf_exempt
def get_employee_details(request, employee_id):
    try:
        employee = RegisterAll.objects.get(id=employee_id, depart='emp')

        # Split the fields into two parts
        half_length = len(fields_to_include) // 2
        fields_part1 = dict(list(fields_to_include.items())[:half_length+1])
        fields_part2 = dict(list(fields_to_include.items())[half_length+1:])

        # Create a dictionary with custom labels and values for the first part
        details = [{'label': fields_part1[field], 'value': getattr(employee, field)} for field in fields_part1]

        # Create a dictionary with custom labels and values for the second part
        details1 = [{'label': fields_part2[field], 'value': getattr(employee, field)} for field in fields_part2]

        # Add more details as needed
        return JsonResponse({'details': details, 'details1': details1}, safe=False)
    except RegisterAll.DoesNotExist:
        return JsonResponse({'error': 'employee not found'}, status=404)
    
from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def update_employee_details(request, employee_id):
    if request.method == 'POST':
        try:
            details = json.loads(request.POST.get('details', '[]'))
            details1 = json.loads(request.POST.get('details1', '[]'))

            if 'Picture' in request.FILES:
                image_data = request.FILES['Picture']
                print(f'picture: {image_data.name}')

            # Assuming you have an employee instance, replace this with your logic to get the employee instance
            employee = RegisterAll.objects.get(id=employee_id)

            # Update fields in the employee object based on details
            for detail in details:
                field_name = detail.get('label', '').lower()
                update_value = detail.get('updatedValue')
                update_employee_field(employee, field_mapping, field_name, update_value)

            # Update fields in the employee object based on details1
            for detail in details1:
                field_name = detail.get('label', '').lower()
                update_value = detail.get('updatedValue')
                update_employee_field(employee, field_mapping, field_name, update_value)

            # Update the 'pic' field if image data is present
            if 'Picture' in request.FILES:
                # Update the 'pic' field if image data is present
                image_data = request.FILES['Picture']
                file_path = f'static/upload/{image_data.name}'

                # Save the uploaded file
                with default_storage.open(file_path, 'wb') as destination:
                    for chunk in image_data.chunks():
                        destination.write(chunk)
                # Update the 'pic' field in the model with the file path
                employee.pic = f'{image_data.name}'
                # employee_instance.save()

            # Save the changes to the employee instance
            employee.save()

            return JsonResponse({'success': 'Data updated successfully'})

        except Exception as e:
            print(f'Error updating employee details: {str(e)}')
            return JsonResponse({'error': f'Error updating employee details: {str(e)}'}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


def update_employee_field(employee, field_mapping, field_name, update_value):
    field_name = field_name.lower()
    print(f'Processing field: {field_name}, update_value: {update_value}')

    if field_name in field_mapping:
        model_field = field_mapping[field_name]
        if hasattr(employee, model_field):
            setattr(employee, model_field, update_value)
        else:
            print(f"Field '{model_field}' does not exist in the model.")
    else:
        print(f"Field '{field_name}' is not mapped in field_mapping.")


# Trainee Get And Update Details

@csrf_exempt
def get_trainee_details(request, trainee_id):
    try:
        trainee = RegisterAll.objects.get(id=trainee_id, depart='trainee')

        # Split the fields into two parts
        half_length = len(fields_to_include) // 2
        fields_part1 = dict(list(fields_to_include.items())[:half_length+1])
        fields_part2 = dict(list(fields_to_include.items())[half_length+1:])

        # Create a dictionary with custom labels and values for the first part
        details = [{'label': fields_part1[field], 'value': getattr(trainee, field)} for field in fields_part1]

        # Create a dictionary with custom labels and values for the second part
        details1 = [{'label': fields_part2[field], 'value': getattr(trainee, field)} for field in fields_part2]

        # Add more details as needed
        return JsonResponse({'details': details, 'details1': details1}, safe=False)
    except RegisterAll.DoesNotExist:
        return JsonResponse({'error': 'trainee not found'}, status=404)
    
from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def update_trainee_details(request, trainee_id):
    if request.method == 'POST':
        try:
            details = json.loads(request.POST.get('details', '[]'))
            details1 = json.loads(request.POST.get('details1', '[]'))

            if 'Picture' in request.FILES:
                image_data = request.FILES['Picture']
                print(f'picture: {image_data.name}')

            # Assuming you have an trainee instance, replace this with your logic to get the trainee instance
            trainee = RegisterAll.objects.get(id=trainee_id)

            # Update fields in the trainee object based on details
            for detail in details:
                field_name = detail.get('label', '').lower()
                update_value = detail.get('updatedValue')
                update_trainee_field(trainee, field_mapping, field_name, update_value)

            # Update fields in the trainee object based on details1
            for detail in details1:
                field_name = detail.get('label', '').lower()
                update_value = detail.get('updatedValue')
                update_trainee_field(trainee, field_mapping, field_name, update_value)

            # Update the 'pic' field if image data is present
            if 'Picture' in request.FILES:
                # Update the 'pic' field if image data is present
                image_data = request.FILES['Picture']
                file_path = f'static/upload/{image_data.name}'


                # Save the uploaded file
                with default_storage.open(file_path, 'wb') as destination:
                    for chunk in image_data.chunks():
                        destination.write(chunk)
                # Update the 'pic' field in the model with the file path
                trainee.pic = f'{image_data.name}'

            # Save the changes to the trainee instance
            trainee.save()

            return JsonResponse({'success': 'Data updated successfully'})

        except Exception as e:
            print(f'Error updating trainee details: {str(e)}')
            return JsonResponse({'error': f'Error updating trainee details: {str(e)}'}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

def update_trainee_field(trainee, field_mapping, field_name, update_value):
    field_name = field_name.lower()
    print(f'Processing field: {field_name}, update_value: {update_value}')

    if field_name in field_mapping:
        model_field = field_mapping[field_name]
        if hasattr(trainee, model_field):
            setattr(trainee, model_field, update_value)
        else:
            print(f"Field '{model_field}' does not exist in the model.")
    else:
        print(f"Field '{field_name}' is not mapped in field_mapping.")


def fetch_employee_details_pdf(request, employee_id):
    # Retrieve employee details from the database
    employee = get_object_or_404(RegisterAll, id=employee_id)
    # Create a dictionary with the required employee details
    employee_details = {
        'nm': employee.nm,
        'user_id': employee.user_id,
        'depart': employee.depart,
        'dsig': employee.dsig,
        'doj': employee.doj,
        'bank': employee.bank,
        'fath_nm': employee.fath_nm,
        'gender': employee.gender,
        'branch': employee.branch,
        'mr_mrs_ms': employee.mr_mrs_ms,
        'addr': employee.addr,
        'locca': employee.locca,
        'company': employee.company,
        # Add more fields as needed
    }
    # Return the employee details as JSON response
    return JsonResponse(employee_details)
#  branches = Branch.objects.all()

#         param = {'current_user': user, 'nm_value': nm_value, 'branches': branches}
#         print(f"Current user: {param}")


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def birthday_report(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    # if selected_month:
    #     data = RegisterAll.objects.filter(dob__month=selected_month)
    # else:
    # data = RegisterAll.objects.all()
    return render(request, 'birthday_report.html', {'current_user': current_user , 'branches': branches,'default_branch':default_branch})


# def birthday_report_fetch(request):
#     selected_month = request.GET.get('selected_month')
    

#     if selected_month:
#         data = RegisterAll.objects.filter(dob__month=selected_month).values('user_id','dob','nm')
#         data_list = list(data)

        
#         return JsonResponse(data_list, safe=False)
#     else:
#         return JsonResponse({'error': 'Invalid request'})

def birthday_report_fetch(request):
    selected_month = request.GET.get('selected_month')
    
    # Check if 'selected_branch_id' is present in the session
    if 'selected_branch_id' in request.session:
        selected_branch_id = request.session['selected_branch_id']
    else:
        selected_branch_id = request.session.get('default_branch_id')

    # Check if 'selected_all' is set in the session
    selected_all = request.session.get('selected_all', False)

    # If selected_all is True, fetch details for all branches
    if selected_all:
        data = RegisterAll.objects.filter(
            dob__month=selected_month
        ).values('user_id', 'dob', 'nm')
    else:
        # If selected_branch_id is not present, return error response
        if not selected_branch_id:
            return HttpResponse(status=404)

        try:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.employee_code[:3]
            selected_branch_admin_code = branch.admin_code[:3]
            selected_branch_trainee_code = branch.trainee_code[:3]
        except Branch.DoesNotExist:
            return HttpResponse(status=404)

        # Filter data based on selected branch
        data = RegisterAll.objects.filter(
            Q(dob__month=selected_month) &
            (Q(user_id__startswith=selected_branch_employee_code) |
             Q(user_id__startswith=selected_branch_admin_code) |
             Q(user_id__startswith=selected_branch_trainee_code))
        ).values('user_id', 'dob', 'nm')

    data_list = list(data)

    return JsonResponse(data_list, safe=False)




# def birthday_report_fetch(request):
#     selected_month = request.GET.get('selected_month')
    
#     if 'selected_branch_id' in request.session:
#         selected_branch_id = request.session['selected_branch_id']
        
#         branch = Branch.objects.get(branch_name=selected_branch_id)
#         selected_branch_employee_code = branch.employee_code[:3]
#         selected_branch_admin_code = branch.admin_code[:3]
#         selected_branch_trainee_code = branch.trainee_code[:3]

#         data = RegisterAll.objects.filter(
#             Q(dob__month=selected_month) &
#             (Q(user_id__startswith=selected_branch_employee_code) |
#              Q(user_id__startswith=selected_branch_admin_code) |
#              Q(user_id__startswith=selected_branch_trainee_code))
#         ).values('user_id', 'dob', 'nm')

#         data_list = list(data)

#         return JsonResponse(data_list, safe=False)
#     elif selected_month:
#         data = RegisterAll.objects.filter(dob__month=selected_month).values('user_id', 'dob', 'nm')
#         data_list = list(data)

#         return JsonResponse(data_list, safe=False)
#     else:
#         return JsonResponse({'error': 'Invalid request'})




@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def anniversary_report(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request, 'anniversary_report.html', {'current_user': current_user , 'branches': branches ,'default_branch':default_branch})


# def anniversary_report_fetch(request):
#     selected_month = request.GET.get('selected_month')
#     if selected_month:
#         data = RegisterAll.objects.filter(doj__month=selected_month).values('user_id','dob','nm')
#         data_list = list(data)
#         return JsonResponse(data_list, safe=False)
#     else:
#         return JsonResponse({'error': 'Invalid request'})

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def anniversary_report(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch  = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request, 'anniversary_report.html', {'current_user': current_user , 'branches': branches , 'default_branch':default_branch})


def anniversary_report_fetch(request):
    selected_month = request.GET.get('selected_month')
    selected_branch_id = request.session.get('selected_branch_id', request.session.get('default_branch_id'))

    # Check if 'selected_all' is set in the session
    selected_all = request.session.get('selected_all', False)

    # If selected_all is True, fetch details for all branches
    if selected_all:
        data = RegisterAll.objects.filter(dob__month=selected_month).values('user_id', 'doj', 'nm')
        data_list = list(data)
        return JsonResponse(data_list, safe=False)

    # If selected_month is provided
    elif selected_month:
        # If selected_branch_id is not present, return error response
        if not selected_branch_id:
            return HttpResponse(status=404)

        try:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.employee_code[:3]
            selected_branch_admin_code = branch.admin_code[:3]
            selected_branch_trainee_code = branch.trainee_code[:3]
        except Branch.DoesNotExist:
            return HttpResponse(status=404)

        # Filter data based on selected branch and month
        data = RegisterAll.objects.filter(
            Q(dob__month=selected_month) &
            (Q(user_id__startswith=selected_branch_employee_code) |
             Q(user_id__startswith=selected_branch_admin_code) |
             Q(user_id__startswith=selected_branch_trainee_code))
        ).values('user_id', 'doj', 'nm')

        data_list = list(data)
        return JsonResponse(data_list, safe=False)

    # If selected_month is not provided, return error response
    else:
        return JsonResponse({'error': 'Invalid request'})





@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def empwise(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()

        # param = {'current_user': user, 'nm_value': nm_value, 'branches': branches}
        # print(f"Current user: {param}")
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request,'empwise.html', {'current_user': current_user , 'branches':branches ,'default_branch':default_branch})   



# @require_POST
# @csrf_exempt
# def fetch_data_radio(request):
#     role = request.POST.get('role')

#     if role is None:
#         return JsonResponse({'error': 'Role is not provided'})

#     print(f"role: {role}")

#     try:
#         if role == 'admin':
#             # Fetch data for admin role with depart containing 'ad'
#             data = list(RegisterAll.objects.filter(depart__contains='ad').values('user_id', 'nm', 'depart').distinct())
#             print(f"data: {data}")
#         elif role == 'staff':
#             # Fetch data for staff role
#             data = list(RegisterAll.objects.filter(depart__contains='emp').values('user_id', 'nm', 'depart').distinct())
#             print(f"data1: {data}")
#         else:
#             # Handle other roles or invalid requests
#             data = list(RegisterAll.objects.values('user_id', 'nm', 'depart').distinct())
#             print(f"data:{data}")

#         return JsonResponse({'data': data})
#     except Exception as e:
#         return JsonResponse({'error': str(e)})

from django.db.models import Q
@require_POST
@csrf_exempt
def fetch_data_radio(request):
    role = request.POST.get('role')
    selected_all = request.session.get('selected_all')

    if selected_all:
        # Fetch all details when selected_all session variable is set
        try:
            if role == 'admin':
                # Fetch data for admin role with depart containing 'ad'
                data = list(RegisterAll.objects.filter(depart__contains='ad').values('user_id', 'nm', 'depart').distinct())
                print(f"data: {data}")
            elif role == 'staff':
                # Fetch data for staff role
                data = list(RegisterAll.objects.filter(depart__contains='emp').values('user_id', 'nm', 'depart').distinct())
                print(f"data1: {data}")
            else:
                # Handle other roles or invalid requests
                data = list(RegisterAll.objects.exclude(depart__contains='SAD').values('user_id', 'nm', 'depart').distinct())
            return JsonResponse({'data': data})
        except Exception as e:
            return JsonResponse({'error': str(e)})

    if 'selected_branch_id' in request.session:
        selected_branch_id = request.session['selected_branch_id']
    else:
        selected_branch_id = request.session.get('default_branch_id')

    try:
        if selected_branch_id:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.employee_code[:3]
            selected_branch_admin_code = branch.admin_code[:3]
            selected_branch_trainee_code = branch.trainee_code[:3]
        else:
            # Fetch default branch details
            default_branch = request.session['default_branch_id']
            default_branch_obj = Branch.objects.get(branch_name=default_branch)
            selected_branch_employee_code = default_branch_obj.employee_code[:3]
            selected_branch_admin_code = default_branch_obj.admin_code[:3]
            selected_branch_trainee_code = default_branch_obj.trainee_code[:3]
    except Branch.DoesNotExist:
        return JsonResponse({'error': 'Branch does not exist'})

    try:
        if role is None:
            return JsonResponse({'error': 'Role is not provided'})

        print(f"role: {role}")

        if selected_branch_id:
            if role == 'admin':
                # Fetch data for admin role with depart containing 'ad' and specific branch code
                data = list(RegisterAll.objects.filter(depart__contains='ad', user_id__startswith=selected_branch_admin_code).values('user_id', 'nm', 'depart').distinct())
                print(f"data: {data}")
            elif role == 'staff':
                # Fetch data for staff role with specific branch code
                data = list(RegisterAll.objects.filter(depart__contains='emp', user_id__startswith=selected_branch_employee_code).values('user_id', 'nm', 'depart').distinct())
                print(f"data1: {data}")
            else:
                # Handle other roles or invalid requests with specific branch codes
                data = list(RegisterAll.objects.filter(
                    Q(user_id__startswith=selected_branch_employee_code) |
                    Q(user_id__startswith=selected_branch_admin_code) |
                    Q(user_id__startswith=selected_branch_trainee_code)
                ).values('user_id', 'nm', 'depart').distinct())
                print(f"data:{data}")
        else:
            if role == 'admin':
                # Fetch data for admin role with depart containing 'ad'
                data = list(RegisterAll.objects.filter(depart__contains='ad').values('user_id', 'nm', 'depart').distinct())
                print(f"data: {data}")
            elif role == 'staff':
                # Fetch data for staff role
                data = list(RegisterAll.objects.filter(depart__contains='emp').values('user_id', 'nm', 'depart').distinct())
                print(f"data1: {data}")
            else:
                # Handle other roles or invalid requests
                data = list(RegisterAll.objects.exclude(depart__contains='SAD').values('user_id', 'nm', 'depart').distinct())
                print(f"data:{data}")

        return JsonResponse({'data': data})
    except Exception as e:
        return JsonResponse({'error': str(e)})




# def fetch_data_radio(request):
#     role = request.POST.get('role')
    
#     if 'selected_branch_id' in request.session:
#         selected_branch_id = request.session['selected_branch_id']
        
#         branch = Branch.objects.get(branch_name=selected_branch_id)
#         selected_branch_employee_code = branch.employee_code[:3]
#         selected_branch_admin_code = branch.admin_code[:3]
#         selected_branch_trainee_code = branch.trainee_code[:3]
#     else:
#         # No branch selected, fetch data without branch filtering
#         try:
#             if role is None:
#                 return JsonResponse({'error': 'Role is not provided'})

#             print(f"role: {role}")

#             if role == 'admin':
#                 # Fetch data for admin role with depart containing 'ad'
#                 data = list(RegisterAll.objects.filter(depart__contains='ad').values('user_id', 'nm', 'depart').distinct())
#                 print(f"data: {data}")
#             elif role == 'staff':
#                 # Fetch data for staff role
#                 data = list(RegisterAll.objects.filter(depart__contains='emp').values('user_id', 'nm', 'depart').distinct())
#                 print(f"data1: {data}")
#             else:
#                 # Handle other roles or invalid requests
#                 data = list(RegisterAll.objects.exclude(depart__contains='SAD').values('user_id', 'nm', 'depart').distinct())
#                 print(f"data:{data}")


#             return JsonResponse({'data': data})
#         except Exception as e:
#             return JsonResponse({'error': str(e)})

#     if role is None:
#         return JsonResponse({'error': 'Role is not provided'})

#     print(f"role: {role}")

#     try:
#         if role == 'admin':
#             # Fetch data for admin role with depart containing 'ad' and specific branch code
#             data = list(RegisterAll.objects.filter(depart__contains='ad', user_id__startswith=selected_branch_admin_code).values('user_id', 'nm', 'depart').distinct())
#             print(f"data: {data}")
#         elif role == 'staff':
#             # Fetch data for staff role with specific branch code
#             data = list(RegisterAll.objects.filter(depart__contains='emp', user_id__startswith=selected_branch_employee_code).values('user_id', 'nm', 'depart').distinct())
#             print(f"data1: {data}")
#         else:
#             # Handle other roles or invalid requests with specific branch codes
#             data = list(RegisterAll.objects.filter(
#                 Q(user_id__startswith=selected_branch_employee_code) |
#                 Q(user_id__startswith=selected_branch_admin_code) |
#                 Q(user_id__startswith=selected_branch_trainee_code)
#             ).values('user_id', 'nm', 'depart').distinct())
#             print(f"data:{data}")

#         return JsonResponse({'data': data})
#     except Exception as e:
#         return JsonResponse({'error': str(e)})




@require_GET
def fetch_attendance(request):
    user_id = request.GET.get('user_id')
    print(f"user_id: {user_id}")

    if not user_id:
        return JsonResponse({'error': 'User ID is a required parameter.'}, status=400)

    try:
        # Fetch all fields for the specified user_id
        attendance_details = list(Attendance.objects.filter(user_id=user_id).values('clk_in_tm', 'date', 'clk_out_tm', 'tot_hr', 'clkin_ip', 'clkout_ip', 'user_id' , 'work_frm' , 'work_to','id', 'mnth', 'yr'))

        print(f"attendance_details: {attendance_details}")

        # You can extract relevant information for the JSON response
        return JsonResponse({'attendance_details': attendance_details})
    except Attendance.DoesNotExist:
        return JsonResponse({'error': 'Attendance details not found for the specified user.'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    




@require_POST
@csrf_exempt
def edit_attendance(request, formatted_date):
    if request.method == 'POST':
        data = json.loads(request.body)
        print(f"formatted_date: {formatted_date}")

        
        clk_in_tm = timezone.datetime.strptime(
            f'{formatted_date} {data.get("in_time")}:{data.get("number_Select")} {data.get("workfromperiod")}',
            '%Y-%m-%d %I:%M %p'
        )
        print(f"clk_in_tm: {clk_in_tm}")

        clk_out_tm = timezone.datetime.strptime(
            f'{formatted_date} {data.get("out_time")}:{data.get("workto_Select")} {data.get("worktoperiod")}',
            '%Y-%m-%d %I:%M %p'
        )


        clk_in_dt_tm = f'{formatted_date} {clk_in_tm.time()}'
        clk_out_dt_tm = f'{formatted_date} {clk_out_tm.time()}'
        # Calculate total hours worked
        # total_hours_worked = (clk_out_tm - clk_in_tm).total_seconds() / 3600.0
        time_difference = clk_out_tm - clk_in_tm

                    # Convert the time difference to total hours
        tot_hr_seconds = time_difference.total_seconds()
        tot_hr = timedelta(seconds=tot_hr_seconds)
        tot_hr_str = str(tot_hr)
        print(f"tot_hr_str: {tot_hr_str}")

        # Use filter instead of get to handle multiple records for the same date
        attendance_list = Attendance.objects.filter(date=formatted_date)

        if attendance_list.exists():
            # Assuming you want to update all records for the given date
            for attendance in attendance_list:
                attendance.clk_in_tm = clk_in_tm
                attendance.clk_out_tm = clk_out_tm
                attendance.clk_in_dt_tm = clk_in_dt_tm
                attendance.clk_out_dt_tm = clk_out_dt_tm
                attendance.tot_hr = tot_hr_str
                

                attendance.save()

            # You can customize the response based on your needs
            return JsonResponse({'message': 'Changes saved successfully'})
        else:
            return JsonResponse({'message': 'No records found for the given date'})

    # Handle GET request if needed
    return render(request, 'empwise.html', {'date': formatted_date})



@require_POST
def fetch_work_schedule(request):
    try:
        user_id = request.POST.get('user_id')
        print(f"user_idtyhtrh:{user_id}")
        # Assuming you have a RegisterAll model with fields 'user_id', 'date', 'work_from', and 'work_to'
        register_entry = RegisterAll.objects.filter(user_id=user_id).first()

        if register_entry:
            work_from = register_entry.work_frm
            work_to = register_entry.work_to
            depart = register_entry.depart
            return JsonResponse({'success': True, 'work_from': work_from, 'work_to': work_to,'depart':depart})
        else:
            return JsonResponse({'success': False, 'error': 'No work schedule found for the given user and date.'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})




@require_POST
def add_in_out(request):
    try:
      # Extract data from the POST request
        user_id = request.POST.get('user_id')
        date_str = request.POST.get('date')
        print(f"date_str: {date_str}")
        clk_in = request.POST.get('clk_in', 0)
        clk_out = request.POST.get('clk_out', 1)

        in_time_str = request.POST.get('in_time')
        in_select_str = request.POST.get('number_Select')
        in_period_str = request.POST.get('workfromperiod')

        workfrom_combined = f"{in_time_str}:{in_select_str} {in_period_str}"
        workfrom_time_obj = datetime.strptime(workfrom_combined, '%I:%M %p').time()

        print(f"workfrom_time_obj: {workfrom_time_obj}")

        out_time_str = request.POST.get('out_time')
        out_select_str = request.POST.get('workto_Select')
        out_period_str = request.POST.get('worktoperiod')
        workto_combined = f"{out_time_str}:{out_select_str} {out_period_str}"
        workto_time_obj = datetime.strptime(workto_combined, '%I:%M %p').time()


        print(f"workto_time_obj: {workto_time_obj}")


        work_from = request.POST.get('work_from')
        print(f"work_from: {work_from}")
        work_to = request.POST.get('work_to')
        print(f"work_to: {work_to}")
        depart = request.POST.get('depart')

# ...

# Combine date and time using datetime.strptime for in_time_str and out_time_str
        in_datetime = datetime.strptime(f"{date_str} {workfrom_time_obj.strftime('%H:%M')}", "%Y-%m-%d %H:%M")
        print(f"in_datetime {in_datetime}")
        out_datetime = datetime.strptime(f"{date_str} {workto_time_obj.strftime('%H:%M')}", "%Y-%m-%d %H:%M")
        print(f"out_datetime {out_datetime}")

# ...


        # Calculate time difference
        time_difference = out_datetime - in_datetime

        # Convert the time difference to total seconds
        tot_seconds = time_difference.total_seconds()

        # Format the seconds into HH:MM:SS
        tot_hr_str = str(timedelta(seconds=tot_seconds))[0:8]  # Extract HH:MM:SS part

        # Now, tot_hr_str contains the formatted time difference in the HH:MM:SS format
        print(f"tot_hr_str: {tot_hr_str}")

        select_datetime = datetime.strptime(date_str, "%Y-%m-%d")
        month = select_datetime.month
        year = select_datetime.year
        late_resn_status = request.POST.get('late_resn_status', 0)

        # Insert data into the Attendance table
        attendance = Attendance(user_id=user_id, depart=depart, clk_in=clk_in, clk_out=clk_out, work_frm=work_from, work_to=work_to,  date=date_str, clk_in_tm=workfrom_time_obj, clk_out_tm=workto_time_obj, clk_in_dt_tm=in_datetime, clk_out_dt_tm=out_datetime, tot_hr=tot_hr_str, mnth=month, yr=year, late_resn_status=late_resn_status)
        attendance.save()

        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


from django.views.decorators.http import require_http_methods

@require_http_methods(["DELETE"])
def delete_record(request, record_id):
    record = get_object_or_404(Attendance, pk=record_id)
    record.delete()
    return JsonResponse({'message': 'Record deleted successfully'})



@require_GET
def fetch_user_data(request):
    user_id = request.GET.get('user_id')
    print(f"user_id: {user_id}")
    mnth = request.GET.get('mnth')
    yr = request.GET.get('yr')
    lev_typ = request.GET.get('lev_typ', 'LOP')

    if not user_id or not lev_typ or not mnth or not yr:
        return JsonResponse({'error': 'User ID is a required parameter.'}, status=400)

    try:
        # Fetch all fields for the specified user_id
        lop_details = list(EmpLeaves.objects.filter(user_id=user_id , lev_typ=lev_typ ,mnth=mnth, yr=yr ).values('from_dt','to_dt','tot_days','reason','lev_typ','mnth','yr'))

        print(f"lop_details: {lop_details}")
        
        # Get the count of rows
        lop_count = len(lop_details)
        print(f"lop_count: {lop_count}")
        # You can extract relevant information for the JSON response
        return JsonResponse({'lop_details': lop_details, 'lop_count': lop_count})
    except Attendance.DoesNotExist:
        return JsonResponse({'error': 'Attendance details not found for the specified user.'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)



@require_GET
def fetch_cl(request):
    user_id = request.GET.get('user_id')
    print(f"user_id: {user_id}")
    mnth = request.GET.get('mnth')
    yr = request.GET.get('yr')
    lev_typ = request.GET.get('lev_typ', 'CL')

    if not user_id or not lev_typ or not mnth or not yr:
        return JsonResponse({'error': 'User ID is a required parameter.'}, status=400)

    try:
        # Fetch all fields for the specified user_id
        lop_details = list(EmpLeaves.objects.filter(user_id=user_id , lev_typ=lev_typ ,mnth=mnth, yr=yr).values('from_dt','to_dt','tot_days','reason','lev_typ','mnth','yr'))

        print(f"cl_details: {lop_details}")

        # You can extract relevant information for the JSON response
        return JsonResponse({'lop_details': lop_details})
    except Attendance.DoesNotExist:
        return JsonResponse({'error': 'Attendance details not found for the specified user.'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)





@require_GET
def fetch_halflop(request):
    user_id = request.GET.get('user_id')
    print(f"user_id: {user_id}")
    lev_typ = request.GET.get('lev_typ', 'HALF DAY-LOP')

    if not user_id or not lev_typ:
        return JsonResponse({'error': 'User ID is a required parameter.'}, status=400)

    try:
        # Fetch all fields for the specified user_id
        halflop_details = list(EmpLeaves.objects.filter(user_id=user_id , lev_typ=lev_typ).values('from_dt','to_dt','tot_days','reason','lev_typ'))

        print(f"halflop_details: {halflop_details}")

        # You can extract relevant information for the JSON response
        return JsonResponse({'halflop_details': halflop_details})
    except Attendance.DoesNotExist:
        return JsonResponse({'error': 'Attendance details not found for the specified user.'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)



@require_GET
def fetch_od(request):
    user_id = request.GET.get('user_id')
    print(f"user_id: {user_id}")
    mnth = request.GET.get('mnth')
    yr = request.GET.get('yr')
    lev_typ = request.GET.get('lev_typ', 'OD')

    if not user_id or not lev_typ or not mnth or not yr:
        return JsonResponse({'error': 'User ID is a required parameter.'}, status=400)

    try:
        # Fetch all fields for the specified user_id
        od_details = list(EmpLeaves.objects.filter(user_id=user_id , lev_typ=lev_typ ,mnth=mnth, yr=yr).values('from_dt','to_dt','tot_days','reason','lev_typ','mnth','yr'))

        print(f"od_details: {od_details}")

        # You can extract relevant information for the JSON response
        return JsonResponse({'od_details': od_details})
    except Attendance.DoesNotExist:
        return JsonResponse({'error': 'Attendance details not found for the specified user.'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_GET
def fetch_halfcl(request):
    user_id = request.GET.get('user_id')
    print(f"user_id: {user_id}")
    lev_typ = request.GET.get('lev_typ', 'HALF DAY-CL')

    if not user_id or not lev_typ:
        return JsonResponse({'error': 'User ID is a required parameter.'}, status=400)

    try:
        # Fetch all fields for the specified user_id
        halfcl_details = list(EmpLeaves.objects.filter(user_id=user_id , lev_typ=lev_typ).values('from_dt','to_dt','tot_days','reason','lev_typ'))
        
        print(f"halfcl_details: {halfcl_details}")

        # You can extract relevant information for the JSON response
        return JsonResponse({'halfcl_details': halfcl_details})
    except Attendance.DoesNotExist:
        return JsonResponse({'error': 'Attendance details not found for the specified user.'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
               

@require_GET
def fetch_halfod(request):
    user_id = request.GET.get('user_id')
    print(f"user_id: {user_id}")
    lev_typ = request.GET.get('lev_typ', 'HALF DAY-OD')

    if not user_id or not lev_typ:
        return JsonResponse({'error': 'User ID is a required parameter.'}, status=400)

    try:
        # Fetch all fields for the specified user_id
        halfod_details = list(EmpLeaves.objects.filter(user_id=user_id , lev_typ=lev_typ).values('from_dt','to_dt','tot_days','reason','lev_typ'))

        print(f"halfod_details: {halfod_details}")

        # You can extract relevant information for the JSON response
        return JsonResponse({'halfod_details': halfod_details})
    except Attendance.DoesNotExist:
        return JsonResponse({'error': 'Attendance details not found for the specified user.'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_GET
def fetch_holiday(request):
    mnth = request.GET.get('mnth')
    print(f"mnth: {mnth}")
    yr = request.GET.get('yr')
    print(f"yr: {yr}")
    if not mnth or not yr:
        return JsonResponse({'error': 'User ID is a required parameter.'}, status=400)

    try:
        # Fetch all fields for the specified user_id
        holiday_details = list(Holiday.objects.filter(month=mnth , year=yr).values('reason','holiday_date','month','year'))

        print(f"holiday_details: {holiday_details}")

        # You can extract relevant information for the JSON response
        return JsonResponse({'holiday_details': holiday_details})
    except Attendance.DoesNotExist:
        return JsonResponse({'error': 'Attendance details not found for the specified user.'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)




@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def add_permission(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request, 'add_permission.html', {'current_user': current_user , 'branches': branches , 'default_branch':default_branch})

#Add Permission
def add_permission1(request):
    if request.method == "POST":
        # Get data from the POST request
        name = request.POST.get("name")
        user_id = request.POST.get("user_id")
        permi_dt = request.POST.get("permi_dt")
        resn = request.POST.get("resn")
        permi_tm_start_am = request.POST.get("permi_tm_start_am")
        permi_tm_end_am = request.POST.get("permi_tm_end_am")
        permi_24tm_start = request.POST.get("permi_24tm_start")
        permi_24tm_end = request.POST.get("permi_24tm_end_am")
        permi_hr = request.POST.get("permi_hr")
        submit_dt = request.POST.get("submit_dt")
        permi_mnth = request.POST.get("permi_mnth")
        permi_yr = request.POST.get("permi_yr")
        permi_frm = request.POST.get("permi_frm")


        # Insert data into the AddPermission model
        PermissionAdd.objects.create(
            name=name,
            user_id=user_id,
            permi_dt=permi_dt,
            resn=resn,
            permi_tm_start_am=permi_tm_start_am,
            permi_tm_end_am=permi_tm_end_am,
            permi_24tm_start=permi_24tm_start,
            permi_24tm_end=permi_24tm_end,
            permi_hr=permi_hr,
            submit_dt=submit_dt,
            permi_mnth=permi_mnth,
            permi_yr=permi_yr,
            permi_frm=permi_frm
        )

        # You can return a JsonResponse if needed
        return JsonResponse({"message": "Data successfully inserted"}, status=200)

    return render(request, "add_permission.html")

# def permission_report(request):
#     # Get the selected year and month from the request
#     selected_year = request.GET.get('selected_year')
#     selected_month = request.GET.get('selected_month')
#     user_id = request.GET.get('user_id')
#     print(f"hjbjvg {user_id}")

#     if 'selected_branch_id' in request.session:
#         selected_branch_id = request.session['selected_branch_id']
        
#         branch = Branch.objects.get(branch_name=selected_branch_id)
#         selected_branch_employee_code = branch.employee_code[:3]
#         selected_branch_admin_code = branch.admin_code[:3]
#         selected_branch_trainee_code = branch.trainee_code[:3]

#         # Fetch data for the selected branch
#         data = list(PermissionAdd.objects.filter(
#             Q(user_id__startswith=selected_branch_employee_code) |
#             Q(user_id__startswith=selected_branch_admin_code) |
#             Q(user_id__startswith=selected_branch_trainee_code),
#             permi_dt__year=selected_year,
#             permi_dt__month=selected_month,
#             user_id=user_id
#         ).values(
#             'permi_hr',
#             'permi_frm',
#             'permi_dt',
#             'resn',
#             'permi_tm_start_am',
#             'permi_tm_end_am',
#             'id',
#             'user_id'
#         ))
#     else:
#         # No branch selected, fetch data without branch filtering
#         data = list(PermissionAdd.objects.filter(
#             permi_dt__year=selected_year,
#             permi_dt__month=selected_month
#         ).values(
#             'permi_hr',
#             'permi_frm',
#             'permi_dt',
#             'resn',
#             'permi_tm_start_am',
#             'permi_tm_end_am',
#             'id',
#             'user_id'
#         ))

#     # Convert queryset to JSON format
#     print(f"records_list{data}")
#     return JsonResponse(data, safe=False)

def permission_report(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session.get('default_branch_id')
        branches = Branch.objects.all()
        
        selected_branch_id = request.session.get('selected_branch_id', default_branch)

        # Check if 'selected_all' is set in the session
        selected_all = request.session.get('selected_all', False)
        
        selected_year = request.GET.get('selected_year')
        selected_month = request.GET.get('selected_month')
        user_id = request.GET.get('user_id')
        # Initialize data_list variable
        # data_list = []
        
        try:
            if selected_all:
                # Fetch details for all branches
                data = list(PermissionAdd.objects.filter(
                    permi_dt__year=selected_year,
                    permi_dt__month=selected_month
                ).values(
                    'permi_hr',
                    'permi_frm',
                    'permi_dt',
                    'resn',
                    'permi_tm_start_am',
                    'permi_tm_end_am',
                    'id',
                    'user_id'
                ))
            else:
                # If selected_branch_id is not present or invalid, return error response
                if not selected_branch_id:
                    return HttpResponse(status=404)

                branch = Branch.objects.get(branch_name=selected_branch_id)
                selected_branch_employee_code = branch.employee_code[:3]
                selected_branch_admin_code = branch.admin_code[:3]
                selected_branch_trainee_code = branch.trainee_code[:3]

                # Filter data based on branch and selected year/month
                data = list(PermissionAdd.objects.filter(
                    Q(user_id__startswith=selected_branch_employee_code) |
                    Q(user_id__startswith=selected_branch_admin_code) |
                    Q(user_id__startswith=selected_branch_trainee_code),
                    permi_dt__year=selected_year,
                    permi_dt__month=selected_month,
                    user_id=user_id
                ).values(
                    'permi_hr',
                    'permi_frm',
                    'permi_dt',
                    'resn',
                    'permi_tm_start_am',
                    'permi_tm_end_am',
                    'id',
                    'user_id'
                ))

            # Convert the QuerySet to a list to be sent as JSON
           

        except Branch.DoesNotExist:
            # Handle the case when the selected branch does not exist
            return redirect('errorpage')

        return JsonResponse(data, safe=False)
    else:
        # Handle the case when the user is not logged in
        return HttpResponse(status=401)

# @require_GET
# def salary_approval_fetch(request):
#     # Get the selected year and month from the request
#     selected_year = request.GET.get('selected_year')
#     selected_month = request.GET.get('selected_month')

#     # Assuming PayrollMaathangi has fields like 'emp_nm', 'emp_id', 'salary_month', etc.
#     # Update the field names accordingly in the values() method
#     records = PayrollMaathangi.objects.filter(
#         salary_month__year=selected_year,
#         salary_month__month=selected_month
#     ).values(
#         'emp_nm',
#         'emp_id',
#         'salary_month',
#         'actual_sal',
#         'salary',
#         'sts',
#     )

#     # Convert the queryset to a list for JSON serialization
#     records_list = list(records)

#     return JsonResponse(records_list, safe=False)    

from django.shortcuts import get_list_or_404


# def delete_permission_record(request, userId):
def delete_permission_record(request,id):
     data = PermissionAdd.objects.get(id=id)
     data.delete()
     
     return redirect('add_permission')


def delete_permission_record1(request,id):
     data = PermissionAdd.objects.get(id=id)
     data.delete()
     
     return redirect('permission_report1')     

# @require_POST
# def delete_permission_record(request):
#     try:
#         user_id = request.POST.get('userId')
#         print(f"{user_id}")
#         permission_instances = get_list_or_404(PermissionAdd, user_id=user_id)

#         # Check if there is exactly one matching instance
#         if len(permission_instances) != 1:
#             return JsonResponse({'error': 'Record not found or not unique'}, status=404)

#         # If there is exactly one matching instance, delete it
#         permission_instance = permission_instances[0]
#         permission_instance.delete()

#         return JsonResponse({'message': 'Record deleted successfully'}, status=200)

#     except Exception as e:
#         # Print the exception to the console for debugging
#         print(e)
#         return JsonResponse({'error': 'Internal Server Error'}, status=500)


def late_report(request):
    if 'username' in request.session:
        current_user = request.session['username']
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request, 'late_report.html', {'current_user': current_user})



#salary report
from django.db.models import F
from django.db.models.functions import ExtractYear, ExtractMonth
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
# def salary_report(request):
#     if 'username' in request.session:
#         current_user = request.session['username']
#         default_branch = request.session['default_branch_id']
#         branches = Branch.objects.all()
#         if 'selected_branch_id' in request.session:
#             selected_branch_id = request.session['selected_branch_id']
#             try:
#                 branch = Branch.objects.get(branch_name=selected_branch_id)
#                 selected_branch_employee_code = branch.employee_code[:3]
#                 selected_branch_admin_code = branch.admin_code[:3]
#                 selected_branch_trainee_code = branch.trainee_code[:3]
#                 data = RegisterAll.objects.filter(
#                     Q(user_id__startswith=selected_branch_employee_code) |
#                     Q(user_id__startswith=selected_branch_admin_code) |
#                     Q(user_id__startswith=selected_branch_trainee_code)
#                 ).values()
#                 print(f"data {data}")
#             except Branch.DoesNotExist:
#                 # Handle the case when the selected branch does not exist
#                 return redirect('salary_report')  # You can set it to None or any default value
#         else:
#             # If branch is not selected, display all data
#             data = RegisterAll.objects.exclude(depart="SAD").values()

#             selected_branch_id = None
#     else:
#         # Handle the case when the user is not logged in
#         return redirect('loginpage')  # You can set it to None or any default value
#     return render(request, 'salary_report.html', {'current_user': current_user, 'data': data, 'branches': branches, 'selected_branch_id': selected_branch_id , 'default_branch':default_branch})

def salary_report(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session.get('default_branch_id')  # Using .get() to handle missing default_branch_id gracefully
        branches = Branch.objects.all()
        
        if 'selected_branch_id' in request.session and request.session['selected_branch_id']:
            selected_branch_id = request.session['selected_branch_id']
        elif 'selected_all' in request.session and request.session['selected_all']:
            selected_branch_id = None  # All branches selected
        else:
            selected_branch_id = default_branch
        
        if selected_branch_id:
            try:
                branch = Branch.objects.get(branch_name=selected_branch_id)
                selected_branch_employee_code = branch.employee_code[:3]
                selected_branch_admin_code = branch.admin_code[:3]
                selected_branch_trainee_code = branch.trainee_code[:3]
                data = RegisterAll.objects.filter(
                    Q(user_id__startswith=selected_branch_employee_code) |
                    Q(user_id__startswith=selected_branch_admin_code) |
                    Q(user_id__startswith=selected_branch_trainee_code)
                ).values()
            except Branch.DoesNotExist:
                return redirect('salary_report')  # Handle the case when the selected branch does not exist
        else:
            # Display all data when selected_all is True or no branch is selected
            data = RegisterAll.objects.exclude(depart="SAD").values()
        
    else:
        return redirect('loginpage')  # Handle the case when the user is not logged in
    
    return render(request, 'salary_report.html', {'current_user': current_user, 'data': data, 'branches': branches, 'selected_branch_id': selected_branch_id, 'default_branch': default_branch})


# def salary_report(request):
#     if 'username' in request.session:
#         current_user = request.session['username']
#         branches = Branch.objects.all()
#     else:
#         # Handle the case when the user is not logged in
#         return redirect('loginpage')  # You can set it to None or any default value
#     # Fetch data from the RegisterAll model
#     data = RegisterAll.objects.all()
#     # Send data to the template
#     return render(request, 'salary_report.html', {'current_user': current_user, 'data': data, 'branches': branches})

def salary_report_retrive(request):
    user_id = request.GET.get('user_id')
    selected_year = request.GET.get('selected_year')
    selected_month = request.GET.get('selected_month')

    # Assuming your model is named PayrollMaathangi
    data = PayrollMaathangi.objects.filter(
        emp_id=user_id,
        salary_month__year=selected_year,
        salary_month__month=selected_month
    ).values('emp_nm','emp_id', 'actual_sal', 'salary_month', 'pf_amt', 'insu_amt', 'esi_amt', 'salary', 'sts')

    # Convert the QuerySet to a list to be sent as JSON
    data_list = list(data)

    # Return the data as JSON
    return JsonResponse(data_list, safe=False)

# @require_GET
# def fetch_all_staff_records(request):
#     # Get the selected year and month from the request
#     selected_year = request.GET.get('selected_year')
#     selected_month = request.GET.get('selected_month')

#     # Assuming PayrollMaathangi has fields like 'emp_nm', 'emp_id', 'salary_month', etc.
#     # Update the field names accordingly in the values() method
#     records = PayrollMaathangi.objects.filter(
#         salary_month__year=selected_year,
#         salary_month__month=selected_month
#     ).values(
#         'emp_nm',
#         'emp_id',
#         'salary_month',
#         'pf_amt',
#         'insu_amt',
#         'esi_amt',
#         'salary',
#         'sts',
#     )

#     # Convert the queryset to a list for JSON serialization
#     records_list = list(records)

#     return JsonResponse(records_list, safe=False)

@require_GET
def fetch_all_staff_records(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session.get('default_branch_id')
        branches = Branch.objects.all()
        
        selected_branch_id = request.session.get('selected_branch_id', default_branch)

        # Check if 'selected_all' is set in the session
        selected_all = request.session.get('selected_all', False)
        selected_year = request.GET.get('selected_year')
        selected_month = request.GET.get('selected_month')

        # Initialize data_list variable
        records_list = []

        try:
            if selected_all:
                # Fetch details for all branches
                records = PayrollMaathangi.objects.filter(
                    salary_month__year=selected_year,
                    salary_month__month=selected_month
                ).values(
                    'emp_nm',
                    'emp_id',
                    'salary_month',
                    'pf_amt',
                    'insu_amt',
                    'esi_amt',
                    'salary',
                    'sts',
                )
            else:
                # If selected_branch_id is not present or invalid, return error response
                if not selected_branch_id:
                    return HttpResponse(status=404)

                branch = Branch.objects.get(branch_name=selected_branch_id)
                
                selected_branch_employee_code = branch.employee_code[:3]
                selected_branch_admin_code = branch.admin_code[:3]
                selected_branch_trainee_code = branch.trainee_code[:3]
                print(f"selected_branch_employee_code {selected_branch_employee_code}")
                print(f"selected_branch_admin_code {selected_branch_admin_code}")
                print(f"selected_branch_trainee_code {selected_branch_trainee_code}")

                # Filter data based on branch and selected year/month
                records = PayrollMaathangi.objects.filter(
                    (Q(emp_id__startswith=selected_branch_employee_code) |
                    Q(emp_id__startswith=selected_branch_admin_code) |
                    Q(emp_id__startswith=selected_branch_trainee_code)) &
                    Q( salary_month__year=selected_year, salary_month__month=selected_month)
                ).values(
                    'emp_nm',
                    'emp_id',
                    'salary_month',
                    'pf_amt',
                    'insu_amt',
                    'esi_amt',
                    'salary',
                    'sts',
                )

            # Convert the QuerySet to a list to be sent as JSON
            records_list = list(records)

        except Branch.DoesNotExist:
            # Handle the case when the selected branch does not exist
            return redirect('errorpage')

        except Exception as e:
            # Handle other exceptions
            return HttpResponse(status=500)  # Return an appropriate error response

    return JsonResponse(records_list, safe=False)







@require_GET
def fetch_all_staff_records_yearly(request):
    if 'username' in request.session:
            current_user = request.session['username']
            default_branch = request.session.get('default_branch_id')
            branches = Branch.objects.all()
            
            selected_branch_id = request.session.get('selected_branch_id', default_branch)

            # Check if 'selected_all' is set in the session
            selected_all = request.session.get('selected_all', False)
            selected_year = request.GET.get('selected_year')

            # Initialize data_list variable
            records_list = []

            try:
                if selected_all:
                    # Fetch details for all branches
                    records = PayrollMaathangi.objects.filter(
                        salary_month__year=selected_year,
                        
                    ).values(
                        'emp_nm',
                        'emp_id',
                        'salary_month',
                        'pf_amt',
                        'insu_amt',
                        'esi_amt',
                        'salary',
                        'sts',
                    )
                else:
                    # If selected_branch_id is not present or invalid, return error response
                    if not selected_branch_id:
                        return HttpResponse(status=404)

                    branch = Branch.objects.get(branch_name=selected_branch_id)
                    
                    selected_branch_employee_code = branch.employee_code[:3]
                    selected_branch_admin_code = branch.admin_code[:3]
                    selected_branch_trainee_code = branch.trainee_code[:3]
                    print(f"selected_branch_employee_code {selected_branch_employee_code}")
                    print(f"selected_branch_admin_code {selected_branch_admin_code}")
                    print(f"selected_branch_trainee_code {selected_branch_trainee_code}")

                    # Filter data based on branch and selected year/month
                    records = PayrollMaathangi.objects.filter(
                        (Q(emp_id__startswith=selected_branch_employee_code) |
                        Q(emp_id__startswith=selected_branch_admin_code) |
                        Q(emp_id__startswith=selected_branch_trainee_code)) &
                        Q( salary_month__year=selected_year)
                    ).values(
                        'emp_nm',
                        'emp_id',
                        'salary_month',
                        'pf_amt',
                        'insu_amt',
                        'esi_amt',
                        'salary',
                        'sts',
                    )

                # Convert the QuerySet to a list to be sent as JSON
                records_list = list(records)

            except Branch.DoesNotExist:
                # Handle the case when the selected branch does not exist
                return redirect('errorpage')

            except Exception as e:
                # Handle other exceptions
                return HttpResponse(status=500)  # Return an appropriate error response

    return JsonResponse(records_list, safe=False)
# @require_GET
# def fetch_all_staff_records_yearly(request):
#     # Get the selected year and month from the request
#     selected_year = request.GET.get('selected_year')
#     # selected_month = request.GET.get('selected_month')

#     # Assuming PayrollMaathangi has fields like 'emp_nm', 'emp_id', 'salary_month', etc.
#     # Update the field names accordingly in the values() method
#     records = PayrollMaathangi.objects.filter(
#         salary_month__year=selected_year,
#         # salary_month__month=selected_month
#     ).values(
#         'emp_nm',
#         'emp_id',
#         'salary_month',
#         'pf_amt',
#         'insu_amt',
#         'esi_amt',
#         'salary',
#         'sts',
#     )

#     # Convert the queryset to a list for JSON serialization
#     records_list = list(records)

#     return JsonResponse(records_list, safe=False)



#Salary Approval
@require_GET

def salary_approval_fetch(request):
    # Get the selected year and month from the request
    selected_year = request.GET.get('selected_year')
    selected_month = request.GET.get('selected_month')

    if 'selected_branch_id' in request.session and request.session['selected_branch_id']:
        selected_branch_id = request.session['selected_branch_id']
    elif 'selected_all' in request.session:
        select_all = request.session['selected_all']
    else:
        selected_branch_id = request.session.get('default_branch_id')  # If 'selected_branch_id' is empty, default to 'default_branch_id'

    if 'selected_branch_id' in locals() or 'selected_branch_id' in globals():
        try:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.employee_code[:3]
            selected_branch_admin_code = branch.admin_code[:3]
            selected_branch_trainee_code = branch.trainee_code[:3]
            # Use Q objects to combine multiple conditions
            records = PayrollMaathangi.objects.filter(
                Q(salary_month__year=selected_year, salary_month__month=selected_month) &
                (Q(emp_id__startswith=selected_branch_employee_code) |
                 Q(emp_id__startswith=selected_branch_admin_code) |
                 Q(emp_id__startswith=selected_branch_trainee_code))
            ).values(
                'emp_nm',
                'emp_id',
                'salary_month',
                'actual_sal',
                'salary',
                'sts',
            )
        except Branch.DoesNotExist:
            # Handle the case when the branch does not exist
            return JsonResponse({'error': 'Selected branch does not exist'}, status=400)

    elif 'select_all' in locals() or 'select_all' in globals():
        try:
            records = PayrollMaathangi.objects.filter(
                salary_month__year=selected_year,
                salary_month__month=selected_month
            ).values(
                'emp_nm',
                'emp_id',
                'salary_month',
                'actual_sal',
                'salary',
                'sts',
            )
        except PayrollMaathangi.DoesNotExist:
            # Handle the case when records do not exist
            return JsonResponse({'error': 'Records do not exist'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)

    # Convert the queryset to a list for JSON serialization
    records_list = list(records)
    return JsonResponse(records_list, safe=False)


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def salary_approval(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    # Send data to the template
    return render(request, 'salary_approval.html', {'current_user': current_user, 'branches': branches , 'default_branch':default_branch})

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def update_sts(request):
    if request.method == 'POST':
        emp_id = request.POST.get('emp_id')
        selected_status = request.POST.get('status')
        selected_year = request.POST.get('selected_year')
        selected_month = request.POST.get('selected_month')
        # Update the sts field in the PayrollMaathangi model
        try:
            payroll_record = PayrollMaathangi.objects.get(emp_id=emp_id,salary_month__year=selected_year,
        salary_month__month=selected_month)
            payroll_record.sts = selected_status
            payroll_record.save()
            return JsonResponse({'success': True})
        except PayrollMaathangi.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Record not found'})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})



#leave_status
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def leave_status(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    
    # years_range = range(2014, 2050)
    return render(request, 'leave_status.html', {'current_user':current_user , 'branches': branches , 'default_branch':default_branch})


# def leavefetch(request):
#     selected_month = request.GET.get('month', None)
#     selected_year = request.GET.get('year', None)
    
#     if 'selected_branch_id' in request.session:
#         selected_branch_id = request.session['selected_branch_id']
        
#         branch = Branch.objects.get(branch_name=selected_branch_id)
#         selected_branch_employee_code = branch.employee_code[:3]
#         selected_branch_admin_code = branch.admin_code[:3]
#         selected_branch_trainee_code = branch.trainee_code[:3]
        
#         # Rest of the code for branch handling...
#     else:
#         # Corrected indentation and added a return statement
#         leaves_data = list(
#             EmpLeaves.objects.order_by('-id').values(
#                 'id', 'user_id', 'from_dt', 'to_dt', 'tot_days', 'reason', 'lev_typ', 'applay_dt', 'status'
#             )
#         )
#         return JsonResponse(leaves_data, safe=False)

#     # Create a mapping of month names to their numerical values
#     month_mapping = {
#         'January': 1, 'February': 2, 'March': 3, 'April': 4, 'May': 5, 'June': 6,
#         'July': 7, 'August': 8, 'September': 9, 'October': 10, 'November': 11, 'December': 12,
#     }

#     # Get the numerical value of the selected month
#     selected_month_number = month_mapping.get(selected_month)

#     # Assuming 'mnth' and 'yr' are the fields in your EmpLeaves model
#     if selected_month_number is not None and selected_year and selected_branch_id:
#         # Use Q objects to build a complex query
#         leaves_data = list(
#             EmpLeaves.objects.filter(
#                 Q(mnth=selected_month_number, yr=selected_year) &
#                 (Q(user_id__startswith=selected_branch_employee_code) |
#                  Q(user_id__startswith=selected_branch_admin_code) |
#                  Q(user_id__startswith=selected_branch_trainee_code))
#             ).order_by('-id').values(
#                 'id', 'user_id', 'from_dt', 'to_dt', 'tot_days', 'reason', 'lev_typ', 'applay_dt', 'status'
#             )
#         )
#         return JsonResponse(leaves_data, safe=False)
#     else:
#         # Handle the case when the conditions for fetching leaves are not met
#         return JsonResponse({'error': 'Invalid parameters for leave fetching'}, status=400)
    

# def leavefetch(request):
#     selected_month = request.GET.get('month', None)
#     selected_year = request.GET.get('year', None)
    
#     if 'selected_branch_id' in request.session:
#         selected_branch_id = request.session['selected_branch_id']
        
#         if not selected_branch_id:  # Check if selected_branch_id is empty
#             if 'default_branch_id' in request.session:
#                 selected_branch_id = request.session.get('default_branch_id')
#             else:
#                 return JsonResponse({'error': 'Default branch is not set in session'}, status=400)
        
#         branch = Branch.objects.get(branch_name=selected_branch_id)
#         selected_branch_employee_code = branch.employee_code[:3]
#         selected_branch_admin_code = branch.admin_code[:3]
#         selected_branch_trainee_code = branch.trainee_code[:3]
        
#         # Rest of the code for branch handling...
#     else:
#         # Corrected indentation and added a return statement
#         leaves_data = list(
#             EmpLeaves.objects.order_by('-id').values(
#                 'id', 'user_id', 'from_dt', 'to_dt', 'tot_days', 'reason', 'lev_typ', 'applay_dt', 'status'
#             )
#         )
#         return JsonResponse(leaves_data, safe=False)

#     # Create a mapping of month names to their numerical values
#     month_mapping = {
#         'January': 1, 'February': 2, 'March': 3, 'April': 4, 'May': 5, 'June': 6,
#         'July': 7, 'August': 8, 'September': 9, 'October': 10, 'November': 11, 'December': 12,
#     }

#     # Get the numerical value of the selected month
#     selected_month_number = month_mapping.get(selected_month)

#     # Assuming 'mnth' and 'yr' are the fields in your EmpLeaves model
#     if selected_month_number is not None and selected_year and selected_branch_id:
#         # Use Q objects to build a complex query
#         leaves_data = list(
#             EmpLeaves.objects.filter(
#                 Q(mnth=selected_month_number, yr=selected_year) &
#                 (Q(user_id__startswith=selected_branch_employee_code) |
#                  Q(user_id__startswith=selected_branch_admin_code) |
#                  Q(user_id__startswith=selected_branch_trainee_code))
#             ).order_by('-id').values(
#                 'id', 'user_id', 'from_dt', 'to_dt', 'tot_days', 'reason', 'lev_typ', 'applay_dt', 'status'
#             )
#         )
#         return JsonResponse(leaves_data, safe=False)
#     else:
#         # Handle the case when the conditions for fetching leaves are not met
#         return JsonResponse({'error': 'Invalid parameters for leave fetching'}, status=400)


def leavefetch(request):
    selected_month = request.GET.get('month', None)
    selected_year = request.GET.get('year', None)
    
    if 'selected_branch_id' in request.session:
        selected_branch_id = request.session['selected_branch_id']
    else:
        selected_branch_id = request.session.get('default_branch_id', None)
        
        if not selected_branch_id:
            return JsonResponse({'error': 'No branch selected'}, status=400)

    select_all = request.session.get('selected_all', False)

    if selected_branch_id:
        branch = Branch.objects.get(branch_name=selected_branch_id)
        selected_branch_employee_code = branch.employee_code[:3]
        selected_branch_admin_code = branch.admin_code[:3]
        selected_branch_trainee_code = branch.trainee_code[:3]
        
        month_mapping = {
            'January': 1, 'February': 2, 'March': 3, 'April': 4, 'May': 5, 'June': 6,
            'July': 7, 'August': 8, 'September': 9, 'October': 10, 'November': 11, 'December': 12,
        }

        selected_month_number = month_mapping.get(selected_month)

        if selected_month_number is not None and selected_year:
            # Filter leaves data based on selected_all session value
            if select_all:
                leaves_data = list(
                    EmpLeaves.objects.filter(
                        mnth=selected_month_number, yr=selected_year
                    ).order_by('-id').values(
                        'id', 'user_id', 'from_dt', 'to_dt', 'tot_days', 'reason', 'lev_typ', 'applay_dt', 'status'
                    )
                )
            else:
                # Apply additional filters based on branch codes
                leaves_data = list(
                    EmpLeaves.objects.filter(
                        Q(mnth=selected_month_number, yr=selected_year) &
                        (Q(user_id__startswith=selected_branch_employee_code) |
                         Q(user_id__startswith=selected_branch_admin_code) |
                         Q(user_id__startswith=selected_branch_trainee_code))
                    ).order_by('-id').values(
                        'id', 'user_id', 'from_dt', 'to_dt', 'tot_days', 'reason', 'lev_typ', 'applay_dt', 'status'
                    )
                )

            return JsonResponse(leaves_data, safe=False)
        else:
            return JsonResponse({'error': 'Invalid parameters for leave fetching'}, status=400)
    else:
        return JsonResponse({'error': 'No branch selected'}, status=400)




def leavedelete(request, item_id):
    try:
        item = EmpLeaves.objects.get(id=item_id)
        item.delete()
        messages.success(request, "Deleted successfully!!")
        return JsonResponse({'message': 'Deleted successfully'}, status=200)
    except EmpLeaves.DoesNotExist:
        return JsonResponse({'message': 'Item not found'}, status=404)
    except Exception as e:
        return JsonResponse({'message': str(e)}, status=500)

#add_leave
# @cache_control(no_cache=True, must_revalidate=True, no_store=True)    
# def add_leave(request):
#     if 'username' in request.session:
#         current_user = request.session['username']
#         branches = Branch.objects.all()
#     else:
#         # Handle the case when the user is not logged in
#         return redirect('loginpage')  # You can set it to None or any default value
    
#     all_data = RegisterAll.objects.all()
    
#     # Assuming 'all_data' is your list of items to display
#     items_per_page = 5
#     paginator = Paginator(all_data, items_per_page)
#     page_number = request.GET.get('page', 1)
#     data = paginator.get_page(page_number)
#     return render(request, 'add_leave.html', {'current_user': current_user ,'data': data , 'branches': branches})

from django.core.paginator import Paginator

@cache_control(no_cache=True, must_revalidate=True, no_store=True)  
@department_required('SAD')  
def add_leave(request):
    if 'username' in request.session:
        current_user = request.session['username']
        select_all = request.session.get('selected_all', False)
        default_branch = request.session.get('default_branch_id', None)
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    
    if 'selected_branch_id' in request.session:
        selected_branch_id = request.session['selected_branch_id']
    elif default_branch:
        selected_branch_id = default_branch  # If not, default to default_branch
    else:
        select_all = True  # Set select_all to True if no branch is selected

    if select_all:
        # Fetch data for all branches
        all_data = RegisterAll.objects.exclude(depart="SAD").values()
    else:
        try:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.employee_code[:3]
            selected_branch_admin_code = branch.admin_code[:3]
            selected_branch_trainee_code = branch.trainee_code[:3]
            
            print(f"selected_branch_employee_code trainee {selected_branch_employee_code}")
        except Branch.DoesNotExist:
            return HttpResponse(status=404)
        
        # Fetch data based on selected branch
        all_data = RegisterAll.objects.filter(
            Q(user_id__startswith=selected_branch_employee_code) |
            Q(user_id__startswith=selected_branch_admin_code) |
            Q(user_id__startswith=selected_branch_trainee_code)
        ).values()
        
    

    return render(request, 'add_leave.html', {'current_user': current_user, 'data': all_data, 'branches': branches, 'selected_branch_id': selected_branch_id, 'default_branch': default_branch, 'select_all': select_all})


def empployee_leave_fetch(request):
    emp_id = request.GET.get('empId')

    # Assuming EmpLeaves model is defined in your models.py
    emp_leaves_data = list(EmpLeaves.objects.filter(user_id=emp_id).values())

    return JsonResponse({'empLeavesData': emp_leaves_data})


def delete_add_leave_record(request,id):
     data = EmpLeaves.objects.get(id=id)
     data.delete()
     
     return redirect('add_leave')


from datetime import datetime

def leave_insert(request):
    if request.method == 'POST':
        user_id = request.POST['employeid']
        from_dt_str = request.POST['leaveFromDate']
        to_dt = request.POST['leaveToDate']
        tot_days = int(request.POST['totalDays'])  # Convert tot_days to an integer
        reason = request.POST['exampleTextarea']
        lev_typ = request.POST['exampleDropdown']
        applay_dt = request.POST['applicationdate']
        depart = request.POST['department']
        # Convert 'from_dt_str' to a datetime object
        from_dt = datetime.strptime(from_dt_str, '%Y-%m-%d')
        # Extract month and year from 'from_dt'
        current_month = from_dt.month
        current_year = from_dt.year
        # If tot_days is greater than 1, create entries for each day in the range
        if tot_days > 1:
            for i in range(tot_days):
                current_date = from_dt + timedelta(days=i)
                newleave_insert = EmpLeaves(
                    user_id=user_id,
                    from_dt=current_date.strftime('%Y-%m-%d'),
                    to_dt=current_date.strftime('%Y-%m-%d'),
                    tot_days=1,  # Each entry represents one day
                    reason=reason,
                    lev_typ=lev_typ,
                    applay_dt=applay_dt,
                    depart=depart,
                    mnth=current_date.month,
                    yr=current_date.year,
                    status='1'
                )
                newleave_insert.save()
        else:
            # If tot_days is 1, create a single entry
            newleave_insert = EmpLeaves(
                user_id=user_id,
                from_dt=from_dt_str,
                to_dt=to_dt,
                tot_days=tot_days,
                reason=reason,
                lev_typ=lev_typ,
                applay_dt=applay_dt,
                depart=depart,
                mnth=current_month,
                yr=current_year,
                status='1'
            )
            newleave_insert.save()
        messages.success(request, 'Leave entry added successfully')
        return redirect('add_leave')
    # Render your form template for GET requests
    return render(request, 'add_leave.html')


def update_status(request, leave_id):
    try:
        leave = EmpLeaves.objects.get(pk=leave_id)
        new_status = request.GET.get('new_status')
        print(f"new_status{new_status}")
        # Update the status field
        leave.status = new_status
        leave.save()

        return JsonResponse({'success': True})
    except EmpLeaves.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Leave not found'})



# def emp_leaves_data(request):
#     leaves_data =list(EmpLeaves.objects.values())
    
#     return JsonResponse(leaves_data, safe=False)
    
def emp_leaves_data(request):
    
    if 'selected_branch_id' in request.session:
        selected_branch_id = request.session['selected_branch_id']
        
        branch = Branch.objects.get(branch_name=selected_branch_id)
        selected_branch_employee_code = branch.employee_code[:3]
        selected_branch_admin_code = branch.admin_code[:3]
        selected_branch_trainee_code = branch.trainee_code[:3]

        leaves_data = list(EmpLeaves.objects.filter(
            Q(user_id__startswith=selected_branch_employee_code) |
            Q(user_id__startswith=selected_branch_admin_code) |
            Q(user_id__startswith=selected_branch_trainee_code)
        ).values())
    else:
        # Handle the case when 'selected_branch_id' is not in the session
        leaves_data = list(EmpLeaves.objects.values())

    return JsonResponse(leaves_data, safe=False)






#work_from_home_report
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def work_from_home_report(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    
    # Fetching data
    work_from_home_data = WorkFromHome.objects.values_list('emp_id', flat=True)
    details = RegisterAll.objects.exclude(depart='SAD')

    # status_fetch=AddClockin.objects.values('usid','status','branch')
    # print(f"status_fetch {status_fetch}")

    # Check if emp_id from RegisterAll is in WorkFromHome data
    emp_id_with_tick = []
    for detail in details:
        if detail.user_id in work_from_home_data:
            emp_id_with_tick.append(detail.user_id)

    print(f"emp_id_with_tick {emp_id_with_tick}")   
    
         

    return render(request, 'work_from_home_report.html', {
        'current_user': current_user,
        'details': details,
        'emp_id_with_tick': emp_id_with_tick,
        'branches': branches,
        'default_branch': default_branch,
        
    })
@csrf_exempt
def view_tick(request):
    if request.method == 'GET':
        user_id = request.GET.get('user_id')  # Fetch user_id from GET parameters
        if user_id is not None:
            # Fetch status for user_id from the database
            try:
                status_fetch = AddClockin.objects.filter(usid=user_id).values('status').first()
                if status_fetch:
                    return JsonResponse({'status': status_fetch['status']})
                else:
                    return JsonResponse({'status': 'User not found'}, status=404)
                
            except Exception as e:
                return JsonResponse({'status': str(e)}, status=500)
        else:
            return JsonResponse({'status': 'User ID not provided'}, status=400)
    else:
        return JsonResponse({'status': 'Method Not Allowed'}, status=405)

from django.core.serializers import serialize
# @require_GET
# def work_from_home_report_retrieve(request):
#     # Retrieve all WorkFromHome objects from the database
#     data = WorkFromHome.objects.all()
#     print(f"data {data}")

#     # Convert queryset to JSON format
#     data_json = serialize('json', data)

#     # Parse JSON data to Python list of dictionaries
#     records_list = json.loads(data_json)

#     return JsonResponse(records_list, safe=False)

@require_GET
def work_from_home_report_retrieve(request):
    # Retrieve all WorkFromHome objects from the database
    data = WorkFromHome.objects.all().order_by('-id')

    # Serialize the queryset including the 'id' field
    data_json = serialize('json', data, fields=('id', 'emp_id', 'req_dt', 'emp_nm', 'wfh_start_dt', 'wfh_end_dt', 'app_status','monst','moned','tuest','tueed','wedst','weded','thust','thued','frist','fried','satst','sated','sunst','suned','resn','app_status','emp_dept','sup_nm'))
    print(f"data_json {data_json}")

    # Parse JSON data to Python list of dictionaries
    records_list = json.loads(data_json)

    return JsonResponse(records_list, safe=False)


# @require_GET
# def work_from_home_report_retrieve(request):
#     # Retrieve all WorkFromHome objects from the database
#     data = WorkFromHome.objects.all()

#     # Convert queryset to list of dictionaries
#     records_list = []
#     for record in data:
#         record_dict = {
#             'id': record.id,
#             'req_dt': record.req_dt,
#             'emp_nm': record.emp_nm,
#             'emp_id': record.emp_id,
#             'emp_dept': record.emp_dept,
#             'emp_desig': record.emp_desig,
#             'wfh_start_dt': record.wfh_start_dt,
#             'wfh_end_dt': record.wfh_end_dt,
#             'monst': record.monst,
#             'moned': record.moned,
#             'tuest': record.tuest,
#             'tueed': record.tueed,
#             'wedst': record.wedst,
#             'weded': record.weded,
#             'thust': record.thust,
#             'thued': record.thued,
#             'frist': record.frist,
#             'fried': record.fried,
#             'satst': record.satst,
#             'sated': record.sated,
#             'sunst': record.sunst,
#             'suned': record.suned,
#             'resn': record.resn,
#             'sup_nm': record.sup_nm,
#             'app_status': record.app_status,
#             # Add other fields as needed
#         }
#         records_list.append(record_dict)

#     return JsonResponse(records_list, safe=False)



def update_report(request):
    if request.method == 'POST':
        emp_id = request.POST.get('emp_id')
        selected_status = request.POST.get('status')
        pk = request.POST.get('pk')

        # Update the sts field in the WorkFromHome model
        try:
            WorkFromHome.objects.filter(emp_id=emp_id,id=pk).update(app_status=selected_status)
            return JsonResponse({'success': True})
        except WorkFromHome.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Record not found'})

    return JsonResponse({'success': False, 'error': 'Invalid request method'})
#Visitors

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def visiters(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    # Send data to the template
    # data = WorkFromHome.objects.all()
    return render(request, 'visiters.html', {'current_user': current_user, 'branches': branches , 'default_branch':default_branch})



def visiters_report(request):
    # Retrieve all Visiters objects from the database
    data = Visiters.objects.all().order_by('-id')
    # Convert queryset to list of dictionaries including the primary key
    records_list = list(data.values('id', 'user', 'log_in_dt_tm', 'log_out_dt_tm', 'ip', 'log_in_tm','log_out_tm','log_out_dt'))
    print(f'records_list :{records_list}')
    # Return JsonResponse
    return JsonResponse(records_list, safe=False)

# def visiters_report(request):
#     try:
#         visitors_data = Visiters.objects.all().values('user', 'log_in_dt_tm', 'log_out_dt_tm', 'log_in_tm', 'log_out_tm', 'ip')
#         data = list(visitors_data)
#         print(f"data {data}")
#         return JsonResponse(data, safe=False)
#     except Exception as e:
#         return JsonResponse({'error': str(e)}, status=500)



#Excel To Databse
import pandas as pd
from datetime import datetime,time
from django.http import HttpResponseServerError

def convert_time_format(time_str):
    # Convert time strings to the format HH:MM:SS
    try:
        time_obj = datetime.strptime(time_str, "%H.%M.%S")
        return time_obj.strftime("%H:%M:%S")
    except ValueError:
        return None

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')

def excel_to_db(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        return redirect('loginpage')
    if request.method == 'POST' and request.FILES['attendance_file']:
        uploaded_file = request.FILES['attendance_file']
        try:
            df = pd.read_csv(uploaded_file, header=None, skiprows=0)
            print(df)
        except pd.errors.EmptyDataError:
            error_message = "File is empty."
            messages.error(request, error_message)
            return redirect('excel_to_db')
        except pd.errors.ParserError:
            error_message = " Please upload a CSV file."
            messages.error(request, error_message)
            return redirect('excel_to_db')
        if df.empty:
            return HttpResponseServerError("Error: The CSV file is empty or does not contain valid data.")
        data_list = []
        for index, row in df.iterrows():
            if row[14] != 'P':
                continue
            date_str = str(row[0])
            date_in = str(row[7])
            date_out = str(row[8])
            date_id = str(row[1])
            # Skip the row if date_in is empty
            if date_in.lower() == 'nan':
                continue
            if date_out.lower() == 'nan':
                continue
            if date_str.lower() == 'nan':
                continue
            if date_id.lower() == 'nan':
                continue
            date = datetime.strptime(row[0], '%d-%b-%y').date()
            mnth = datetime.strptime(date_str, '%d-%b-%y').strftime('%m')
            yr = datetime.strptime(date_str, '%d-%b-%y').strftime('%Y')
            time_in = row[7]
            time_out = row[8]
            if '.' in time_in:
                time_in = datetime.strptime(time_in, '%H.%M.%S').time().strftime('%H:%M:%S')
            else:
                time_in = datetime.strptime(time_in, '%H:%M:%S').time().strftime('%H:%M:%S')
            if '.' in time_out and "(SE)" in time_out:
                # Handle the case where both '.' and '(SE)' are present
                print("Both '.' and '(SE)' are present")
                time_out = time_out.split("(SE)")[0].strip()
                time_out = datetime.strptime(time_out, '%H.%M.%S').time().strftime('%H:%M:%S')
            elif '.' in time_out:
                time_out = datetime.strptime(time_out, '%H.%M.%S').time().strftime('%H:%M:%S')
            elif "(SE)" in time_out:
                # Handle the case where only '(SE)' is present
                print("Only '(SE)' is present")
                time_out = time_out.split("(SE)")[0].strip()
                time_out = datetime.strptime(time_out, '%H:%M:%S').time().strftime('%H:%M:%S')
            else:
                time_out = datetime.strptime(time_out, '%H:%M:%S').time().strftime('%H:%M:%S')
            print(f'in_time :{time_in}')
            print(f'out_time :{time_out}')
            raw_tot_hr = row[9]
            # Check if the time format is 'H.M' (e.g., '9.27')
            if '.' in raw_tot_hr:
                tot_hr = datetime.strptime(raw_tot_hr, '%H.%M').time().strftime('%H:%M:%S')
            else:
                # Assume the time format is 'H:M' (e.g., '9:27')
                tot_hr = datetime.strptime(raw_tot_hr, '%H:%M').time().strftime('%H:%M:%S')
            user_id = row[1]
            formatted_date = date
            formatted_time_in = time_in
            formatted_time_out = time_out
            clk_in_dt_tm = f"{formatted_date} {formatted_time_in}"
            clk_out_dt_tm = f"{formatted_date} {formatted_time_out}"
            # Check if the record already exists
            if Attendance.objects.filter(user_id=user_id, date=date).exists():
                continue
            # Fetch additional data from RegisterAll
            try:
                register_all = RegisterAll.objects.get(user_id=user_id)
                work_from = register_all.work_frm
                work_to = register_all.work_to
                depart = register_all.depart
                user_id_registerall = register_all.user_id
            except RegisterAll.DoesNotExist:
                work_from = ''
                work_to = ''
                depart = ''
                user_id_registerall = 'ABCDEFHG'
            if row[1] != user_id_registerall:
                continue
            data = {
                'date': date,
                'user_id': user_id,
                'clk_in_tm': time_in,
                'clk_out_tm': time_out,
                'work_frm': work_from,
                'work_to': work_to,
                'depart': depart,
                'tot_hr': tot_hr,
                'mnth': mnth,
                'yr': yr,
                'clk_in': '0',
                'clk_out': '0',
                'clk_in_dt_tm': clk_in_dt_tm,
                'clk_out_dt_tm': clk_out_dt_tm,
                'clkin_ip': '',
                'clkout_ip': '',
                'notes': '',
                'late_resn_status': '0',
            }
            data_list.append(data)
        # Save the extracted data to the database
        Attendance.objects.bulk_create([Attendance(**data) for data in data_list])
        success_message = "Data inserted successfully."
        messages.success(request, success_message)
        return redirect('excel_to_db')
    return render(request, 'excel_to_db.html', {'current_user': current_user, 'branches': branches, 'default_branch': default_branch})

#Salary Calculation
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def salary_calculation(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session.get('default_branch_id')
        branches = Branch.objects.all()
        
        storedMonthNumber = request.GET.get('storedMonthNumber')

        if 'selected_branch_id' in request.session:
            selected_branch_id = request.session['selected_branch_id']
        else:
            selected_branch_id = default_branch
        
        select_all = request.session.get('selected_all', False)
        
        try:
            if select_all:
               data = RegisterAll.objects.exclude(depart='SAD').values()
            else:
                branch = Branch.objects.get(branch_name=selected_branch_id)
                selected_branch_employee_code = branch.employee_code[:3]
                selected_branch_admin_code = branch.admin_code[:3]
                selected_branch_trainee_code = branch.trainee_code[:3]
                data = RegisterAll.objects.filter(
                    Q(user_id__startswith=selected_branch_employee_code) |
                    Q(user_id__startswith=selected_branch_admin_code) |
                    Q(user_id__startswith=selected_branch_trainee_code)
                ).values()
            
            print(f"data {data}")
        except Branch.DoesNotExist:
            return redirect('salary_calculation')  # Redirect if the selected branch does not exist
    else:
        return redirect('loginpage')  # Redirect if the user is not logged in
    
    return render(request, 'salary_calculation.html', {'current_user': current_user, 'data': data, 'branches': branches, 'selected_branch_id': selected_branch_id, 'storedMonthNumber': storedMonthNumber, 'default_branch': default_branch})




# def salary_calculation(request):
#     if 'username' in request.session:
#         current_user = request.session['username']
#         branches = Branch.objects.all()
#         # itemss_list = PayrollMaathangi.objects.values('emp_id', 'salary_month__month')
#         if request.method == 'GET':
#            storedMonthNumber = request.GET.get('storedMonthNumber')
#         # print(f"itemss_list",itemss_list)
#         if 'selected_branch_id' in request.session:
#             selected_branch_id = request.session['selected_branch_id']
#             try:
#                 branch = Branch.objects.get(branch_name=selected_branch_id)
#                 selected_branch_employee_code = branch.employee_code[:3]
#                 selected_branch_admin_code = branch.admin_code[:3]
#                 selected_branch_trainee_code = branch.trainee_code[:3]
#                 data = RegisterAll.objects.filter(
#                     Q(user_id__startswith=selected_branch_employee_code) |
#                     Q(user_id__startswith=selected_branch_admin_code) |
#                     Q(user_id__startswith=selected_branch_trainee_code)
#                 ).values()
#                 print(f"data {data}")
#             except Branch.DoesNotExist:
#                 # Handle the case when the selected branch does not exist
#                 return redirect('salary_calculation')  # You can set it to None or any default value
#         else:
#             # If branch is not selected, display all data
#             data = RegisterAll.objects.exclude(depart="SAD").values()
#             selected_branch_id = None
#     else:
#         # Handle the case when the user is not logged in
#         return redirect('loginpage')  # You can set it to None or any default value
#     return render(request, 'salary_calculation.html', {'current_user': current_user, 'data': data, 'branches': branches, 'selected_branch_id': selected_branch_id  ,'storedMonthNumber': storedMonthNumber,})






#set_holiday
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def set_holiday(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()

    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    # Send data to the template
    # data = RegisterAll.objects.all()
    return render(request, 'set_holiday.html', {'current_user': current_user , 'branches': branches , 'default_branch':default_branch})

@require_POST
# @cache_control(no_cache=True, must_revalidate=True, no_store=True)
def update_holidays(request):
    try:
        data = json.loads(request.body)
        print(data)  # Add this line to print the received data

        # Assuming you have a Holiday model with the specified fields
        for holiday_data in data:
            # Extract data from each holiday_data item and update the database
            month = holiday_data.get('month')
            year = holiday_data.get('year')
            holiday_date = holiday_data.get('holiday_date')
            reason = holiday_data.get('reason')
            branch = holiday_data.get('branch')
            # This is just an example, modify it based on your actual model and database structure
            Holiday.objects.create(month=month, year=year, holiday_date=holiday_date, reason= reason, branch= branch)
            # Holiday.objects.update_or_create(month=month, year=year, holiday_date=holiday_date, defaults={'reason': reason, 'branch': branch})

        return JsonResponse({'message': 'Update successful'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def get_branch_names(request):
    branch_names = Branch.objects.values_list('branch_name', flat=True)
    return JsonResponse({'branch_names': list(branch_names)})
def get_all_holidays(request):
    # Fetch all holiday records
    holidays = Holiday.objects.all()
    # Create a list to store the holiday data
    holiday_data = []
    # Iterate over each holiday record and add it to the list
    for holiday in holidays:
        holiday_data.append({
            'id':holiday.id,
            'reason': holiday.reason,
            'holiday_date': holiday.holiday_date.strftime('%Y-%m-%d'),
            'month': holiday.month,
            'year': holiday.year,
            'branch': holiday.branch,
        })
    # Return the data as JSON
    return JsonResponse({'holidays': holiday_data})
def delete_holiday(request, id):
    data = Holiday.objects.get(id=id)
    data.delete()
    messages.error(request,"Deleted successsfully!!")
    return redirect('add_depart')

def check_date_exists(request):
    selected_date = request.GET.get('date', '')

    # Query the database to check if the date exists
    date_exists = Holiday.objects.filter(holiday_date=selected_date).exists()

    # Return the result as a JSON response
    return JsonResponse({'exists': date_exists})



#Employee leave report
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def emort_fetch(request):
    filter_param = request.GET.get('filter', 'active')  # Default to 'active' if no filter provided
    if filter_param == 'active':
        data = RegisterAll.objects.filter(acti='active').values()
    elif filter_param == 'disactive':
        data = RegisterAll.objects.filter(acti='disactive').values()
    else:
        data = RegisterAll.objects.exclude(depart='SAD').values()
    
    return JsonResponse(list(data), safe=False)

from datetime import datetime
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def employe_leave_report(request):
    if 'username' in request.session:
        current_user = request.session['username']
        
        default_branch = request.session['default_branch_id']

        branches = Branch.objects.all()

    

    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    current_year = datetime.now().year
    years_range = range(current_year, current_year + 10)  # You can adjust the range as needed
    return render(request, 'employe_leave_report.html', {'current_user': current_user, 'years_range': years_range , 'branches': branches,'default_branch':default_branch})

def empreport_fetch(request):
    filter_value = request.GET.get('filter', 'ViewAll')
    default_branch = request.session.get('default_branch_id')
    select_all = request.session.get('selected_all', False)

    if 'selected_branch_id' in request.session:
        selected_branch_id = request.session['selected_branch_id']
    elif default_branch:
        selected_branch_id = default_branch
    else:
        select_all = True

    try:
        branch = Branch.objects.get(branch_name=selected_branch_id)
        selected_branch_employee_code = branch.employee_code[:3]
        print(f"selected_branch_employee_code trainee {selected_branch_employee_code}")
    except Branch.DoesNotExist:
        return HttpResponse(status=404)

    if selected_branch_id and not select_all:
        selected_branch_admin_code = branch.admin_code[:3]
        selected_branch_trainee_code = branch.trainee_code[:3]

        if filter_value == 'Admin':
            data = RegisterAll.objects.filter(depart__contains='ad', user_id__startswith=selected_branch_admin_code).values()
        elif filter_value == 'Active':
            data = RegisterAll.objects.filter(
                Q(acti='active'),
                Q(user_id__startswith=selected_branch_employee_code) |
                Q(user_id__startswith=selected_branch_admin_code) |
                Q(user_id__startswith=selected_branch_trainee_code)
            ).values()
        else:
            data = RegisterAll.objects.filter(
                Q(user_id__startswith=selected_branch_employee_code) |
                Q(user_id__startswith=selected_branch_admin_code) |
                Q(user_id__startswith=selected_branch_trainee_code)
            ).values()
    elif select_all:
        if filter_value == 'Admin':
            data = RegisterAll.objects.filter(depart__contains='ad').values()
        elif filter_value == 'Active':
            data = RegisterAll.objects.filter(
                Q(acti='active')
            ).values()
        else:
            data = RegisterAll.objects.exclude(depart='SAD').values()
    else:
        data = RegisterAll.objects.exclude(depart='SAD').values()

    return JsonResponse(list(data), safe=False)


@csrf_exempt  # Use this decorator if you want to exempt CSRF for this view (make sure it's secure in your production environment)
@require_POST
def update_stss(request):
    emp_id = request.POST.get('emp_id')
    selected_status = request.POST.get('status')
    userId = request.POST.get('userId')
    print(f"emp_id{emp_id}")
    print(f"selected_status{selected_status}")
    # Assuming you have a model named PayrollMaathangi
    try:
        payroll_instance = EmpLeaves.objects.get(from_dt=emp_id,user_id=userId)
        payroll_instance.status = selected_status
        payroll_instance.save()
        response_data = {'success': True}
    except EmpLeaves.DoesNotExist:
        response_data = {'success': False, 'error': 'PayrollMaathangi instance not found'}
    except Exception as e:
        response_data = {'success': False, 'error': str(e)}

    return JsonResponse(response_data)


def empport_fetch(request, user_id):
    selected_year = request.GET.get('selected_year')
    selected_month = request.GET.get('selected_month')
    # Validate selected_year and selected_month
    if not selected_year or not selected_month:
        return JsonResponse({'error': 'Invalid parameters'}, status=400)
    # Modify the query to filter data based on selected month and year
    leaves_data = list(
        EmpLeaves.objects.filter(
            user_id=user_id,
            mnth=selected_month,
            yr=selected_year
        ).values()
    )
    # If no data is found, return an empty list
    if not leaves_data:
        return JsonResponse([], safe=False)
    return JsonResponse(leaves_data, safe=False)



from django.views.decorators.http import require_http_methods
@require_http_methods(["DELETE"])
def delete_delete(request, record_id):
    record = get_object_or_404(EmpLeaves, pk=record_id)
    record.delete()
    return JsonResponse({'message': 'Record deleted successfully'})



#Employee Attendance
def attendance(request):
    if 'username' in request.session:
        current_user = request.session['username']
         # Get the last record for the current user
        last_record = Visiters.objects.filter(user=current_user,).order_by('-log_in_dt_tm')[1:2].first()
        if last_record:
            log_in_tm = last_record.log_in_tm
            log_out_tm = last_record.log_out_tm
            log_dt = last_record.log_dt
            log_out_dt = last_record.log_out_dt
            # Add any additional fields you want to retrieve
            print(f'log_in_tm :{log_in_tm}')
            print(f'log_out_tm :{log_out_tm}')
            print(f'log_dt :{log_dt}')
            print(f'log_out_dt :{log_out_dt}')
            return render(request, 'empattendance.html', {
                'current_user': current_user,
                'log_in_tm': log_in_tm,
                'log_out_tm': log_out_tm,
                'log_dt': log_dt,
                'log_out_dt': log_out_dt,
            })
        else:
            return render(request, 'empattendance.html')
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value

from django.core.exceptions import ObjectDoesNotExist
@csrf_exempt
def save_notes(request):
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        dt = request.POST.get('dt')
        note = request.POST.get('note')

        try:
            # Check if an entry with the given user_id and dt exists
            existing_note = AttnNotes.objects.get(user_id=user_id, dt=dt)
            # Update the existing note
            existing_note.note = note
            existing_note.save()
        except ObjectDoesNotExist:
            # If no entry exists, create a new one
            AttnNotes.objects.create(user_id=user_id, note=note, dt=dt)

        return JsonResponse({'status': 'success'})
    else:
        return JsonResponse({'status': 'error'})
    


def retrieve_notes(request):
    if request.method == 'GET':
        user_id = request.GET.get('user_id')
        dt = request.GET.get('dt')
        print(f"dt {dt}")
        # Retrieve notes for the user_id and dt
        try:
            notes_obj = AttnNotes.objects.filter(user_id=user_id, dt=dt).first()
            notes = notes_obj.note
            print(f"notes_obj {notes_obj}")
            return JsonResponse({'status': 'success', 'note': notes})
        except AttnNotes.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Notes not found'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'})    


#profile employee
from django.utils import timezone
from datetime import datetime
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
# def profile(request):
#     if 'username' in request.session:
#         current_user = request.session['username']
#         try:
#             user_profile = RegisterAll.objects.filter(user_id=current_user).first()
#             user_record = Visiters.objects.filter(user=current_user).order_by('-id')
#             if len(user_record) >= 2:
#                 second_record = user_record[1]
#             else:
#                 second_record = None

#             print(f"user_record {user_record}")
#             return render(request, 'profile.html', {'current_user': current_user, 'user_profile': user_profile, 'user_record': second_record})
#         except RegisterAll.DoesNotExist:
#             # Handle the case when the user profile does not exist
#             return HttpResponse("User profile not found.")
#         except Visiters.DoesNotExist:
#             user_record = None
#             return render(request, 'profile.html', {'current_user': current_user, 'user_profile': user_profile, 'user_record': user_record})
#     else:
#         # Handle the case when the user is not logged in
#         return redirect('loginpage')

def profile(request):
    if 'username' in request.session and request.session['username']:
        current_user = request.session['username']
        user_profile = RegisterAll.objects.get(user_id=current_user)
        if user_profile.team_ld == '0':
            pic_url = '/static/upload/'
        elif user_profile.team_ld == '1':
            pic_url = 'http://mindtek.seasense.in/mindtek/admin_login/Registration/uploads/'
        else:
            pic_url = "kjnnjn"  # Default URL for the image
            
        print(f"pic_url {pic_url}")  # Debugging
        print(f"user_profile.team_ld {user_profile.team_ld}")  # Debugging
        last_record = Visiters.objects.filter(user=current_user,).order_by('-log_in_dt_tm')[1:2].first()
        if last_record:
            log_in_tm = last_record.log_in_tm
            log_out_tm = last_record.log_out_tm
            log_dt = last_record.log_dt
            log_out_dt = last_record.log_out_dt
            # Determine the URL format based on team_id
            return render(request, 'profile.html', {'current_user': current_user, 'user_profile': user_profile,  'pic_url': pic_url,'log_in_tm': log_in_tm,
            'log_out_tm': log_out_tm,
            'log_dt': log_dt,
            'log_out_dt': log_out_dt,})
        else:
            return render(request, 'profile.html', {'current_user': current_user, 'user_profile': user_profile,  'pic_url': pic_url})
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')



    # views.py
# @csrf_exempt
# def date_profile(request, user_profile=None):
#     if user_profile is None:
#         # Handle the case where user_profile is not provided
#         return JsonResponse({'error': 'User profile ID not provided'}, status=400)
#     try:
#         admin = RegisterAll.objects.get(id=user_profile, depart='emp')
#         print(f"admin : {admin}")
#         return JsonResponse({'success': 'Profile updated successfully'})
#     except RegisterAll.DoesNotExist:
#         return JsonResponse({'error': 'Admin not found'}, status=404)
    
@csrf_exempt
def update_user_details(request):
    if request.method == 'POST':
        try:
            # Get data from the POST request
            user_id=request.POST.get('userId')
            contact = request.POST.get('contact')
            address = request.POST.get('address')
            email = request.POST.get('email')
            bank = request.POST.get('bank')
            accno = request.POST.get('accno')
            ifsc = request.POST.get('ifsc')
            user_profile = RegisterAll.objects.get(user_id=user_id)
            # Update the user profile
            user_profile.mob = contact
            user_profile.addr = address
            user_profile.email = email
            user_profile.bank = bank
            user_profile.acc_no = accno
            user_profile.ifsc = ifsc
            # Save changes to the database
            user_profile.save()
            return JsonResponse({'success': True})
        except RegisterAll.DoesNotExist:
            return JsonResponse({'error': 'User profile not found.'})
        except Exception as e:
            return JsonResponse({'error': str(e)})
    return JsonResponse({'error': 'Invalid request method'})
@csrf_exempt
def date_profile(request, user_profile=None):
    if request.method == 'GET':
        # Retrieve the user profile from the database
        user_profile = get_object_or_404(RegisterAll, id=user_profile, depart='emp')
        # Render the form with the user profile data
        return render(request, 'profile.html', {'user_profile': user_profile})




#Apply leave report

from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def apply_leave(request):
    if 'username' in request.session:
        current_user = request.session['username']
        employee_id = current_user
        user_info = RegisterAll.objects.filter(user_id=current_user).first()
        if user_info:
            employee_depart = user_info.depart
            is_admin = employee_depart == 'ad'  # Check if the user is an admin
        else:
            is_admin = False  # Default to False if user_info is not found
    else:
        return redirect('loginpage')
    # Retrieve all leave entries for the current employee
    all_leave_entries = EmpLeaves.objects.filter(user_id=employee_id)
    # Pagination logic
    paginator = Paginator(all_leave_entries, 5)  # Number of items per page
    page_number = request.GET.get('page')
    try:
        data = paginator.page(page_number)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        data = paginator.page(1)
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        data = paginator.page(paginator.num_pages)
    # Pass the paginated leave entries to the template context
    last_record = Visiters.objects.filter(user=current_user).order_by('-log_in_dt_tm').first()
    if last_record:
        log_in_tm = last_record.log_in_tm
        log_out_tm = last_record.log_out_tm
        log_dt = last_record.log_dt
        log_out_dt = last_record.log_out_dt
    else:
        log_in_tm = None
        log_out_tm = None
        log_dt = None
        log_out_dt = None
    context = {
        'current_user': current_user,
        'employee_name': user_info.nm if user_info else "",  # Ensure user_info exists before accessing its attributes
        'employee_id': employee_id,
        'employee_depart': employee_depart,
        'all_leave_entries': data,
        'is_admin': is_admin,  # Pass the flag indicating admin status to the template
        'log_in_tm': log_in_tm,
        'log_out_tm': log_out_tm,
        'log_dt': log_dt,
        'log_out_dt': log_out_dt
    }
    return render(request, 'apply_leave.html', context)



from datetime import timedelta
def submit_leave(request):
    if request.method == 'POST':
        # Get data from the submitted form
        application_date = request.POST.get('applicationDate')
        employee_id = request.POST.get('employee_id')
        leave_type = request.POST.get('leaveType')
        reason = request.POST.get('reason')
        leave_from_date = request.POST.get('leaveFromDate')
        leave_to_date = request.POST.get('leaveToDate')
        total_days = int(request.POST.get('totalDays', 0))  # Convert total_days to an integer
        status = request.GET.get('status', 0)
        depart = request.GET.get('depart', 'emp')
        # Convert the application_date to a datetime object
        application_datetime = datetime.strptime(application_date, '%Y-%m-%d')
        # Extract month and year from the datetime object
        application_month = application_datetime.month
        application_year = application_datetime.year
        # If total_days is greater than 1, create entries for each day in the range
        if total_days > 1:
            for i in range(total_days):
                current_date = datetime.strptime(leave_from_date, '%Y-%m-%d') + timedelta(days=i)
                leave_entry = EmpLeaves(
                    applay_dt=application_date,
                    user_id=employee_id,
                    lev_typ=leave_type,
                    reason=reason,
                    from_dt=current_date.strftime('%Y-%m-%d'),
                    to_dt=current_date.strftime('%Y-%m-%d'),
                    tot_days=1,  # Each entry represents one day
                    mnth=current_date.month,
                    yr=current_date.year,
                    status=status,
                    depart=depart
                )
                leave_entry.save()
        else:
            # If total_days is 1, create a single entry
            leave_entry = EmpLeaves(
                applay_dt=application_date,
                user_id=employee_id,
                lev_typ=leave_type,
                reason=reason,
                from_dt=leave_from_date,
                to_dt=leave_to_date,
                tot_days=total_days,
                mnth=application_month,
                yr=application_year,
                status=status,
                depart=depart
            )
            leave_entry.save()
        # Redirect after successful submission
        return redirect('apply_leave')  # Replace 'apply_leave' with the actual URL to redirect
    return render(request, 'apply_leave.html')  # Render the form again if the request method is not POST

def delete_leave(request,id):
     data = EmpLeaves.objects.get(id=id)
     data.delete()
     
     return redirect('apply_leave')




#emp attendance 
#salary status
@require_GET
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def salary_status_fetch(request):
    # Get the selected year and month from the request
    selected_year = request.GET.get('selected_year')
    emp_id = request.GET.get('emp_id')
    # selected_month = request.GET.get('selected_month')

    # Assuming PayrollMaathangi has fields like 'emp_nm', 'emp_id', 'salary_month', etc.
    # Update the field names accordingly in the values() method
    records = PayrollMaathangi.objects.filter(
        salary_month__year=selected_year,
        emp_id=emp_id,
        # salary_month__month=selected_month
    ).values(
        # 'emp_nm',
        # 'emp_id',
        'salary_month',
        'actual_sal',
        'salary',
        'sts',
    )

    # Convert the queryset to a list for JSON serialization
    records_list = list(records)

    return JsonResponse(records_list, safe=False)

@require_GET
def employee_detail_fetch(request):
    emp_id = request.GET.get('emp_id')
    # Fetch data from RegisterAll based on emp_id
    employee_data = RegisterAll.objects.filter(user_id=emp_id).values(
        'depart',
        'nm',
        'user_id',
        'mnth',
        'yr',
        'dsig',
        'locca',
        'bank',
        'acc_no',
        'doj',
        'pf_cd',
    )
    # Convert the querysets to lists for JSON serialization
    employee_data_list = list(employee_data)
    # Combine both sets of data into a single dictionary
    response_data = {
        'employee_data': employee_data_list,
    }
    return JsonResponse(response_data, safe=False)


@require_GET
def employee_salary_record_fetch(request):
    selected_year = request.GET.get('year')
    emp_id = request.GET.get('emp_id')
    selected_month = request.GET.get('month')
    # Fetch data from RegisterAll based on emp_id
    employee_salary_record = PayrollMaathangi.objects.filter(
        salary_month__year=selected_year,
        emp_id=emp_id,
        salary_month__month=selected_month
    ).values(
    'id',
    'emp_id',
    'emp_nm',
    'desig',
    'doj',
    'locc',
    'pf_amt',
    'pf_num',
    'actual_sal',
    'punch',
    'punch_hlf',
    'cl',
    'cl_hlf',
    'od',
    'od_hlf',
    'holiday',
    'missed_clkin',
    'lop',
    'lop_hlf',
    'missed_clkin_hlf',
    'early_clkout',
    'mng_late',
    'earlyby',
    'tot_late',
    'tot_late_deduct_days',
    'tot_month_days',
    'min_attnd_need',
    'sal_elig_days',
    'process_dt',
    'salary_dt',
    'adv_deduct',
    'arr_deduct',
    'sd_deduct',
    'days_extra_deduct',
    'bonus_earn',
    'prv_arr_earn',
    'sts',
    'salary_month',
    'salary',
    'insu_amt',
    'esi_amt',
    )
    # Convert the querysets to lists for JSON serialization
    employee_salary_record_list = list(employee_salary_record)
    # Combine both sets of data into a single dictionary
    response_data = {
        'employee_salary_record': employee_salary_record_list,
    }
    return JsonResponse(response_data, safe=False)



@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def salary_status(request):
    if 'username' in request.session:
        current_user = request.session['username']
        last_record = Visiters.objects.filter(user=current_user,).order_by('-log_in_dt_tm')[1:2].first()
        if last_record:
            log_in_tm = last_record.log_in_tm
            log_out_tm = last_record.log_out_tm
            log_dt = last_record.log_dt
            log_out_dt = last_record.log_out_dt
            return render(request, 'salary_status.html', {'current_user': current_user ,'log_in_tm': log_in_tm,
        'log_out_tm': log_out_tm,
        'log_dt': log_dt,
        'log_out_dt': log_out_dt})
        else:
            return render(request, 'salary_status.html', {'current_user': current_user})
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    # Send data to the template


# def trainee_userid(request):
#     depart = request.GET.get("depart", 'trainee')

#     if 'selected_branch_id' in request.session:
#         selected_branch_id = request.session['selected_branch_id']
#         branch = Branch.objects.get(branch_name=selected_branch_id)
#         selected_branch_trainee_code = branch.trainee_code[:3]

#         data = RegisterAll.objects.filter(
#             depart=depart,
#             user_id__startswith=selected_branch_trainee_code  # Use filter directly here
#         ).values_list('user_id', flat=True)  # Use values_list to get a flat list of 'user_id'

#         data_list = list(data)
#         return JsonResponse(data_list, safe=False)
#     else:
#         return JsonResponse({'error': 'Invalid request'})


def trainee_userid(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session.get('default_branch_id')
        branches = Branch.objects.all()
        
        selected_branch_id = request.session.get('selected_branch_id', default_branch)

        # Check if 'selected_all' is set in the session
        selected_all = request.session.get('selected_all', False)
        
        depart = request.GET.get("depart", 'trainee')
        # Initialize data_list variable
        data_list = []
        
        try:
            if selected_all:
                data = RegisterAll.objects.filter(
            depart=depart,
            
        ).values_list('user_id', flat=True) 
            else:
                # If selected_branch_id is not present or invalid, return error response
                if not selected_branch_id:
                    return HttpResponse(status=404)

                branch = Branch.objects.get(branch_name=selected_branch_id)
                selected_branch_employee_code = branch.employee_code[:3]
                selected_branch_admin_code = branch.admin_code[:3]
                selected_branch_trainee_code = branch.trainee_code[:3]

                # Filter data based on branch and selected year/month
                data = RegisterAll.objects.filter(
                    Q(user_id__startswith=selected_branch_employee_code) |
                    Q(user_id__startswith=selected_branch_admin_code) |
                    Q(user_id__startswith=selected_branch_trainee_code),
                    depart=depart
                ).values_list('user_id', flat=True) 

            # Convert the QuerySet to a list to be sent as JSON
            data_list = list(data)

        except Branch.DoesNotExist:
            # Handle the case when the selected branch does not exist
            return redirect('errorpage')

        return JsonResponse(data_list, safe=False)
    else:
        # Handle the case when the user is not logged in
        return HttpResponse(status=401)

    

def fetch_trainee_details(request, user_id):
    trainee = get_object_or_404(RegisterAll, user_id=user_id)

    # Assuming you want to return multiple details
    trainee_details = {
        'user_id': trainee.user_id,
        'nm': trainee.nm,
        'mob': trainee.mob,
        'addr': trainee.addr,
        'em_depart': trainee.em_depart,
        'em_depart_hed': trainee.em_depart_hed,
        'email': trainee.email,
        'permi' : trainee.permi,
        'dsig' : trainee.dsig,
        'work_frm' : trainee.work_frm,
        'work_to' : trainee.work_to,
        'sala' : trainee.sala,
        'doj' : trainee.doj,
        'pf_cd' : trainee.pf_cd,
        'locca' : trainee.locca,
        'bank' : trainee.bank,
        'acc_no' : trainee.acc_no,
        'ifsc' : trainee.ifsc,
        'dob' : trainee.dob,
        'fath_nm' : trainee.fath_nm,
        'hm_mob' : trainee.hm_mob,
        'blood' : trainee.blood,

        'other_deduct' : trainee.other_deduct,
        'pf_amt' : trainee.pf_amt,
        'sd_amt' : trainee.sd_amt,
        'em_depart_tl' : trainee.em_depart_tl,
        'offc_mob' : trainee.offc_mob,
        'no_of_cl' : trainee.no_of_cl,
        'pic' : trainee.pic,       

    }

    return JsonResponse(trainee_details)


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def permission_report1(request):
    if 'username' in request.session:
        current_user = request.session['username']
        
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request, 'permission_report.html', {'current_user': current_user , 'branches': branches, 'default_branch':default_branch})


# def permission_report_fetch(request):
#     # Get the selected year and month from the request
#     selected_year = request.GET.get('selected_year')
#     selected_month = request.GET.get('selected_month')
#     user_id = request.GET.get('user_id')
#     print(f"hjbjvg {user_id}")
#     if 'selected_branch_id' in request.session:
#         selected_branch_id = request.session['selected_branch_id']
#         branch = Branch.objects.get(branch_name=selected_branch_id)
#         selected_branch_employee_code = branch.employee_code[:3]
#         selected_branch_admin_code = branch.admin_code[:3]
#         selected_branch_trainee_code = branch.trainee_code[:3]
#         # Fetch data for the selected branch
#         data = list(PermissionAdd.objects.filter(
#             Q(user_id__startswith=selected_branch_employee_code) |
#             Q(user_id__startswith=selected_branch_admin_code) |
#             Q(user_id__startswith=selected_branch_trainee_code),
#             user_id=user_id,
#             permi_dt__year=selected_year,
#             permi_dt__month=selected_month
#         ).values(
#             'permi_hr',
#             'permi_frm',
#             'permi_dt',
#             'resn',
#             'permi_tm_start_am',
#             'permi_tm_end_am',
#             'id',
#             'user_id'
#         ))
#     else:
#         # No branch selected, fetch data without branch filtering
#         data = list(PermissionAdd.objects.filter(
#             permi_dt__year=selected_year,
#             permi_dt__month=selected_month
#         ).values(
#             'permi_hr',
#             'permi_frm',
#             'permi_dt',
#             'resn',
#             'permi_tm_start_am',
#             'permi_tm_end_am',
#             'id',
#             'user_id'
#         ))
#     # Convert queryset to JSON format
#     print(f"records_list{data}")
#     return JsonResponse(data, safe=False)


def permission_report_fetch(request):
    # Get the selected year and month from the request
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session.get('default_branch_id')
        branches = Branch.objects.all()
        
        selected_branch_id = request.session.get('selected_branch_id', default_branch)

        # Check if 'selected_all' is set in the session
        selected_all = request.session.get('selected_all', False)
        
        selected_year = request.GET.get('selected_year')
        selected_month = request.GET.get('selected_month')
        user_id = request.GET.get('user_id')
        # Initialize data_list variable
        # data_list = []
        
        try:
            if selected_all:
                # Fetch details for all branches
                data = list(PermissionAdd.objects.filter(
                    permi_dt__year=selected_year,
                    permi_dt__month=selected_month
                ).values(
                    'permi_hr',
                    'permi_frm',
                    'permi_dt',
                    'resn',
                    'permi_tm_start_am',
                    'permi_tm_end_am',
                    'id',
                    'user_id'
                ))
            else:
                # If selected_branch_id is not present or invalid, return error response
                if not selected_branch_id:
                    return HttpResponse(status=404)

                branch = Branch.objects.get(branch_name=selected_branch_id)
                selected_branch_employee_code = branch.employee_code[:3]
                selected_branch_admin_code = branch.admin_code[:3]
                selected_branch_trainee_code = branch.trainee_code[:3]

                # Filter data based on branch and selected year/month
                data = list(PermissionAdd.objects.filter(
                    Q(user_id__startswith=selected_branch_employee_code) |
                    Q(user_id__startswith=selected_branch_admin_code) |
                    Q(user_id__startswith=selected_branch_trainee_code),
                    user_id=user_id,
                    permi_dt__year=selected_year,
                    permi_dt__month=selected_month
                ).values(
                    'permi_hr',
                    'permi_frm',
                    'permi_dt',
                    'resn',
                    'permi_tm_start_am',
                    'permi_tm_end_am',
                    'id',
                    'user_id'
                ))
            # Convert the QuerySet to a list to be sent as JSON
            

        except Branch.DoesNotExist:
            # Handle the case when the selected branch does not exist
            return redirect('errorpage')

        return JsonResponse(data, safe=False)
    else:
        # Handle the case when the user is not logged in
        return HttpResponse(status=401)





#salary calculation

def fetch_salary_att_data(request):
    if request.method == 'GET':
        user_id = request.GET.get('userId')
        selected_month = request.GET.get('month')
        selected_year = request.GET.get('year')

        try:
            # Assuming YourModel has fields like additionalData1 and additionalData2
            user_data = Attendance.objects.filter(user_id=user_id, mnth=selected_month, yr=selected_year).values()

            # If you want to convert the QuerySet to a list of dictionaries
            user_data_list = list(user_data)

            response_data = {
                'count': len(user_data_list),  # Change this line if count means something else
                'data': user_data_list,  # You can change the key 'data' based on your needs
                # Add more fields as needed
            }
            print(f"response_data oooo {response_data}")

            return JsonResponse(response_data)

        except Exception as e:
            return JsonResponse({'error': f'Error: {e}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

from django.db.models import Sum

def fetch_salary_leave_data(request):
    if request.method == 'GET':
        user_id = request.GET.get('userId')
        selected_month = request.GET.get('month')
        selected_year = request.GET.get('year')

        try:
            # Assuming YourModel has fields like additionalData1 and additionalData2
            user_data = EmpLeaves.objects.filter(user_id=user_id, mnth=selected_month, yr=selected_year, lev_typ="LOP")
            
            # Calculate total days for "LOP" entries
            total_lop_days = user_data.aggregate(total_lop_days=Sum('tot_days'))['total_lop_days'] or 0

            # If you want to convert the QuerySet to a list of dictionaries
            user_data_list = list(user_data.values())

            response_data = {
                'count': len(user_data_list),
                'total_lop_days': total_lop_days,  # Add total days for "LOP" entries
                'data': user_data_list,
                # Add more fields as needed
            }
            print(f"response_data lop {response_data}")
            return JsonResponse(response_data)

        except Exception as e:
            return JsonResponse({'error': f'Error: {e}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

def fetch_salary_cl_data(request):
    if request.method == 'GET':
        user_id = request.GET.get('userId')
        selected_month = request.GET.get('month')
        selected_year = request.GET.get('year')

        try:
            # Assuming YourModel has fields like additionalData1 and additionalData2
            user_data = EmpLeaves.objects.filter(user_id=user_id, mnth=selected_month, yr=selected_year,lev_typ="CL").values()

            total_cl_days = user_data.aggregate(total_lop_days=Sum('tot_days'))['total_lop_days'] or 0

            # If you want to convert the QuerySet to a list of dictionaries
            user_data_list = list(user_data)

            response_data = {
                'count': len(user_data_list),  # Change this line if count means something else
                'total_cl_days': total_cl_days,
                'data': user_data_list,  # You can change the key 'data' based on your needs
                # Add more fields as needed
            }
            

            return JsonResponse(response_data)

        except Exception as e:
            return JsonResponse({'error': f'Error: {e}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

def fetch_salary_od_data(request):
    if request.method == 'GET':
        user_id = request.GET.get('userId')
        selected_month = request.GET.get('month')
        selected_year = request.GET.get('year')

        try:
            # Assuming YourModel has fields like additionalData1 and additionalData2
            user_data = EmpLeaves.objects.filter(user_id=user_id, mnth=selected_month, yr=selected_year,lev_typ="OD").values()

            total_od_days = user_data.aggregate(total_lop_days=Sum('tot_days'))['total_lop_days'] or 0

            # If you want to convert the QuerySet to a list of dictionaries
            user_data_list = list(user_data)

            response_data = {
                'count': len(user_data_list),  # Change this line if count means something else
                'total_od_days': total_od_days,
                'data': user_data_list,  # You can change the key 'data' based on your needs
                # Add more fields as needed
            }
            print(f"response_data od {response_data}")
            

            return JsonResponse(response_data)

        except Exception as e:
            return JsonResponse({'error': f'Error: {e}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


def fetch_salary_holiday_data(request):
    if request.method == 'GET':
        
        selected_month = request.GET.get('month')
        selected_year = request.GET.get('year')

        try:
            # Assuming YourModel has a 'holiday_date' field
            user_data = Holiday.objects.filter(
                Q(holiday_date__month=selected_month) &
                Q(holiday_date__year=selected_year)
            ).values()

            # If you want to convert the QuerySet to a list of dictionaries
            user_data_list = list(user_data)

            response_data = {
                'count': len(user_data_list),
                'data': user_data_list,
                # Add more fields as needed
            }
            
            return JsonResponse(response_data)

        except Exception as e:
            return JsonResponse({'error': f'Error: {e}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


def fetch_salary_halfod_data(request):
    if request.method == 'GET':
        user_id = request.GET.get('userId')
        selected_month = request.GET.get('month')
        selected_year = request.GET.get('year')

        try:
            # Assuming YourModel has fields like additionalData1 and additionalData2
            user_data = EmpLeaves.objects.filter(user_id=user_id, mnth=selected_month, yr=selected_year,lev_typ="HALF DAY-OD").values()

            # total_halfod_days = user_data.aggregate(total_lop_days=Sum('tot_days'))['total_lop_days'] or 0
            total_halfod_days = user_data.annotate(half_day=F('tot_days') - 0.5).aggregate(total_halfod_days=Sum('half_day'))['total_halfod_days'] or 0

            # If you want to convert the QuerySet to a list of dictionaries
            user_data_list = list(user_data)

            response_data = {
                'count': len(user_data_list),  # Change this line if count means something else
                'total_halfod_days': total_halfod_days,
                'data': user_data_list,  # You can change the key 'data' based on your needs
                # Add more fields as needed
            }
            

            return JsonResponse(response_data)

        except Exception as e:
            return JsonResponse({'error': f'Error: {e}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


def fetch_salary_halfcl_data(request):
    if request.method == 'GET':
        user_id = request.GET.get('userId')
        selected_month = request.GET.get('month')
        selected_year = request.GET.get('year')

        try:
            # Assuming YourModel has fields like additionalData1 and additionalData2
            user_data = EmpLeaves.objects.filter(user_id=user_id, mnth=selected_month, yr=selected_year,lev_typ="HALF DAY-CL").values()

            # total_halfcl_days = user_data.aggregate(total_lop_days=Sum('tot_days'))['total_lop_days'] or 0
            total_halfcl_days = user_data.annotate(half_day=F('tot_days') - 0.5).aggregate(total_halfcl_days=Sum('half_day'))['total_halfcl_days'] or 0
            # If you want to convert the QuerySet to a list of dictionaries
            user_data_list = list(user_data)

            response_data = {
                'count': len(user_data_list),  # Change this line if count means something else
                'total_halfcl_days': total_halfcl_days,
                'data': user_data_list,  # You can change the key 'data' based on your needs
                # Add more fields as needed
            }
            

            return JsonResponse(response_data)

        except Exception as e:
            return JsonResponse({'error': f'Error: {e}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


from django.db.models import Sum, F

def fetch_salary_halflop_data(request):
    if request.method == 'GET':
        user_id = request.GET.get('userId')
        selected_month = request.GET.get('month')
        selected_year = request.GET.get('year')

        try:
            # Assuming YourModel has fields like additionalData1 and additionalData2
            user_data = EmpLeaves.objects.filter(user_id=user_id, mnth=selected_month, yr=selected_year,lev_typ="HALF DAY-LOP")
            
            # Aggregate the total halflop days, starting from 0.5 for each record
            total_halflop_days = user_data.annotate(half_day=F('tot_days') - 0.5).aggregate(total_halflop_days=Sum('half_day'))['total_halflop_days'] or 0

            # If you want to convert the QuerySet to a list of dictionaries
            user_data_list = list(user_data.values())

            response_data = {
                'count': len(user_data_list),  # Change this line if count means something else
                'total_halflop_days': total_halflop_days,
                'data': user_data_list,  # You can change the key 'data' based on your needs
                # Add more fields as needed
            }
            
            return JsonResponse(response_data)

        except Exception as e:
            return JsonResponse({'error': f'Error: {e}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)






def generate_salary(request):
    if request.method == 'POST':
        try:
            punched_value = request.POST.get('punched')
            doj = request.POST.get('doj')
            name = request.POST.get('name')
            empId = request.POST.get('empId')
            design = request.POST.get('design')
            locca = request.POST.get('locca')
            pf_num = request.POST.get('pf_num')
            salary = request.POST.get('salary')
            halfpunchedValue = request.POST.get('halfpunchedValue')
            halfdayclValue = request.POST.get('halfdayclValue')
            clValue = request.POST.get('clValue')
            odValue = request.POST.get('odValue')
            halfdayod = request.POST.get('halfdayod')
            halfmissedValue = request.POST.get('halfmissedValue')
            lopValue = request.POST.get('lopValue')
            halfdaylopValue = request.POST.get('halfdaylopValue')
            earlycount = request.POST.get('earlycount')
            mrng_late = request.POST.get('mrng_late')
            earlyByValue = request.POST.get('earlyByValue')
            totalLateValue = request.POST.get('totalLateValue')
            retrievedDeductionElementValue = request.POST.get('retrievedDeductionElementValue')
            totalDaysFromSession = request.POST.get('totalDaysFromSession')
            retrievedMinAttendance = request.POST.get('retrievedMinAttendance')
            retrievedTotalEarning = request.POST.get('retrievedTotalEarning')
            missedClockInTotalValue = request.POST.get('missedClockInTotalValue')
            pf_amt = request.POST.get('pf_amt')
            if pf_amt:
                # If advAmountValue is not empty, convert it to the appropriate type
                pf_amt = float(pf_amt)  # Assuming it's a numeric value
            else:
                # If advAmountValue is empty, assign the default value of zero
                pf_amt = 0
            holidayValue = request.POST.get('holidayValue')
            process_dt = request.POST.get('process_dt')
            salary_dt = request.POST.get('process_dt')
            salary_month = request.POST.get('process_dt')
            advAmountValue = request.POST.get('advAmountValue')
            if advAmountValue:
                # If advAmountValue is not empty, convert it to the appropriate type
                advAmountValue = float(advAmountValue)  # Assuming it's a numeric value
            else:
                # If advAmountValue is empty, assign the default value of zero
                advAmountValue = 0
            print(f"Punched value: {punched_value}")
            arrearAmountValue = request.POST.get('arrearAmountValue')
            if arrearAmountValue:
                # If advAmountValue is not empty, convert it to the appropriate type
                arrearAmountValue = float(arrearAmountValue)  # Assuming it's a numeric value
            else:
                # If advAmountValue is empty, assign the default value of zero
                arrearAmountValue = 0
            print(f"Punched value: {punched_value}")
            sd_amt = request.POST.get('sd_amt')
            if sd_amt:
                # If advAmountValue is not empty, convert it to the appropriate type
                sd_amt = float(sd_amt)  # Assuming it's a numeric value
            else:
                # If advAmountValue is empty, assign the default value of zero
                sd_amt = 0
            retrievedTotalEarning = request.POST.get('retrievedTotalEarning')
            bonus_earn = request.POST.get('bonus_earn',0)
            # AmountValue = request.POST.get('AmountValue')
            arrearValue = request.POST.get('arrearValue')
            if arrearValue:
                # If advAmountValue is not empty, convert it to the appropriate type
                arrearValue = float(arrearValue)  # Assuming it's a numeric value
            else:
                # If advAmountValue is empty, assign the default value of zero
                arrearValue = 0
            print(f"Punched value: {punched_value}")
            sts = request.POST.get('sts',0)
            net_salary = request.POST.get('net_salary')
            insu_amt = request.POST.get('insu_amt')
            esi_amt = request.POST.get('esi_amt')
            # Perform calculations or operations here based on punched_value
            # Save the punched value into the PayrolMathangi model
            generate_salary = PayrollMaathangi(punch=punched_value,doj=doj,emp_nm=name,emp_id=empId,desig=design,locc=locca,pf_num=pf_num,actual_sal=salary,punch_hlf=halfpunchedValue ,cl_hlf=halfdayclValue,cl=clValue,od=odValue,od_hlf=halfdayod,missed_clkin_hlf=halfmissedValue,lop=lopValue,lop_hlf=halfdaylopValue,early_clkout=earlycount,mng_late=mrng_late,earlyby=earlyByValue,tot_late=totalLateValue,tot_late_deduct_days=retrievedDeductionElementValue,tot_month_days=totalDaysFromSession,min_attnd_need=retrievedMinAttendance,sal_elig_days=retrievedTotalEarning,missed_clkin=missedClockInTotalValue,pf_amt=pf_amt,holiday=holidayValue,process_dt=process_dt,salary_dt=salary_dt,adv_deduct=advAmountValue,arr_deduct=arrearAmountValue,sd_deduct=sd_amt,days_extra_deduct=retrievedTotalEarning,bonus_earn=bonus_earn,prv_arr_earn=arrearValue,sts=sts,salary_month=salary_month,salary=net_salary,insu_amt=insu_amt,esi_amt=esi_amt)
            generate_salary.save()
            return JsonResponse({'message': 'Employee registered successfully'}, status=200)
        except Exception as e:
            # Return error response with detailed error message
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


def check_user_id(request):
    if request.method == 'POST':
        selected_year = request.POST.get('year')
        emp_id = request.POST.get('userId')
        selected_month = request.POST.get('month')
        # user_id = request.POST.get('userId')  # Get the user ID from the AJAX request
        if PayrollMaathangi.objects.filter(
        salary_month__year=selected_year,
        emp_id=emp_id,
        salary_month__month=selected_month
    ).exists():
            return JsonResponse({'status': 'exists'})
        else:
            return JsonResponse({'status': 'not_exists'})

@require_GET
def fetch_month_year_record_payrollmathangi(request):
    selected_year = request.GET.get('year')
    selected_month = request.GET.get('month')
    # Fetch data from RegisterAll based on emp_id
    employee_salary_record = PayrollMaathangi.objects.filter(
        salary_month__year=selected_year,
        salary_month__month=selected_month
    ).values(
    'emp_id',
    'salary_month',
    )
    # Convert the querysets to lists for JSON serialization
    employee_salary_record_list = list(employee_salary_record)
    # Combine both sets of data into a single dictionary
    response_data = {
        'employee_salary_record': employee_salary_record_list,
    }
    return JsonResponse(response_data, safe=False)


@require_GET
def employee_payrollmathangi_record(request):
    selected_year = request.GET.get('year')
    emp_id = request.GET.get('userId')
    selected_month = request.GET.get('month')
    # Fetch data from RegisterAll based on emp_id
    employee_salary_record = PayrollMaathangi.objects.filter(
        salary_month__year=selected_year,
        emp_id=emp_id,
        salary_month__month=selected_month
    ).values(
    'id',
    'emp_id',
    'emp_nm',
    'desig',
    'doj',
    'locc',
    'pf_amt',
    'pf_num',
    'actual_sal',
    'punch',
    'punch_hlf',
    'cl',
    'cl_hlf',
    'od',
    'od_hlf',
    'holiday',
    'missed_clkin',
    'lop',
    'lop_hlf',
    'missed_clkin_hlf',
    'early_clkout',
    'mng_late',
    'earlyby',
    'tot_late',
    'tot_late_deduct_days',
    'tot_month_days',
    'min_attnd_need',
    'sal_elig_days',
    'process_dt',
    'salary_dt',
    'adv_deduct',
    'arr_deduct',
    'sd_deduct',
    'days_extra_deduct',
    'bonus_earn',
    'prv_arr_earn',
    'sts',
    'salary_month',
    'salary',
    'insu_amt',
    'esi_amt',
    )
    # Convert the querysets to lists for JSON serialization
    employee_salary_record_list = list(employee_salary_record)
    # Combine both sets of data into a single dictionary
    response_data = {
        'employee_salary_record': employee_salary_record_list,
    }
    return JsonResponse(response_data, safe=False)

def employee_detail_registerall(request):
    emp_id = request.GET.get('userId')
    # Fetch data from RegisterAll based on emp_id
    employee_data = RegisterAll.objects.filter(user_id=emp_id).values(
        'depart',
        'nm',
        'user_id',
        'mnth',
        'yr',
        'dsig',
        'locca',
        'bank',
        'acc_no',
        'doj',
        'pf_cd',
    )
    # Convert the querysets to lists for JSON serialization
    employee_data_list = list(employee_data)
    # Combine both sets of data into a single dictionary
    response_data = {
        'employee_data': employee_data_list,
    }
    return JsonResponse(response_data, safe=False)

from django.http import JsonResponse
def delete_employee_payrollmathangi_record(request, id):
    try:
        data = PayrollMaathangi.objects.get(id=id)
        data.delete()
        return JsonResponse({'message': 'Record deleted successfully'}, status=200)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)




#print_id
    
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def print_id(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
        
        selected_branch_id = request.session.get('selected_branch_id', default_branch)

        # Check if 'selected_all' is set in the session
        selected_all = request.session.get('selected_all', False)

        # If selected_all is True, fetch details for all branches
        if selected_all:
            leave_requests = RegisterAll.objects.exclude(depart="SAD").values()
        else:
            # If selected_branch_id is not present, return error response
            if not selected_branch_id:
                return HttpResponse(status=404)

            try:
                branch = Branch.objects.get(branch_name=selected_branch_id)
                selected_branch_employee_code = branch.employee_code[:3]
                selected_branch_admin_code = branch.admin_code[:3]
                selected_branch_trainee_code = branch.trainee_code[:3]

                # Fetch leave requests where bk_attendance date is the current date
                leave_requests = RegisterAll.objects.exclude(depart='SAD').filter(
                    Q(user_id__startswith=selected_branch_employee_code) |
                    Q(user_id__startswith=selected_branch_admin_code) |
                    Q(user_id__startswith=selected_branch_trainee_code)
                )
            except Branch.DoesNotExist:
                # Handle the case when the selected branch does not exist
                return redirect('errorpage')  # Redirect to an error page or handle as required
        
        # Query all records from RegisterAll model
        print(f"leave_requests {leave_requests}")
        # Send data to the template
        return render(request, 'print_id.html', {'current_user': current_user, 'leave_requests': leave_requests, 'branches': branches, 'default_branch': default_branch})
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')

    

# def print_id(request):
#     if 'username' in request.session:
#         current_user = request.session['username']
#         default_branch = request.session['default_branch_id']
#         branches = Branch.objects.all()
#         if 'selected_branch_id' in request.session:
#             selected_branch_id = request.session['selected_branch_id']
#             try:
#                 branch = Branch.objects.get(branch_name=selected_branch_id)
#                 selected_branch_employee_code = branch.employee_code[:3]
#                 selected_branch_admin_code = branch.admin_code[:3]
#                 selected_branch_trainee_code = branch.trainee_code[:3]
                
#                 # Fetch leave requests where bk_attendance date is the current date
#                 leave_requests = RegisterAll.objects.exclude(depart='SAD').filter(
#                     Q(user_id__startswith=selected_branch_employee_code) |
#                     Q(user_id__startswith=selected_branch_admin_code) |
#                     Q(user_id__startswith=selected_branch_trainee_code)
#                 )
#             except Branch.DoesNotExist:
#                 # Handle the case when the selected branch does not exist
#                 return redirect('errorpage')  # Redirect to an error page or handle as required
#         else:
#             # If no branch is selected, fetch all leave requests
#             leave_requests = RegisterAll.objects.exclude(depart='SAD').all()
            
#         # Query all records from RegisterAll model
#         print(f"leave_requests {leave_requests}")
#         # Send data to the template
#         return render(request, 'print_id.html', {'current_user': current_user, 'leave_requests': leave_requests, 'branches': branches , 'default_branch':default_branch})
#     else:
#         # Handle the case when the user is not logged in
#         return redirect('loginpage')    


def fetch_user_details(request):
    if request.method == 'GET':
        user_id = request.GET.get('user_id')
        try:
            users = RegisterAll.objects.filter(user_id=user_id)
            if users.exists():  # Check if any user with the given user_id exists
                user = users.first()  # Assuming you want the details of the first user found
                user_details = {
                    'pic': user.pic,  # Include profile picture URL
                    'name': user.nm,
                    'user_id': user.user_id,
                    'dsig': user.dsig,
                    'fath_nm': user.fath_nm,
                    'blood': user.blood,
                    'addr': user.addr,
                    'hm_mob': user.hm_mob,
                    'offc_mob': user.offc_mob,
                    # Add more fields as needed
                }
                return JsonResponse(user_details)
            else:
                return JsonResponse({'error': 'User not found'}, status=404)
        except RegisterAll.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)
    
@csrf_exempt  # Ensure to import csrf_exempt from django.views.decorators.csrf
def update_data(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_id = data.get('user_id')
            objs = RegisterAll.objects.filter(user_id=user_id)
            if objs.exists():
                for obj in objs:
                    obj.nm = data.get('nm')
                    obj.fath_nm = data.get('fath_nm')
                    obj.blood = data.get('blood')
                    obj.addr = data.get('addr')
                    obj.hm_mob = data.get('hm_mob')
                    obj.offc_mob = data.get('offc_mob')
                    obj.save()
                return JsonResponse({'status': 'success'})
            else:
                return JsonResponse({'status': 'error', 'message': 'Object not found'})
        except RegisterAll.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Object not found'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'})
    
from django.http import HttpResponseNotFound, FileResponse
import mimetypes
import os
def download_file(request, downloadFile):
    # Assuming user_details.pic is a valid directory name
    # Define the path to the file
    file_path = os.path.join('/static/upload/', request.user_details.pic, downloadFile)
    # Check if the file exists
    if not os.path.exists(file_path):
        return HttpResponseNotFound('File not found')
    # Guess the MIME type of the file
    mime_type, _ = mimetypes.guess_type(file_path)
    # Open the file and serve it as a response
    with open(file_path, 'rb') as f:
        response = FileResponse(f, content_type=mime_type)
        response['Content-Disposition'] = f'attachment; filename="{downloadFile}"'
        return response            
    


@require_POST
def check_salary(request):
    dob = request.POST.get('dob')
    # Assuming you have a model named Employee with a field 'date_of_birth'
    # Replace Employee with your actual model name
    employee = RegisterAll.objects.filter(dob=dob).first()
    if employee:
        salary = employee.sala  # Assuming 'salary' is a field in your Employee model
        return JsonResponse({'salary': salary})
    else:
        return JsonResponse({'error': 'Employee not found'}, status=400)
    



@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def add_location(request):
    if 'username' in request.session:
        current_user = request.session['username']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request, 'location.html', {'current_user': current_user , 'branches': branches})    


@csrf_exempt
def add_department_again(request):
    if request.method == 'POST':
        department_name = request.POST.get('department_name')
        if department_name:
            department = AddDepartment.objects.create(nm=department_name)
            department.save()
            return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=400)


@csrf_exempt
def department_head(request):
    if request.method == 'POST':
        department = request.POST.get('department')
        departmentHead = request.POST.get('departmentHead')
        empid = request.POST.get('empid')
        head_name = request.POST.get('head_name')
        branchName = request.POST.get('branchName')

        if head_name:
            department =AddDepartmentHead.objects.create(dept=department,name=head_name ,desig=departmentHead ,emp_id=empid , branch=branchName)
            department.save()
            return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=400)  





def validate_employee_id(request):
    if request.method == 'GET' and 'emp_id' in request.GET:
        emp_id = request.GET.get('emp_id')
        print(f"emp_id {emp_id}")
        try:
            employee = RegisterAll.objects.filter(user_id=emp_id).first()
            # name=employee.nm
            # print(f"name",name)
            return JsonResponse({'name': employee.nm})  # Assuming 'name' is a field in the RegisterAll model
        except RegisterAll.DoesNotExist:
            return JsonResponse({'error': 'Employee ID not found'}, status=404)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)



def validate_employee_id1(request):
    if request.method == 'GET' and 'employeeid' in request.GET:
        emp_idd = request.GET.get('employeeid')
        print(f"employeeid {emp_idd}")
        try:
            employeee = RegisterAll.objects.filter(user_id=emp_idd).first()
            # name=employee.nm
            # print(f"name",name)
            return JsonResponse({'name': employeee.nm})  # Assuming 'name' is a field in the RegisterAll model
        except RegisterAll.DoesNotExist:
            return JsonResponse({'error': 'Employee ID not found'}, status=404)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)
            
    



@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def location(request):
    if 'username' in request.session:
        current_user = request.session['username']
        branches = Branch.objects.all()
    else:
        return redirect('loginpage')
    if request.method == 'POST':
        location = request.POST.get('location')  # Fetch location from POST data
        if location:
            if AddLocation.objects.filter(location__iexact=location).exists():
                messages.error(request, 'Location already exists')
                return redirect('location')
            new_location = AddLocation.objects.create(location=location)  # Create new location object
            messages.success(request, 'Location added successfully')
            return redirect('location')
        else:
            messages.error(request, 'Location name is required')
            return redirect('location')  # Redirect back to the same page if location is not provided
    data = AddLocation.objects.all()
    return render(request, 'location.html', {'data': data, 'current_user': current_user, 'branches': branches})

from django.shortcuts import get_object_or_404
from django.http import HttpResponse
def delete_location(request, location_id):
    try:
        location = get_object_or_404(AddLocation, pk=location_id)
        # Delete the location or perform any other necessary operations
        location.delete()
        return HttpResponse("Location deleted successfully")
    except AddLocation.DoesNotExist:
        return HttpResponse("Location does not exist", status=404)


#salary_increment
@require_POST
def add_salary_increment(request):
    if request.method == 'POST':
        # Retrieve data from the POST request
        salary = request.POST.get('salary')
        basic = request.POST.get('basic')
        hr = request.POST.get('hr')
        conv_All = request.POST.get('conv_All')
        medical_All = request.POST.get('medical_All')
        special_All = request.POST.get('special_All')
        incre_date = request.POST.get('incre_date')
        position = request.POST.get('position')
        final_salary = request.POST.get('final_salary')
        user_id = request.POST.get('user_id')

        # Create an instance of the model and save data to the database
        salary_instance = AddSalary(
            salary=salary,
            basic=basic,
            hr=hr,
            conv_all=conv_All,
            medical_all=medical_All,
            spl_all=special_All,
            incre_dt=incre_date,
            position=position,
            sal_last=final_salary,
            user_id=user_id,
        )
        salary_instance.save()

        # Prepare the data to be returned in the response
        response_data = {
            'salary': salary,
            'basic': basic,
            'hr': hr,
            'conv_All': conv_All,
            'medical_All': medical_All,
            'special_All': special_All,
            'incre_date': incre_date,
            'position': position,
            'final_salary': final_salary,
        }

        return JsonResponse({'message': 'Data received successfully', 'data': response_data})
    else:
        return JsonResponse({'error': 'Invalid request method'})



def fetch_salary_increment(request):
    if request.method == 'POST':
        user_id = request.POST.get('userId')
        print(f"user_id {user_id}")

        try:
            # Assuming SalaryIncrement model has a field named 'user_id'
            # Replace 'user_id' with the actual field name if it's different
            salary_increment = AddSalary.objects.get(user_id=user_id)
            # Now you can extract the details you need from the salary_increment object
            details = {
                'user_id': salary_increment.user_id,
                'salary': salary_increment.sal_last,
                'position': salary_increment.position,
                'incre_dt': salary_increment.incre_dt,
                # Add more fields as needed
            }
            print(f"details {details}")
            return JsonResponse(details)
        except AddSalary.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)  


def fetch_locations(request):
    if request.method == 'GET':
        try:
            # Retrieve locations from the Branch model
            locations = Branch.objects.values('id', 'addr')
            
            # Serialize locations queryset into a list of dictionaries
            serialized_locations = list(locations)
            print(f"serialized_locations {serialized_locations}")
            # Remove duplicates based on 'id'
            unique_serialized_locations = {item['addr']: item for item in serialized_locations}.values()

            # Convert back to list if necessary
            unique_serialized_locations = list(unique_serialized_locations)
            print(f"unique_serialized_locations {unique_serialized_locations}")
            return JsonResponse(unique_serialized_locations, safe=False)  # safe=False to allow non-dict objects in serialization
        except Branch.DoesNotExist:
            return JsonResponse({'error': 'Locations not found'}, status=404)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)



@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def wallpaper(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()  
    else:
        # Handle the case when the user is not logged in
        return redirect('wallpaper')  # You can set it to None or any default value    
    return render(request, 'wallpaper.html',{'current_user': current_user , 'branches': branches, 'default_branch':default_branch})


@csrf_exempt
def upload_wallpaper(request):
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        request.session['uploaded_file_path'] = uploaded_file.name
        # Define the directory where you want to save the file
        save_directory = os.path.join('static', 'wallpaper')
        # Create the directory if it doesn't exist
        os.makedirs(save_directory, exist_ok=True)
        
        # Delete existing files in the wallpaper folder
        existing_files = os.listdir(save_directory)
        for file in existing_files:
            os.remove(os.path.join(save_directory, file))

        # Save the file to the specified directory
        with open(os.path.join(save_directory, uploaded_file.name), 'wb+') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)

        # Delete existing records from the wallpaper table
        Wallpaper.objects.all().delete()

        # Insert into database
        wallpaper = Wallpaper(wallpaper=uploaded_file.name)
        wallpaper.save()

        return JsonResponse({'message': 'File uploaded and inserted into the database successfully.'})
    else:
        return JsonResponse({'error': 'No file found in the request.'}, status=400)

import os
# from django.conf import settings
from django.templatetags.static import static

def display_last_image(request):
    # Get the path to the wallpaper folder
    wallpaper_folder = os.path.join('static', 'wallpaper')

    # Get a list of all image files in the wallpaper folder
    image_files = [f for f in os.listdir(wallpaper_folder) if os.path.isfile(os.path.join(wallpaper_folder, f))]

    # If there are image files, get the last one
    if image_files:
        last_image = image_files[-1]
        # Construct the image URL using Django's static template tag
        image_url = static(f'wallpaper/{last_image}')
        print(f"image_url {image_url}")
    else:
        image_url = None
        

    # Return the image URL as JSON
    return JsonResponse({'image_url': image_url})



def delete_last_image(request):
    if request.method == 'DELETE':
        # Retrieve the last wallpaper image from the database
        last_wallpaper = Wallpaper.objects.last()
        
        if last_wallpaper:
            # Get the path to the image file
            path = os.path.join('static', 'wallpaper')  # Corrected assignment
            image_path = os.path.join(path, last_wallpaper.wallpaper)  # Assuming 'image' is the correct field name
            if os.path.exists(image_path):
                os.remove(image_path)
                # Optionally, you can also delete the database entry for the image
                last_wallpaper.delete()
                return JsonResponse({'message': 'Image deleted successfully'}, status=200)
            else:
                return JsonResponse({'error': 'Image not found'}, status=404)
        else:
            return JsonResponse({'error': 'No wallpaper found'}, status=404)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)



#footer
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
# @department_required('SAD')
def footer(request):
    if 'username' in request.session:
        current_user = request.session['username']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request, 'footer.html', {'current_user': current_user , 'branches': branches}) 




from django.core.files.storage import default_storage
from django.http import JsonResponse
@csrf_exempt
def save_view_admin_details(request):
    if request.method == 'POST':
        try:
            edited_data = request.POST  # Use request.POST to access form data
            user_id = edited_data.get('user_id', None)
            

            if 'pic' in request.FILES:
                # Update the 'pic' field if image data is present
                image_data = request.FILES['pic']

                # Generate a random filename
                random_filename = f'{random_string()}.png'

                # Build the file path
                file_path = f'static/upload/{random_filename}'

                # Save the uploaded file
                with default_storage.open(file_path, 'wb') as destination:
                    for chunk in image_data.chunks():
                        destination.write(chunk)

                # Update the 'pic' field in the model with the random filename
                register_instance = RegisterAll.objects.get(user_id=user_id, depart='ad')
                register_instance.pic = random_filename
            else:
                # If no new image is provided, keep the existing 'pic' value
                register_instance = RegisterAll.objects.get(user_id=user_id, depart='ad')
                if not register_instance.pic:  # Check if the 'pic' field is not empty
                    # Assign the old image name or a default value if needed
                    register_instance.pic = edited_data.get('pic', '')  # Replace with your logic

            register_instance.nm = edited_data.get('nm', '')
            
            register_instance.pwd = edited_data.get('pwd', '')
            ciphertext = encrypt(register_instance.pwd, key)
            print("Encrypted:", ciphertext)
            register_instance.pwd = ciphertext  

            register_instance.mob = edited_data.get('mob', '')
            register_instance.email = edited_data.get('email', '')
            register_instance.fath_nm = edited_data.get('fath_nm', '')
            register_instance.dob = edited_data.get('dob', '')
            register_instance.addr = edited_data.get('addr', '')
            register_instance.hm_mob = edited_data.get('hm_mob', '')
            register_instance.blood = edited_data.get('blood', '')
            register_instance.gender = edited_data.get('gender_type', '')
            register_instance.em_depart = edited_data.get('em_depart', '')
            register_instance.em_depart_hed = edited_data.get('em_depart_hed', '')
            register_instance.em_depart_tl = edited_data.get('em_depart_tl', '')
            register_instance.reg_dt = edited_data.get('reg_dt', '')
            register_instance.permi = edited_data.get('permi', '')
            register_instance.doj = edited_data.get('doj', '')
            register_instance.offc_mob = edited_data.get('offc_mob', '')
            register_instance.work_frm = edited_data.get('work_frm', '')
            register_instance.work_to = edited_data.get('work_to', '')
            register_instance.no_of_cl = edited_data.get('no_of_cl', '')
            register_instance.employee_contri = edited_data.get('employee_contri', '')
            register_instance.employer_contri = edited_data.get('employer_contri', '')
            register_instance.locca = edited_data.get('locca', '')
            register_instance.bank = edited_data.get('bank', '')
            register_instance.acc_no = edited_data.get('acc_no', '')
            register_instance.ifsc = edited_data.get('ifsc', '')
            register_instance.dsig = edited_data.get('dsig', '')
            # register_instance.sd_amt = edited_data.get('sd_amt', '')
            register_instance.company = edited_data.get('company', '')
            register_instance.insu_amt = edited_data.get('insu_amt', '')
            # register_instance.esi_amt = edited_data.get('esi_amt', '')
            register_instance.sala = edited_data.get('sala', '')
            register_instance.branch = edited_data.get('branch', '')
            register_instance.aadhar_num = edited_data.get('aadhar_num', '')
            register_instance.pan_num = edited_data.get('pan_num', '')
            register_instance.rejoin_dt = edited_data.get('rejoin_dt', '')
            register_instance.reliving_dt = edited_data.get('reliving_dt', '')
            register_instance.save()
            return JsonResponse({'success': True, 'message': 'Changes saved successfully'})
        except RegisterAll.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'User not found'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': f'Error during save: {str(e)}'})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'})

def admin_view_details(request, admin_id):
    try:
        admin_details = RegisterAll.objects.get(id=admin_id, depart='ad')
    except RegisterAll.DoesNotExist:
        return JsonResponse({'error': 'Admin not found'}, status=404)
    decrypted_password = decrypt(admin_details.pwd, key)
    print(f"decrypted_password {decrypted_password}")

    response_data = {
    'picture': admin_details.pic,
    'name': admin_details.nm,
    'userId': admin_details.user_id,
    'password': decrypted_password,
    'mobile': admin_details.mob,
    'address': admin_details.addr,
    'gender_type': admin_details.gender,
    'department': admin_details.em_depart,
    'departmentHead': admin_details.em_depart_hed,
    'employeeDeptTL': admin_details.em_depart_tl,
    'numberOfCL': admin_details.no_of_cl,
    'email': admin_details.email,
    'registrationDate': admin_details.reg_dt,  # Assuming 'registration date' is a datetime field
    'designation': admin_details.dsig,
    'workFrom': admin_details.work_frm,
    'workTo': admin_details.work_to,
    'officeMobile': admin_details.offc_mob,
    'dateOfJoining': admin_details.doj,
    'UAN': admin_details.pf_cd,
    'location': admin_details.locca,
    'bank': admin_details.bank,
    'accountNumber': admin_details.acc_no,
    'ifscCode': admin_details.ifsc,
    'dateOfBirth': admin_details.dob,
    'empContri': admin_details.employee_contri,
    'emplrContri': admin_details.employer_contri,
    # 'sdAmount': admin_details.sd_amt,
    'company': admin_details.company,
    'permission': admin_details.permi,
    'fatherSpouseName': admin_details.fath_nm,
    'bloodGroup': admin_details.blood,
    'homeMobile': admin_details.hm_mob,
    'insuranceAmount': admin_details.insu_amt,
    # 'esiAmount': admin_details.esi_amt,
    'salary': admin_details.sala,
    'rejoining': admin_details.rejoin_dt,
    'reliving': admin_details.reliving_dt,

    'branch': admin_details.branch,
    'aadhar': admin_details.aadhar_num,
    'pan': admin_details.pan_num,

    'teamid': admin_details.team_ld,
}
    return JsonResponse(response_data)

@csrf_exempt
def save_view_employee_details(request):
    if request.method == 'POST':
        try:
            edited_data = request.POST  # Use request.POST to access form data
            user_id = edited_data.get('user_id', None)
            # if 'pic' in request.FILES:
            #     # Update the 'pic' field if image data is present
            #     image_data = request.FILES['pic']
            #     file_path = f'static/upload/{image_data.name}'
            #     # Save the uploaded file
            #     with default_storage.open(file_path, 'wb') as destination:
            #         for chunk in image_data.chunks():
            #             destination.write(chunk)
            #     # Update the 'pic' field in the model with the file path
            #     register_instance = RegisterAll.objects.get(user_id=user_id, depart='emp')
            #     register_instance.pic = f'{image_data.name}'
            if 'pic' in request.FILES:
                # Update the 'pic' field if image data is present
                image_data = request.FILES['pic']

                # Generate a random filename
                random_filename = f'{random_string()}.png'

                # Build the file path
                file_path = f'static/upload/{random_filename}'

                # Save the uploaded file
                with default_storage.open(file_path, 'wb') as destination:
                    for chunk in image_data.chunks():
                        destination.write(chunk)

                # Update the 'pic' field in the model with the random filename
                register_instance = RegisterAll.objects.get(user_id=user_id, depart='emp')
                register_instance.pic = random_filename
            else:
                # If no new image is provided, keep the existing 'pic' value
                register_instance = RegisterAll.objects.get(user_id=user_id, depart='emp')
                if not register_instance.pic:  # Check if the 'pic' field is not empty
                    # Assign the old image name or a default value if needed
                    register_instance.pic = edited_data.get('pic', '')  # Replace with your logic
            register_instance.nm = edited_data.get('nm', '')

            register_instance.pwd = edited_data.get('pwd', '')
            ciphertext = encrypt(register_instance.pwd, key)
            print("Encrypted:", ciphertext)
            register_instance.pwd = ciphertext  

            register_instance.mob = edited_data.get('mob', '')
            register_instance.email = edited_data.get('email', '')
            register_instance.fath_nm = edited_data.get('fath_nm', '')
            register_instance.dob = edited_data.get('dob', '')
            register_instance.addr = edited_data.get('addr', '')
            register_instance.hm_mob = edited_data.get('hm_mob', '')
            register_instance.gender = edited_data.get('gender_type', '')
            register_instance.blood = edited_data.get('blood', '')
            register_instance.em_depart = edited_data.get('em_depart', '')
            register_instance.em_depart_hed = edited_data.get('em_depart_hed', '')
            register_instance.em_depart_tl = edited_data.get('em_depart_tl', '')
            register_instance.reg_dt = edited_data.get('reg_dt', '')
            register_instance.permi = edited_data.get('permi', '')
            register_instance.doj = edited_data.get('doj', '')
            register_instance.offc_mob = edited_data.get('offc_mob', '')
            register_instance.work_frm = edited_data.get('work_frm', '')
            register_instance.work_to = edited_data.get('work_to', '')
            register_instance.no_of_cl = edited_data.get('no_of_cl', '')
            register_instance.employee_contri = edited_data.get('employee_contri', '')
            register_instance.employer_contri = edited_data.get('employer_contri', '')
            register_instance.locca = edited_data.get('locca', '')
            register_instance.bank = edited_data.get('bank', '')
            register_instance.acc_no = edited_data.get('acc_no', '')
            register_instance.ifsc = edited_data.get('ifsc', '')
            register_instance.dsig = edited_data.get('dsig', '')
            # register_instance.sd_amt = edited_data.get('sd_amt', '')
            register_instance.company = edited_data.get('company', '')
            register_instance.insu_amt = edited_data.get('insu_amt', '')
            # register_instance.esi_amt = edited_data.get('esi_amt', '')
            register_instance.sala = edited_data.get('sala', '')
            register_instance.rejoin_dt = edited_data.get('rejoin_dt', '')
            register_instance.reliving_dt = edited_data.get('reliving_dt', '')

            register_instance.branch = edited_data.get('branch', '')
            register_instance.aadhar_num = edited_data.get('aadhar_num', '')
            register_instance.pan_num = edited_data.get('pan_num', '')

            register_instance.save()

            return JsonResponse({'success': True, 'message': 'Changes saved successfully'})
        except RegisterAll.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'User not found'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': f'Error during save: {str(e)}'})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'})

def employee_view_details(request, employee_id):
    try:
        employee_details = RegisterAll.objects.get(id=employee_id, depart='emp')
    except RegisterAll.DoesNotExist:
        return JsonResponse({'error': 'Admin not found'}, status=404)
    
    decrypted_password = decrypt(employee_details.pwd, key)
    print(f"decrypted_password {decrypted_password}")

    response_data = {
    'picture': employee_details.pic,
    'name': employee_details.nm,
    'userId': employee_details.user_id,
    'password': decrypted_password,
    'mobile': employee_details.mob,
    'address': employee_details.addr,
    'gender_type': employee_details.gender,
    'department': employee_details.em_depart,
    'departmentHead': employee_details.em_depart_hed,
    'employeeDeptTL': employee_details.em_depart_tl,
    'numberOfCL': employee_details.no_of_cl,
    'email': employee_details.email,
    'registrationDate': employee_details.reg_dt,  # Assuming 'registration date' is a datetime field
    'designation': employee_details.dsig,
    'workFrom': employee_details.work_frm,
    'workTo': employee_details.work_to,
    'officeMobile': employee_details.offc_mob,
    'dateOfJoining': employee_details.doj,
    'UAN': employee_details.pf_cd,
    'location': employee_details.locca,
    'bank': employee_details.bank,
    'accountNumber': employee_details.acc_no,
    'ifscCode': employee_details.ifsc,
    'dateOfBirth': employee_details.dob,
    'empContri': employee_details.employee_contri,
    'emplrContri': employee_details.employer_contri,
    # 'sdAmount': employee_details.sd_amt,
    'company': employee_details.company,
    'permission': employee_details.permi,
    'fatherSpouseName': employee_details.fath_nm,
    'bloodGroup': employee_details.blood,
    'homeMobile': employee_details.hm_mob,
    'insuranceAmount': employee_details.insu_amt,
    # 'esiAmount': employee_details.esi_amt,
    'salary': employee_details.sala,
    'rejoining': employee_details.rejoin_dt,
    'reliving': employee_details.reliving_dt,

    'branch': employee_details.branch,
    'aadhar': employee_details.aadhar_num,
    'pan': employee_details.pan_num,

    'teamid': employee_details.team_ld,
}
    
    return JsonResponse(response_data)

@csrf_exempt
def save_view_trainee_details(request):
    if request.method == 'POST':
        try:
            edited_data = request.POST  # Use request.POST to access form data
            user_id = edited_data.get('user_id', None)
            # if 'pic' in request.FILES:
            #     # Update the 'pic' field if image data is present
            #     image_data = request.FILES['pic']
            #     file_path = f'static/upload/{image_data.name}'
            #     # Save the uploaded file
            #     with default_storage.open(file_path, 'wb') as destination:
            #         for chunk in image_data.chunks():
            #             destination.write(chunk)
            #     # Update the 'pic' field in the model with the file path
            #     register_instance = RegisterAll.objects.get(user_id=user_id, depart='trainee')
            #     register_instance.pic = f'{image_data.name}'


            if 'pic' in request.FILES:
                # Update the 'pic' field if image data is present
                image_data = request.FILES['pic']

                # Generate a random filename
                random_filename = f'{random_string()}.png'

                # Build the file path
                file_path = f'static/upload/{random_filename}'

                # Save the uploaded file
                with default_storage.open(file_path, 'wb') as destination:
                    for chunk in image_data.chunks():
                        destination.write(chunk)

                # Update the 'pic' field in the model with the random filename
                register_instance = RegisterAll.objects.get(user_id=user_id, depart='trainee')
                register_instance.pic = random_filename



            else:
                # If no new image is provided, keep the existing 'pic' value
                register_instance = RegisterAll.objects.get(user_id=user_id, depart='trainee')
                if not register_instance.pic:  # Check if the 'pic' field is not empty
                    # Assign the old image name or a default value if needed
                    register_instance.pic = edited_data.get('pic', '')  # Replace with your logic
            register_instance.nm = edited_data.get('nm', '')

            register_instance.pwd = edited_data.get('pwd', '')
            ciphertext = encrypt(register_instance.pwd, key)
            print("Encrypted:", ciphertext)
            register_instance.pwd = ciphertext 

            register_instance.mob = edited_data.get('mob', '')
            register_instance.email = edited_data.get('email', '')
            register_instance.fath_nm = edited_data.get('fath_nm', '')
            register_instance.dob = edited_data.get('dob', '')
            register_instance.addr = edited_data.get('addr', '')
            register_instance.gender = edited_data.get('gender_type', '')
            register_instance.hm_mob = edited_data.get('hm_mob', '')
            register_instance.blood = edited_data.get('blood', '')
            register_instance.em_depart = edited_data.get('em_depart', '')
            register_instance.em_depart_hed = edited_data.get('em_depart_hed', '')
            register_instance.em_depart_tl = edited_data.get('em_depart_tl', '')
            register_instance.reg_dt = edited_data.get('reg_dt', '')
            register_instance.permi = edited_data.get('permi', '')
            register_instance.doj = edited_data.get('doj', '')
            register_instance.offc_mob = edited_data.get('offc_mob', '')
            register_instance.work_frm = edited_data.get('work_frm', '')
            register_instance.work_to = edited_data.get('work_to', '')
            register_instance.no_of_cl = edited_data.get('no_of_cl', '')
            register_instance.employee_contri = edited_data.get('employee_contri', '')
            register_instance.employer_contri = edited_data.get('employer_contri', '')
            register_instance.locca = edited_data.get('locca', '')
            register_instance.bank = edited_data.get('bank', '')
            register_instance.acc_no = edited_data.get('acc_no', '')
            register_instance.ifsc = edited_data.get('ifsc', '')
            register_instance.dsig = edited_data.get('dsig', '')
            # register_instance.sd_amt = edited_data.get('sd_amt', '')
            register_instance.company = edited_data.get('company', '')
            register_instance.insu_amt = edited_data.get('insu_amt', '')
            # register_instance.esi_amt = edited_data.get('esi_amt', '')
            register_instance.sala = edited_data.get('sala', '')
            register_instance.rejoin_dt = edited_data.get('rejoin_dt', '')
            register_instance.reliving_dt = edited_data.get('reliving_dt', '')

            
            register_instance.branch = edited_data.get('branch', '')
            register_instance.aadhar_num = edited_data.get('aadhar_num', '')
            register_instance.pan_num = edited_data.get('pan_num', '')

            register_instance.save()

            return JsonResponse({'success': True, 'message': 'Changes saved successfully'})
        except RegisterAll.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'User not found'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': f'Error during save: {str(e)}'})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'})

def trainee_view_details(request, trainee_id):
    try:
        trainee_details = RegisterAll.objects.get(id=trainee_id, depart='trainee')
    except RegisterAll.DoesNotExist:
        return JsonResponse({'error': 'Admin not found'}, status=404)
    decrypted_password = decrypt(trainee_details.pwd, key)
    print(f"decrypted_password {decrypted_password}")

    response_data = {
    'picture': trainee_details.pic,
    

    'name': trainee_details.nm,
    'userId': trainee_details.user_id,
    'password': decrypted_password,
    'mobile': trainee_details.mob,
    'address': trainee_details.addr,
    'gender_type': trainee_details.gender,
    'department': trainee_details.em_depart,
    'departmentHead': trainee_details.em_depart_hed,
    'employeeDeptTL': trainee_details.em_depart_tl,
    'numberOfCL': trainee_details.no_of_cl,
    'email': trainee_details.email,
    'registrationDate': trainee_details.reg_dt,  # Assuming 'registration date' is a datetime field
    'designation': trainee_details.dsig,
    'workFrom': trainee_details.work_frm,
    'workTo': trainee_details.work_to,
    'officeMobile': trainee_details.offc_mob,
    'dateOfJoining': trainee_details.doj,
    'UAN': trainee_details.pf_cd,
    'location': trainee_details.locca,
    'bank': trainee_details.bank,
    'accountNumber': trainee_details.acc_no,
    'ifscCode': trainee_details.ifsc,
    'dateOfBirth': trainee_details.dob,
    'empContri': trainee_details.employee_contri,
    'emplrContri': trainee_details.employer_contri,
    # 'sdAmount': trainee_details.sd_amt,
    'company': trainee_details.company,
    'permission': trainee_details.permi,
    'fatherSpouseName': trainee_details.fath_nm,
    'bloodGroup': trainee_details.blood,
    'homeMobile': trainee_details.hm_mob,
    'insuranceAmount': trainee_details.insu_amt,
    # 'esiAmount': trainee_details.esi_amt,
    'salary': trainee_details.sala,
    'rejoining': trainee_details.rejoin_dt,
    'reliving': trainee_details.reliving_dt,

    'branch': trainee_details.branch,
    'aadhar': trainee_details.aadhar_num,
    'pan': trainee_details.pan_num,

    'teamid': trainee_details.team_ld,
}
    
    
    return JsonResponse(response_data)


def get_department_head(request):
    selected_branch_id = request.session['selected_branch_id']
    if request.method == 'POST':
        data = json.loads(request.body)
        selected_value = data.get('selectedValue')
        # Query the database to get data based on selectedValue and desig='Head'
        result = AddDepartmentHead.objects.filter(dept=selected_value, desig='Head',branch=selected_branch_id).values()
        return JsonResponse(list(result), safe=False)
    return JsonResponse({'error': 'Invalid request method'}, status=400)

def get_department_tl(request):
    selected_branch_id = request.session['selected_branch_id']
    if request.method == 'POST':
        data = json.loads(request.body)
        selected_value = data.get('selectedValue')
        # Query the database to get data based on selectedValue and desig='Head'
        result = AddDepartmentHead.objects.filter(dept=selected_value, desig='TL',branch=selected_branch_id).values()
        return JsonResponse(list(result), safe=False)
    return JsonResponse({'error': 'Invalid request method'}, status=400)

def get_branch_options(request):
    branch_options = AddDepartment.objects.values_list('nm', flat=True)
    print(f'branch_options :{branch_options}')
    return JsonResponse(list(branch_options), safe=False)


def get_location_options(request):
    location_options = Branch.objects.values_list('addr', flat=True).distinct()
    print(f'location_options :{location_options}')
    return JsonResponse(list(location_options), safe=False)   



def check_trainee_id(request):
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        print(f"user_id {user_id}")
        if RegisterAll.objects.filter(user_id=user_id).exists():
            return JsonResponse({'exists': True})
        else:
            return JsonResponse({'exists': False}) 

def check_same_department(request):
    if request.method == 'POST':
        department_name = request.POST.get('department_name')
        if AddDepartment.objects.filter(nm=department_name).exists():
            return JsonResponse({'exists': True})
        else:
            return JsonResponse({'exists': False})


#Today report
        
#Today report
from datetime import date
@cache_control(no_cache=True, must_revalidate=True, no_store=True) 
@department_required('SAD') 
def today_report(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request, 'today_report.html', {'current_user': current_user , 'branches': branches,'default_branch':default_branch}) 

def get_today_present_data(request):
    if 'username' in request.session:
        current_user = request.session.get('username')
        default_branch = request.session.get('default_branch_id')
        branches = Branch.objects.all()

        # Check if selected_branch_id is in the session
        selected_branch_id = request.session.get('selected_branch_id', default_branch)

        try:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.employee_code[:3]
            selected_branch_admin_code = branch.admin_code[:3]
            selected_branch_trainee_code = branch.trainee_code[:3]
        except Branch.DoesNotExist:
            return HttpResponse(status=404)

        try:
            branch_default = Branch.objects.get(branch_name=default_branch)
            default_branch_employee_code = branch_default.employee_code[:3]
            default_branch_admin_code = branch_default.admin_code[:3]
            default_branch_trainee_code = branch_default.trainee_code[:3]
        except Branch.DoesNotExist:
            return HttpResponse(status=404)

    selected_date = request.GET.get('selected_date')
        
    if selected_date:
        try:
            selected_date = datetime.strptime(selected_date, '%Y-%m-%d').date()
        except ValueError:
            return JsonResponse({'error': 'Invalid date format. Please provide the date in YYYY-MM-DD format.'}, status=400)
    else:
        selected_date = date.today()  # If no date selected, use current date
    
    # Filter present_user_ids based on selected_branch_employee_code
    present_users = Attendance.objects.filter(date=selected_date).values('user_id', 'clk_in_tm', 'clk_out_tm')
    present_user_ids = {user['user_id']: {'clk_in_tm': user['clk_in_tm'], 'clk_out_tm': user['clk_out_tm']} for user in present_users}
    
    # Fetch both user_id, name, clock in/out times, work from, and work to from RegisterAll table
    if 'selected_branch_id' in request.session:  
        registered_users = RegisterAll.objects.filter(user_id__startswith=selected_branch_employee_code).values_list('user_id', 'nm', 'work_frm', 'work_to') | \
                           RegisterAll.objects.filter(user_id__startswith=selected_branch_admin_code).values_list('user_id', 'nm', 'work_frm', 'work_to') | \
                           RegisterAll.objects.filter(user_id__startswith=selected_branch_trainee_code).values_list('user_id', 'nm', 'work_frm', 'work_to')
    else:
        registered_users = RegisterAll.objects.filter(user_id__startswith=default_branch_employee_code).values_list('user_id', 'nm', 'work_frm', 'work_to') | \
                           RegisterAll.objects.filter(user_id__startswith=default_branch_admin_code).values_list('user_id', 'nm', 'work_frm', 'work_to') | \
                           RegisterAll.objects.filter(user_id__startswith=default_branch_trainee_code).values_list('user_id', 'nm', 'work_frm', 'work_to')
    
    data = []
    for user_id, name, work_frm, work_to in registered_users:
        present_absent = 'Present' if user_id in present_user_ids else 'Absent'
        clk_in_tm = present_user_ids[user_id]['clk_in_tm'] if user_id in present_user_ids else None
        clk_out_tm = present_user_ids[user_id]['clk_out_tm'] if user_id in present_user_ids else None
        data.append({'user_id': user_id, 'nm': name, 'present_absent': present_absent, 'clk_in_tm': clk_in_tm, 'clk_out_tm': clk_out_tm, 'work_frm': work_frm, 'work_to': work_to})
    
    return JsonResponse({'data': data})


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def add_wfh(request):
    if 'username' in request.session:
        current_user = request.session['username']
        work_data = RegisterAll.objects.filter(user_id=current_user).values('user_id', 'nm', 'em_depart','em_depart_hed','em_depart_tl')
        check_data = AddDepartmentHead.objects.filter(emp_id=current_user,desig='TL').values('name')
        check_data2 = AddDepartmentHead.objects.filter(emp_id=current_user,desig='Head').values('name')
        print(f"work_data {work_data}")
        print(f"check_data {check_data}")
        print(f"check_data2 {check_data2}")
        last_record = Visiters.objects.filter(user=current_user,).order_by('-log_in_dt_tm')[1:2].first()
        if last_record:
            log_in_tm = last_record.log_in_tm
            log_out_tm = last_record.log_out_tm
            log_dt = last_record.log_dt
            log_out_dt = last_record.log_out_dt
            return render(request, 'add_wfh.html', {'current_user': current_user,'log_in_tm': log_in_tm,
                'log_out_tm': log_out_tm,
                'log_dt': log_dt,
                'log_out_dt': log_out_dt, 'work_data': work_data,'check_data':check_data,'check_data2':check_data2})
        else:
            return render(request, 'add_wfh.html', {'current_user': current_user,'work_data': work_data,'check_data':check_data,'check_data2':check_data2})
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')

@csrf_exempt
def save_work_from_home(request):
    if request.method == "POST":
        data = json.loads(request.body)
        
        start_date = data.get("start_date")
        end_date = data.get("end_date")
        req_dt = data.get("req_dt")
        department = data.get("department")
        employee_id = data.get("employee_id")
        employee_name = data.get("employee_name")

        # Retrieve Monday to Sunday start and end times
        monday_start_hour = data.get("monday_start_hour")
        monday_start_minute = data.get("numberSelect1")
        monday_start_period = data.get("monday_start_period")
        if monday_start_hour and monday_start_minute and monday_start_period:
            monday_start = f"{monday_start_hour}:{monday_start_minute} {monday_start_period}"
        else:
            monday_start = " " 
        
        monday_end_hour = data.get("monday_end_hour")
        monday_end_minute = data.get("numberSelect2")
        monday_end_period = data.get("monday_end_period")
        # monday_end = f"{monday_end_hour}:{monday_end_minute} {monday_end_period}"
        if monday_end_hour and monday_end_minute and monday_end_period:
            monday_end = f"{monday_end_hour}:{monday_end_minute} {monday_end_period}"
        else:
            monday_end = " " 

        tue_start_hour = data.get("tue_start_hour")
        numberSelect3 = data.get("numberSelect3")
        tue_start_period = data.get("tue_start_period")
        # tue_start = f"{tue_start_hour}:{numberSelect3} {tue_start_period}"
        if tue_start_hour and numberSelect3 and tue_start_period:
            tue_start = f"{tue_start_hour}:{numberSelect3} {tue_start_period}"
        else:
            tue_start = " " 
        
        tue_end_hour = data.get("tue_end_hour")
        numberSelect4 = data.get("numberSelect4")
        tue_end_period = data.get("tue_end_period")
        # tue_end = f"{tue_end_hour}:{numberSelect4} {tue_end_period}"
        if tue_end_hour and numberSelect4 and tue_end_period:
            tue_end = f"{tue_end_hour}:{numberSelect4} {tue_end_period}"
        else:
            tue_end = " "

        wed_start_hour = data.get("wed_start_hour")
        numberSelect5 = data.get("numberSelect5")
        wed_start_period = data.get("wed_start_period")
        # wed_start = f"{wed_start_hour}:{numberSelect5} {wed_start_period}"
        if wed_start_hour and numberSelect5 and wed_start_period:
            wed_start = f"{wed_start_hour}:{numberSelect5} {wed_start_period}"
        else:
            wed_start = " "
        
        wed_end_hour = data.get("wed_end_hour")
        numberSelect6 = data.get("numberSelect6")
        wed_end_period = data.get("wed_end_period")
        # wed_end = f"{wed_end_hour}:{numberSelect6} {wed_end_period}"
        if wed_end_hour and numberSelect6 and wed_end_period:
            wed_end = f"{wed_end_hour}:{numberSelect6} {wed_end_period}"
        else:
            wed_end = " "

        thur_start_hour = data.get("thur_start_hour")
        numberSelect7 = data.get("numberSelect7")
        thur_start_period = data.get("thur_start_period")
        # thur_start = f"{thur_start_hour}:{numberSelect7} {thur_start_period}"
        if thur_start_hour and numberSelect7 and thur_start_period:
            thur_start = f"{thur_start_hour}:{numberSelect7} {thur_start_period}"
        else:
            thur_start = " "
        
        thur_end_hour = data.get("thur_end_hour")
        numberSelect8 = data.get("numberSelect8")
        thur_end_period = data.get("thur_end_period")
        # thur_end = f"{thur_end_hour}:{numberSelect8} {thur_end_period}"
        if thur_end_hour and numberSelect8 and thur_end_period:
            thur_end = f"{thur_end_hour}:{numberSelect8} {thur_end_period}"
        else:
            thur_end = " "

        fri_start_hour = data.get("fri_start_hour")
        numberSelect9 = data.get("numberSelect9")
        fri_start_period = data.get("fri_start_period")
        # fri_start = f"{fri_start_hour}:{numberSelect9} {fri_start_period}"
        if fri_start_hour and numberSelect9 and fri_start_period:
            fri_start = f"{fri_start_hour}:{numberSelect9} {fri_start_period}"
        else:
            fri_start = " "
        
        fri_end_hour = data.get("fri_end_hour")
        numberSelect10 = data.get("numberSelect10")
        fri_end_period = data.get("fri_end_period")
        # fri_end = f"{fri_end_hour}:{numberSelect10} {fri_end_period}"
        if fri_end_hour and numberSelect10 and fri_end_period:
            fri_end = f"{fri_end_hour}:{numberSelect10} {fri_end_period}"
        else:
            fri_end = " "

        sat_start_hour = data.get("sat_start_hour")
        numberSelect11 = data.get("numberSelect11")
        sat_start_period = data.get("sat_start_period")
        # sat_start = f"{sat_start_hour}:{numberSelect11} {sat_start_period}"
        if sat_start_hour and numberSelect11 and sat_start_period:
            sat_start = f"{sat_start_hour}:{numberSelect11} {sat_start_period}"
        else:
            sat_start = " "
        
        sat_end_hour = data.get("sat_end_hour")
        numberSelect12 = data.get("numberSelect12")
        sat_end_period = data.get("sat_end_period")
        # sat_end = f"{sat_end_hour}:{numberSelect12} {sat_end_period}"
        if sat_end_hour and numberSelect12 and sat_end_period:
            sat_end = f"{sat_end_hour}:{numberSelect12} {sat_end_period}"
        else:
            sat_end = " "

        sun_start_hour = data.get("sun_start_hour")
        numberSelect13 = data.get("numberSelect13")
        sun_start_period = data.get("sun_start_period")
        # sun_start = f"{sun_start_hour}:{numberSelect13} {sun_start_period}"
        if sun_start_hour and numberSelect13 and sun_start_period:
            sun_start = f"{sun_start_hour}:{numberSelect13} {sun_start_period}"
        else:
            sun_start = " "
        
        sun_end_hour = data.get("sun_end_hour")
        numberSelect14 = data.get("numberSelect14")
        sun_end_period = data.get("sun_end_period")        
        # sun_end = f"{sun_end_hour}:{numberSelect14} {sun_end_period}"
        if sun_end_hour and numberSelect14 and sun_end_period:
            sun_end = f"{sun_end_hour}:{numberSelect14} {sun_end_period}"
        else:
            sun_end = " "


        app_status = data.get('app_status',"0")     


        reason = data.get("reason")
        supervisorName = data.get("supervisorName")
        # Save data to the database
        work_from_home_add = WorkFromHome(
            wfh_start_dt=start_date, 
            wfh_end_dt=end_date, 
            req_dt=req_dt, 
            emp_dept=department, 
            emp_id=employee_id, 
            emp_nm=employee_name,
            monst=monday_start,
            moned=monday_end,
            tuest=tue_start,
            tueed=tue_end,
            wedst=wed_start,
            weded=wed_end,
            thust=thur_start,
            thued=thur_end,
            frist=fri_start,  # Corrected field name
            fried=fri_end,    # Corrected field name
            satst=sat_start,
            sated=sat_end,
            sunst=sun_start,
            suned=sun_end,
            resn=reason,
            sup_nm=supervisorName,
            app_status=app_status
        )
        work_from_home_add.save()
        
        return JsonResponse({"message": "Data saved successfully!"})
    else:
        return JsonResponse({"error": "Only POST method allowed"})



@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def wfh_status(request):
    if 'username' in request.session:
        current_user = request.session['username']
        try:
            fetch_data = WorkFromHome.objects.filter(emp_id=current_user).values('id','req_dt','emp_nm','emp_id','emp_dept','emp_desig','wfh_end_dt','wfh_start_dt' ,'monst','moned','tuest','tueed','wedst','weded','thust','thued','frist','fried','satst','sated','sunst','suned','resn','sup_nm','app_status')
            print(f"fetch_data {fetch_data}")
        except RegisterAll.DoesNotExist:
            fetch_data = None
        last_record = Visiters.objects.filter(user=current_user,).order_by('-log_in_dt_tm')[1:2].first()
        if last_record:
            log_in_tm = last_record.log_in_tm
            log_out_tm = last_record.log_out_tm
            log_dt = last_record.log_dt
            log_out_dt = last_record.log_out_dt
            return render(request, 'wfh_status.html', {'current_user': current_user ,
            'log_in_tm': log_in_tm,
            'log_out_tm': log_out_tm,
            'log_dt': log_dt,
            'log_out_dt': log_out_dt, 'fetch_data':fetch_data})
        else:
             return render(request, 'wfh_status.html', {'current_user': current_user ,'fetch_data':fetch_data})
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    # Send data to the template
@csrf_exempt
@require_POST
def delete_wfh(request, id):
    try:
        data = get_object_or_404(WorkFromHome, id=id)
        data.delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)



@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def morning_morning(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        return redirect('loginpage')
    selected_year = request.GET.get('selected_year')
    selected_month = request.GET.get('selected_month')
    attendance_details = Attendance.objects.filter(
        yr=selected_year,
        mnth=selected_month,
        clk_in_tm__gt=F('work_frm')
    ).values('user_id').annotate(record_count=Count('user_id'))
    selected_branch_id = request.session.get('selected_branch_id')
    if selected_branch_id:
        try:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.employee_code[:3]
            selected_branch_admin_code = branch.admin_code[:3]
            selected_branch_trainee_code = branch.trainee_code[:3]
            attendance_details = RegisterAll.objects.exclude(depart='SAD').filter(
                Q(user_id__startswith=selected_branch_employee_code) |
                Q(user_id__startswith=selected_branch_admin_code) |
                Q(user_id__startswith=selected_branch_trainee_code)
            )
            attendance_details = attendance_details.filter(
                Q(user_id__startswith=selected_branch_employee_code) |
                Q(user_id__startswith=selected_branch_admin_code) |
                Q(user_id__startswith=selected_branch_trainee_code)
            )
        except Branch.DoesNotExist:
            return redirect('errorpage')
    return render(request, 'morning_morning.html', { 'branches': branches, 'current_user': current_user ,'default_branch':default_branch})

# def morning_late_report(request):
#     selected_year = request.GET.get('selected_year')
#     selected_month = request.GET.get('selected_month')
#     selected_branch_id = request.session.get('selected_branch_id')
#     if selected_branch_id:
#         try:
#             branch = Branch.objects.get(branch_name=selected_branch_id)
#             selected_branch_employee_code = branch.employee_code[:3]
#             selected_branch_admin_code = branch.admin_code[:3]
#             selected_branch_trainee_code = branch.trainee_code[:3]
#             # Filter attendance details based on selected branch
#             attendance_details = Attendance.objects.filter(
#                 Q(user_id__startswith=selected_branch_employee_code) |
#                 Q(user_id__startswith=selected_branch_admin_code) |
#                 Q(user_id__startswith=selected_branch_trainee_code),
#                 yr=selected_year,
#                 mnth=selected_month,
#                 clk_in_tm__gt=F('work_frm')  # Filter where clock in time is greater than work from time
#             ).values('user_id', 'mnth', 'yr').annotate(record_count=Count('user_id'))
#         except Branch.DoesNotExist:
#             return redirect('errorpage')
#     else:
#         return JsonResponse({'error': 'Selected branch not found'})
#     # Update with additional information from RegisterAll model
#     for entry in attendance_details:
#         user_id = entry['user_id']
#         register_data = RegisterAll.objects.filter(user_id=user_id).first()  # Fetch register data for user
#         if register_data:
#             entry['nm'] = register_data.nm
#         else:
#             entry['nm'] = 'Unknown'
#     # Convert queryset to list for JSON serialization
#     details_list = list(attendance_details)
#     return JsonResponse({'details': details_list})


def morning_late_report(request):
    if 'username' in request.session:
        current_user = request.session.get('username')
        default_branch = request.session.get('default_branch_id')
        select_all = request.session.get('selected_all', False)
        branches = Branch.objects.all()

        if 'selected_branch_id' in request.session:
            selected_branch_id = request.session['selected_branch_id']
        elif default_branch:
            selected_branch_id = default_branch
        else:
            select_all = True

        try:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.employee_code[:3]
            selected_branch_admin_code = branch.admin_code[:3]
            selected_branch_trainee_code = branch.trainee_code[:3]
        except Branch.DoesNotExist:
            return HttpResponse(status=404)

        try:
            branch_default = Branch.objects.get(branch_name=default_branch)
            default_branch_employee_code = branch_default.employee_code[:3]
            default_branch_admin_code = branch_default.admin_code[:3]
            default_branch_trainee_code = branch_default.trainee_code[:3]
        except Branch.DoesNotExist:
            return HttpResponse(status=404)

        selected_year = request.GET.get('selected_year')
        selected_month = request.GET.get('selected_month')

        if 'selected_branch_id' in request.session:
            attendance_details = Attendance.objects.filter(
                Q(user_id__startswith=selected_branch_employee_code) |
                Q(user_id__startswith=selected_branch_admin_code) |
                Q(user_id__startswith=selected_branch_trainee_code),
                yr=selected_year,
                mnth=selected_month,
                clk_in_tm__gt=F('work_frm')
            ).values('user_id', 'mnth', 'yr').annotate(record_count=Count('user_id'))
        elif select_all:
             attendance_details = Attendance.objects.filter(
                yr=selected_year,
                mnth=selected_month,
                clk_in_tm__gt=F('work_frm')
            ).values('user_id', 'mnth', 'yr').annotate(record_count=Count('user_id'))
            
        else:
            attendance_details = Attendance.objects.filter(
                Q(user_id__startswith=default_branch_employee_code) |
                Q(user_id__startswith=default_branch_admin_code) |
                Q(user_id__startswith=default_branch_trainee_code),
                yr=selected_year,
                mnth=selected_month,
                clk_in_tm__gt=F('work_frm')
            ).values('user_id', 'mnth', 'yr').annotate(record_count=Count('user_id'))

        for entry in attendance_details:
            user_id = entry['user_id']
            register_data = RegisterAll.objects.filter(user_id=user_id).first()
            if register_data:
                entry['nm'] = register_data.nm
            else:
                entry['nm'] = 'Unknown'

        details_list = list(attendance_details)
        return JsonResponse({'details': details_list})
    else:
        return redirect('loginpage')


from django.http import JsonResponse
from django.db.models import F
from .models import Attendance
def get_late_days(request):
    user_id = request.GET.get('user_id')
    mnth = request.GET.get('month')
    # Query the database to get the dates and clk_in_tm associated with the user_id
    attendance_data = list(Attendance.objects.filter(user_id=user_id,mnth=mnth, clk_in_tm__gt=F('work_frm')).values('date', 'clk_in_tm', 'work_frm'))
    return JsonResponse({'attendance_data': attendance_data})


from django.db.models import F
def get_early_days(request):
    user_id = request.GET.get('user_id')
    # Query the database to get the dates and clk_in_tm associated with the user_id
    attendance_data = list(Attendance.objects.filter(user_id=user_id, clk_out_tm__lt=F('work_to')).values('date', 'clk_out_tm', 'work_to'))
    return JsonResponse({'attendance_data': attendance_data})

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def early_by_report(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
    else:
        return redirect('loginpage')
    selected_year = request.GET.get('selected_year')
    selected_month = request.GET.get('selected_month')
    attendance_details = Attendance.objects.filter(
        yr=selected_year,
        mnth=selected_month,
        clk_out_tm__lt=F('work_to')
    ).values('user_id').annotate(record_count=Count('user_id'))
    details_list = list(attendance_details)
    selected_branch_id = request.session.get('selected_branch_id')
    if selected_branch_id:
        try:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.employee_code[:3]
            selected_branch_admin_code = branch.admin_code[:3]
            selected_branch_trainee_code = branch.trainee_code[:3]
            leave_requests = RegisterAll.objects.exclude(depart='SAD').filter(
                Q(user_id__startswith=selected_branch_employee_code) |
                Q(user_id__startswith=selected_branch_admin_code) |
                Q(user_id__startswith=selected_branch_trainee_code)
            )
            attendance_details = attendance_details.filter(
                Q(user_id__startswith=selected_branch_employee_code) |
                Q(user_id__startswith=selected_branch_admin_code) |
                Q(user_id__startswith=selected_branch_trainee_code)
            )
        except Branch.DoesNotExist:
            return redirect('errorpage')
    return render(request, 'early_by_report.html', {'branches': branches, 'current_user': current_user ,'default_branch':default_branch})







    
def get_early_days(request):
    user_id = request.GET.get('user_id')
    attendance_data = list(Attendance.objects.filter(user_id=user_id, clk_out_tm__lt=F('work_to')).values('date', 'clk_out_tm', 'work_to'))
    return JsonResponse({'attendance_data': attendance_data})


# def early_by_report_fetch(request):
#     selected_year = request.GET.get('selected_year')
#     selected_month = request.GET.get('selected_month')
#     selected_branch_id = request.session.get('selected_branch_id')
#     if selected_branch_id:
#         try:
#             branch = Branch.objects.get(branch_name=selected_branch_id)
#             selected_branch_employee_code = branch.employee_code[:3]
#             selected_branch_admin_code = branch.admin_code[:3]
#             selected_branch_trainee_code = branch.trainee_code[:3]
#             attendance_details = Attendance.objects.filter(
#                 Q(user_id__startswith=selected_branch_employee_code) |
#                 Q(user_id__startswith=selected_branch_admin_code) |
#                 Q(user_id__startswith=selected_branch_trainee_code),
#                 yr=selected_year,
#                 mnth=selected_month,
#                 clk_out_tm__lt=F('work_to')
#             ).values('user_id', 'mnth', 'yr').annotate(record_count=Count('user_id'))
#         except Branch.DoesNotExist:
#             return JsonResponse({'error': 'Selected branch not found'})
#     else:
#         return JsonResponse({'error': 'Selected branch not found'})
#     for entry in attendance_details:
#         user_id = entry['user_id']
#         register_data = RegisterAll.objects.filter(user_id=user_id).first()
#         if register_data:
#             entry['nm'] = register_data.nm
#         else:
#             entry['nm'] = 'Unknown'
#     details_list = list(attendance_details)
#     return JsonResponse({'details': details_list})

def early_by_report_fetch(request):

    if 'username' in request.session:
        current_user = request.session.get('username')
        default_branch = request.session['default_branch_id']
        select_all = request.session.get('selected_all', False)
        branches = Branch.objects.all()

        # Check if selected_branch_id is in the session
        if 'selected_branch_id' in request.session:
            selected_branch_id = request.session['selected_branch_id']
        elif default_branch:
            selected_branch_id = default_branch  # If not, default to default_branch
        else:
            select_all = True    # If not, default to default_branch

        try:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.employee_code[:3]
            selected_branch_admin_code = branch.admin_code[:3]
            selected_branch_trainee_code = branch.trainee_code[:3]
        except Branch.DoesNotExist:
            return HttpResponse(status=404)
        
        try:
            branch_default = Branch.objects.get(branch_name=default_branch)
            default_branch_employee_code = branch_default.employee_code[:3]
            default_branch_admin_code = branch_default.admin_code[:3]
            default_branch_trainee_code = branch_default.trainee_code[:3]
        except Branch.DoesNotExist:
            return HttpResponse(status=404)
        
        selected_year = request.GET.get('selected_year')
        selected_month = request.GET.get('selected_month')
        selected_branch_id = request.session.get('selected_branch_id')
        
        if 'selected_branch_id' in request.session:
            attendance_details = Attendance.objects.filter(
                Q(user_id__startswith=selected_branch_employee_code) |
                Q(user_id__startswith=selected_branch_admin_code) |
                Q(user_id__startswith=selected_branch_trainee_code),
                yr=selected_year,
                mnth=selected_month,
                clk_out_tm__lt=F('work_to')
            ).values('user_id', 'mnth', 'yr').annotate(record_count=Count('user_id'))
        elif select_all:
            attendance_details = Attendance.objects.filter(
                yr=selected_year,
                mnth=selected_month,
                clk_out_tm__lt=F('work_to')
            ).values('user_id', 'mnth', 'yr').annotate(record_count=Count('user_id'))
            
        else:
            attendance_details = Attendance.objects.filter(
                Q(user_id__startswith=default_branch_employee_code) |
                Q(user_id__startswith=default_branch_admin_code) |
                Q(user_id__startswith=default_branch_trainee_code),
                yr=selected_year,
                mnth=selected_month,
                clk_out_tm__lt=F('work_to')
            ).values('user_id', 'mnth', 'yr').annotate(record_count=Count('user_id'))

            
        
        for entry in attendance_details:
            user_id = entry['user_id']
            register_data = RegisterAll.objects.filter(user_id=user_id).first()
            if register_data:
                entry['nm'] = register_data.nm
            else:
                entry['nm'] = 'Unknown'
        
        details_list = list(attendance_details)
        return JsonResponse({'details': details_list})
    else:
        return redirect('loginpage')





@csrf_exempt
@require_POST
def delete_wfh_report(request, pk):
    try:
        # Assuming your WorkFromHome model has emp_id and req_dt fields
        data = get_object_or_404(WorkFromHome, id=pk)
        data.delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

    

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def add_increment(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()

        # param = {'current_user': user, 'nm_value': nm_value, 'branches': branches}
        # print(f"Current user: {param}")
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request,'add_increment.html', {'current_user': current_user , 'branches':branches ,'default_branch':default_branch})   





@require_POST
@csrf_exempt
def increment_radio(request):
    role = request.POST.get('role')
    selected_all = request.session.get('selected_all')
    data = []

    if selected_all:
        # Fetch all details when selected_all session variable is set
        try:
            if role == 'admin':
                # Fetch data for admin role with depart containing 'ad'
                data = list(RegisterAll.objects.filter(depart__contains='ad').values('user_id', 'nm', 'depart').distinct())
            elif role == 'staff':
                # Fetch data for staff role
                data = list(RegisterAll.objects.filter(depart__contains='emp').values('user_id', 'nm', 'depart').distinct())
            else:
                # Handle other roles or invalid requests
                data = list(RegisterAll.objects.exclude(depart__contains='SAD').values('user_id', 'nm', 'depart').distinct())
                print(f"data {data}")
            return JsonResponse({'data': data})
        except Exception as e:
            return JsonResponse({'error': str(e)})

    selected_branch_id = request.session.get('selected_branch_id', request.session.get('default_branch_id'))

    try:
        if selected_branch_id:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.employee_code[:3]
            selected_branch_admin_code = branch.admin_code[:3]
            selected_branch_trainee_code = branch.trainee_code[:3]
        else:
            raise Branch.DoesNotExist("Branch does not exist")

        if role is None:
            return JsonResponse({'error': 'Role is not provided'})

        if role == 'admin':
            # Fetch data for admin role with depart containing 'ad' and specific branch code
            data = list(RegisterAll.objects.filter(depart__contains='ad', user_id__startswith=selected_branch_admin_code).values('user_id', 'nm', 'depart').distinct())
        elif role == 'staff':
            # Fetch data for staff role with specific branch code
            data = list(RegisterAll.objects.filter(depart__contains='emp', user_id__startswith=selected_branch_employee_code).values('user_id', 'nm', 'depart').distinct())
        else:
            # Handle other roles or invalid requests with specific branch codes
            data = list(RegisterAll.objects.filter(
                Q(user_id__startswith=selected_branch_employee_code) |
                Q(user_id__startswith=selected_branch_admin_code) |
                Q(user_id__startswith=selected_branch_trainee_code)
            ).values('user_id', 'nm', 'depart').distinct())

        return JsonResponse({'data': data})
    except Branch.DoesNotExist:
        return JsonResponse({'error': 'Branch does not exist'})
    except Exception as e:
        return JsonResponse({'error': str(e)})



def get_user_details(request):
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        user_data = AddSalary.objects.filter(user_id=user_id).values('id', 'salary', 'user_id','incre_dt','sal_last')
        print(f"user_data{user_data}")
        return JsonResponse({'user_details': list(user_data)})     
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)


def salary_fetch(request):
    if request.method == 'POST':
        user_id = request.POST.get('user_id')

        # Assuming you have a RegisterAll model with user details
        user = RegisterAll.objects.filter(user_id=user_id).values('id','sala','user_id')
        print(f"user {user}")
        
        return JsonResponse({'user_user': list(user)})     
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)


def check_increment_date(request):
    if request.method == 'POST':
        incrementDate = request.POST.get('incrementDate')
        userID = request.POST.get('userID')

        # Get the last entry's incre_dt value for the given userID
        last_entry = AddSalary.objects.filter(user_id=userID).order_by('-id').first()
        last_entry_incre_dt = last_entry.incre_dt if last_entry else None
        
        print(f"incrementDate: {incrementDate}")
        print(f"last_entry incre_dt: {last_entry_incre_dt}")

        # Check if an entry with userID and incrementDate exists
        if AddSalary.objects.filter(user_id=userID, incre_dt=incrementDate).exists():
            return JsonResponse({'exists': True, 'last_entry_incre_dt': last_entry_incre_dt})
        else:
            return JsonResponse({'exists': False, 'last_entry_incre_dt': last_entry_incre_dt})



@csrf_exempt
def insert_salary(request):
    if request.method == 'POST':
        try:
            # Extract data from the AJAX request
            current_salary = request.POST.get('incrementSalary')
            increment_date = request.POST.get('increment_date')
            basic_salary = request.POST.get('basicSalary')
            hra_salary = request.POST.get('hraSalary')
            conv_all = request.POST.get('convAll')
            medical_all = request.POST.get('medicalAll')
            user_id = request.POST.get('userID')
            actual_salary = request.POST.get('actual_salary')

            # Create a new Salary object and save it to the database
            salary = AddSalary.objects.create(
                salary=current_salary,
                incre_dt=increment_date,
                basic=basic_salary,
                hr=hra_salary,
                conv_all=conv_all,
                medical_all=medical_all,
                spl_all=medical_all,
                sal_last=actual_salary,
                user_id=user_id
            )

            # Update the actual_salary in the registerall table
            RegisterAll.objects.filter(user_id=user_id).update(sala=actual_salary)

            # Return a success response
            return JsonResponse({'status': 'success', 'message': 'Data inserted successfully and actual_salary updated'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    else:
        # Return an error response if the request method is not POST
        return JsonResponse({'status': 'error', 'message': 'Only POST requests are allowed'})



from django.db import transaction

@csrf_exempt
def delete_salary_record(request):
    if request.method == 'POST':
        user_id = request.POST.get('user_id')  # Retrieve user ID from POST data
        print(f"user_id sgbdfh {user_id}")
        try:
            with transaction.atomic():
                user = AddSalary.objects.get(id=user_id)  # Get user object by ID
                salary = user.salary  # Retrieve salary value
                print(f"salary {salary}")
                user_id = user.user_id  # Retrieve user ID from AddSalary model
                print(f"user_id sgghffgfbdfh {user_id}")
                user.delete()  # Delete the user

                # Update sala value in registerall table for the specific user
                RegisterAll.objects.filter(user_id=user_id).update(sala=F('sala') - salary)

                return JsonResponse({'success': True})  # Return success response
        except AddSalary.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'User does not exist'})  # User not found error
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})  # Other errors
    else:
        return JsonResponse({'success': False, 'error': 'Invalid request method'})  # Invalid request method error





@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def increament_report(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()

        # param = {'current_user': user, 'nm_value': nm_value, 'branches': branches}
        # print(f"Current user: {param}")
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request,'increament_report.html', {'current_user': current_user , 'branches':branches ,'default_branch':default_branch})   




def increament_report_month_year(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session.get('default_branch_id')
        branches = Branch.objects.all()
        
        selected_branch_id = request.session.get('selected_branch_id', default_branch)

        # Check if 'selected_all' is set in the session
        selected_all = request.session.get('selected_all', False)
        selected_year = request.GET.get('selected_year')
        selected_month = request.GET.get('selected_month')

        # Initialize data_list variable
        data_list = []

        try:
            if selected_all:
                # Fetch details for all branches
                data = AddSalary.objects.filter(
                    incre_dt__year=selected_year,
                    incre_dt__month=selected_month
                ).values('user_id', 'sal_last', 'incre_dt', 'salary', 'id')
            else:
                # If selected_branch_id is not present or invalid, return error response
                if not selected_branch_id:
                    return HttpResponse(status=404)

                branch = Branch.objects.get(branch_name=selected_branch_id)
                selected_branch_employee_code = branch.employee_code[:3]
                selected_branch_admin_code = branch.admin_code[:3]
                selected_branch_trainee_code = branch.trainee_code[:3]

                # Filter data based on branch and selected year/month
                data = AddSalary.objects.filter(
                    (Q(user_id__startswith=selected_branch_employee_code) |
                     Q(user_id__startswith=selected_branch_admin_code) |
                     Q(user_id__startswith=selected_branch_trainee_code)) &
                    Q(incre_dt__year=selected_year, incre_dt__month=selected_month)
                ).values('user_id', 'sal_last', 'incre_dt', 'salary', 'id')

            # Convert the QuerySet to a list to be sent as JSON
            data_list = list(data)

        except Branch.DoesNotExist:
            # Handle the case when the selected branch does not exist
            return redirect('errorpage')

    return JsonResponse(data_list, safe=False)

def increament_report_year(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session.get('default_branch_id')
        branches = Branch.objects.all()
        
        selected_branch_id = request.session.get('selected_branch_id', default_branch)

        # Check if 'selected_all' is set in the session
        selected_all = request.session.get('selected_all', False)
        
        selected_year = request.GET.get('selected_year')
        # Initialize data_list variable
        data_list = []
        
        try:
            if selected_all:
                # Fetch details for all branches
                data = AddSalary.objects.filter(
                    incre_dt__year=selected_year
                ).values('user_id', 'sal_last', 'incre_dt', 'salary', 'id')
            else:
                # If selected_branch_id is not present or invalid, return error response
                if not selected_branch_id:
                    return HttpResponse(status=404)

                branch = Branch.objects.get(branch_name=selected_branch_id)
                selected_branch_employee_code = branch.employee_code[:3]
                selected_branch_admin_code = branch.admin_code[:3]
                selected_branch_trainee_code = branch.trainee_code[:3]

                # Filter data based on branch and selected year/month
                data = AddSalary.objects.filter(
                    Q(user_id__startswith=selected_branch_employee_code) |
                    Q(user_id__startswith=selected_branch_admin_code) |
                    Q(user_id__startswith=selected_branch_trainee_code),
                    incre_dt__year=selected_year
                ).values('user_id', 'sal_last', 'incre_dt', 'salary', 'id')

            # Convert the QuerySet to a list to be sent as JSON
            data_list = list(data)

        except Branch.DoesNotExist:
            # Handle the case when the selected branch does not exist
            return redirect('errorpage')

        return JsonResponse(data_list, safe=False)
    else:
        # Handle the case when the user is not logged in
        return HttpResponse(status=401)


    
def employee_userid(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session.get('default_branch_id')
        branches = Branch.objects.all()
        
        selected_branch_id = request.session.get('selected_branch_id', default_branch)

        # Check if 'selected_all' is set in the session
        selected_all = request.session.get('selected_all', False)
        

        # Initialize data_list variable
        user_id_nm_list = []

        try:
            if selected_all:
                # Fetch details for all branches
                data = AddSalary.objects.values_list('user_id', flat=True)
                user_id_nm_list = []
                for user_id in data:
                    nm = RegisterAll.objects.filter(user_id=user_id).values_list('nm', flat=True).first()
                    if nm is not None:
                        user_id_nm_list.append({'user_id': user_id, 'nm': nm})
            else:
                # If selected_branch_id is not present or invalid, return error response
                if not selected_branch_id:
                    return HttpResponse(status=404)

                branch = Branch.objects.get(branch_name=selected_branch_id)
                selected_branch_employee_code = branch.employee_code[:3]
                selected_branch_admin_code = branch.admin_code[:3]
                selected_branch_trainee_code = branch.trainee_code[:3]

                # Filter data based on branch and selected year/month
                data = AddSalary.objects.filter(
                    Q(user_id__startswith=selected_branch_employee_code) |
                    Q(user_id__startswith=selected_branch_admin_code) |
                    Q(user_id__startswith=selected_branch_trainee_code)
                ).values_list('user_id', flat=True)
                user_id_nm_list = []
                for user_id in data:
                    nm = RegisterAll.objects.filter(user_id=user_id).values_list('nm', flat=True).first()
                    if nm is not None:
                        user_id_nm_list.append({'user_id': user_id, 'nm': nm})

           

        except Branch.DoesNotExist:
            # Handle the case when the selected branch does not exist
            return redirect('errorpage')  # Changed to HttpResponseRedirect

        return JsonResponse(user_id_nm_list, safe=False)
    else:
        # Handle the case when the user is not logged in
        return HttpResponse(status=401)

   
    
def employee_details(request, user_id):
    employees = AddSalary.objects.filter(user_id=user_id)
    employee_details_list = []
    for employee in employees:
        employee_details = {
            'id': employee.id,
            'user_id': employee.user_id,
            'sal_last': employee.sal_last,
            'incre_dt': employee.incre_dt,
            'salary': employee.salary,
        }
        employee_details_list.append(employee_details)
    return JsonResponse(employee_details_list, safe=False)

# def delete_increament_report(request, id):
#     data = AddSalary.objects.get(id=id)
#     data.delete()
#     messages.error(request,"Deleted successsfully!!")
#     return redirect('increament_report')

def fetch_status(request):
    enable_obj, _ = Enable.objects.get_or_create()
    status = enable_obj.status
    return JsonResponse({"status": status})

def enable_disable_view(request):
    if request.method == "POST":
        action = request.POST.get("action")
        print(f"action {action}")
        if action == "enable":
            # Assuming you have a model called Enable with a field named status
            enable_obj, created = Enable.objects.get_or_create()
            enable_obj.status = "enabled"
            enable_obj.save()
            return JsonResponse({"status": "success"})
        elif action == "disable":
            enable_obj, created = Enable.objects.get_or_create()
            enable_obj.status = "disabled"
            enable_obj.save()
            return JsonResponse({"status": "success"})
    return JsonResponse({"status": "error"}, status=400)



#total emp permission report

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def total_employee_permission_report(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()
        selected_branch_id = request.session.get('selected_branch_id', default_branch)
        # Check if 'selected_all' is set in the session
        selected_all = request.session.get('selected_all', False)
        # If selected_all is True, fetch details for all branches
        if selected_all:
            leave_requests = RegisterAll.objects.exclude(depart="SAD").values()
        else:
            # If selected_branch_id is not present, return error response
            if not selected_branch_id:
                return HttpResponse(status=404)
            try:
                branch = Branch.objects.get(branch_name=selected_branch_id)
                selected_branch_employee_code = branch.employee_code[:3]
                selected_branch_admin_code = branch.admin_code[:3]
                selected_branch_trainee_code = branch.trainee_code[:3]
                # Fetch leave requests where bk_attendance date is the current date
                leave_requests = RegisterAll.objects.exclude(depart='SAD').filter(
                    Q(user_id__startswith=selected_branch_employee_code) |
                    Q(user_id__startswith=selected_branch_admin_code) |
                    Q(user_id__startswith=selected_branch_trainee_code)
                )
            except Branch.DoesNotExist:
                # Handle the case when the selected branch does not exist
                return redirect('errorpage')  # Redirect to an error page or handle as required
        # Query all records from RegisterAll model
        print(f"leave_requests {leave_requests}")
        # Send data to the template
        return render(request, 'total_employee_permission_report.html', {'current_user': current_user, 'leave_requests': leave_requests, 'branches': branches, 'default_branch': default_branch})
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')
# views.py
from django.http import JsonResponse, HttpResponse
from django.shortcuts import redirect
from django.db.models import Q
from .models import PermissionAdd, Branch
def total_per_fetch(request):
    selected_year = request.GET.get('selected_year')
    selected_month = request.GET.get('selected_month')
    if 'username' in request.session:
        current_user = request.session.get('username')
        default_branch = request.session.get('default_branch_id')
        select_all = request.session.get('selected_all', False)
        branches = Branch.objects.all()
        if 'selected_branch_id' in request.session:
            selected_branch_id = request.session['selected_branch_id']
        elif default_branch:
            selected_branch_id = default_branch
        else:
            select_all = True
        try:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.employee_code[:3]
            selected_branch_admin_code = branch.admin_code[:3]
            selected_branch_trainee_code = branch.trainee_code[:3]
        except Branch.DoesNotExist:
            return HttpResponse(status=404)
        try:
            branch_default = Branch.objects.get(branch_name=default_branch)
            default_branch_employee_code = branch_default.employee_code[:3]
            default_branch_admin_code = branch_default.admin_code[:3]
            default_branch_trainee_code = branch_default.trainee_code[:3]
        except Branch.DoesNotExist:
            return HttpResponse(status=404)
        # Check if year and month are provided
        if selected_year is None or selected_month is None:
            return HttpResponse("Year and month are required parameters", status=400)
        try:
            attendance_details = PermissionAdd.objects.filter(
                Q(user_id__startswith=selected_branch_employee_code) |
                Q(user_id__startswith=selected_branch_admin_code) |
                Q(user_id__startswith=selected_branch_trainee_code),
                permi_dt__year=selected_year,
                permi_dt__month=selected_month
            ).values(
                'name',
                'permi_hr',
                'permi_frm',
                'permi_dt',
                'resn',
                'permi_tm_start_am',
                'permi_tm_end_am',
                'id',
                'user_id'
            )
            data_list = list(attendance_details)
            return JsonResponse(data_list, safe=False)
        except PermissionAdd.DoesNotExist:
            return HttpResponse(status=404)
    else:
        return HttpResponse(status=401)
    
def delete_totalemployee(request,id):
     data = PermissionAdd.objects.get(id=id)
     data.delete()
     return redirect('total_employee_permission_report')



@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def add_loan_emp(request):
    if 'username' in request.session:
        current_user = request.session['username']

        # param = {'current_user': user, 'nm_value': nm_value, 'branches': branches}
        # print(f"Current user: {param}")
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request,'add_loan_emp.html', {'current_user': current_user})


def insert_loan_record(request):
    if request.method == 'POST':
        # Extract fields from the requestData
        user_id = request.POST.get('userID')
        name = request.POST.get('userName')
        req_date = request.POST.get('loanDate')
        loan_amount = request.POST.get('loanAmount')
        status = request.POST.get('status')

        # Check if a loan record with the same req_date already exists
        if AddLoan.objects.filter(Q(user_id=user_id) & Q(req_date=req_date)).exists():
            return JsonResponse({'error': 'A loan record with the same date already exists'}, status=400)

        # Create and save the AddLoan instance
        add_loan_instance = AddLoan(
            user_id=user_id,
            name=name,
            req_date=req_date,
            loan_amount=loan_amount,
            status=status
        )
        add_loan_instance.save()

        # Respond with a success message
        return JsonResponse({'message': 'Loan record inserted successfully'}, status=200)
    else:
        # If not a POST request, respond with an error message
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)
    
def fetch_loan_records(request):
    if request.method == 'GET':
        # Extract userId from the request parameters
        userId = request.GET.get('userId')

        # Fetch records from AddLoan model where user_id matches userId
        loan_records = list(AddLoan.objects.filter(user_id=userId).values())

        # Respond with fetched records
        return JsonResponse({'loan_records': loan_records}, status=200)
    else:
        # If not a GET request, respond with an error message
        return JsonResponse({'error': 'Only GET requests are allowed'}, status=405)

def delete_loan_record(request):
    if request.method == 'POST':
        # Get the ID of the loan record to be deleted from the request data
        loan_id = request.POST.get('id')

        try:
            # Try to retrieve the loan record
            loan_record = AddLoan.objects.get(id=loan_id)
            # Delete the record
            loan_record.delete()
            return JsonResponse({'message': 'Loan record deleted successfully'}, status=200)
        except AddLoan.DoesNotExist:
            return JsonResponse({'error': 'Loan record not found'}, status=404)
    else:
        # If not a POST request, respond with an error message
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def add_loan_admin(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()

        # param = {'current_user': user, 'nm_value': nm_value, 'branches': branches}
        # print(f"Current user: {param}")
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request,'add_loan_admin.html', {'current_user': current_user , 'branches':branches ,'default_branch':default_branch}) 


def get_user_loan_records(request):
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        user_data = AddLoan.objects.filter(user_id=user_id).values('id', 'loan_amount', 'name','req_date','status','user_id')
        print(f"user_data{user_data}")
        return JsonResponse({'user_details': list(user_data)})     
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def update_sts_add_loan(request):
    if request.method == 'POST':
        emp_id = request.POST.get('emp_id')
        selected_status = request.POST.get('status')
        print(f'selected_status :{selected_status}')
        req_date = request.POST.get('req_date')
        print(f'req_date :{req_date}')
        print(f'emp_id :{emp_id}')
        # selected_month = request.POST.get('selected_month')
        # Update the sts field in the PayrollMaathangi model
        try:
            loan_record = AddLoan.objects.get(user_id=emp_id,req_date=req_date)
            loan_record.status = selected_status
            loan_record.save()
            return JsonResponse({'success': True})
        except AddLoan.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Record not found'})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@department_required('SAD')
def loan_report_admin(request):
    if 'username' in request.session:
        current_user = request.session['username']
        default_branch = request.session['default_branch_id']
        branches = Branch.objects.all()

        # param = {'current_user': user, 'nm_value': nm_value, 'branches': branches}
        # print(f"Current user: {param}")
    else:
        # Handle the case when the user is not logged in
        return redirect('loginpage')  # You can set it to None or any default value
    return render(request,'loan_report_admin.html', {'current_user': current_user , 'branches':branches ,'default_branch':default_branch})    


@require_GET
def loan_report_fetch(request):
    # Get the selected year and month from the request
    selected_year = request.GET.get('selected_year')
    selected_month = request.GET.get('selected_month')

    if 'selected_branch_id' in request.session and request.session['selected_branch_id']:
        selected_branch_id = request.session['selected_branch_id']
    elif 'selected_all' in request.session:
        select_all = request.session['selected_all']
    else:
        selected_branch_id = request.session.get('default_branch_id')  # If 'selected_branch_id' is empty, default to 'default_branch_id'

    if 'selected_branch_id' in locals() or 'selected_branch_id' in globals():
        try:
            branch = Branch.objects.get(branch_name=selected_branch_id)
            selected_branch_employee_code = branch.employee_code[:3]
            selected_branch_admin_code = branch.admin_code[:3]
            selected_branch_trainee_code = branch.trainee_code[:3]
            # Use Q objects to combine multiple conditions
            records = AddLoan.objects.filter(
                Q(req_date__year=selected_year, req_date__month=selected_month) &
                (Q(user_id__startswith=selected_branch_employee_code) |
                 Q(user_id__startswith=selected_branch_admin_code) |
                 Q(user_id__startswith=selected_branch_trainee_code))
            ).values(
                
                'name',
                'id',
                'user_id',
                'req_date',
                'loan_amount',
                'status',
                
            )
        except Branch.DoesNotExist:
            # Handle the case when the branch does not exist
            return JsonResponse({'error': 'Selected branch does not exist'}, status=400)

    elif 'select_all' in locals() or 'select_all' in globals():
        try:
            records = AddLoan.objects.filter(
                req_date__year=selected_year,
                req_date__month=selected_month
            ).values(
               
                'name',
                'id',
                'user_id',
                'req_date',
                'loan_amount',
                'status',
               
            )
        except AddLoan.DoesNotExist:
            # Handle the case when records do not exist
            return JsonResponse({'error': 'Records do not exist'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)

    # Convert the queryset to a list for JSON serialization
    records_list = list(records)
    return JsonResponse(records_list, safe=False)




def add_clock_in(request):
    if request.method == 'POST':
        branch = request.POST.get('branch')
        user_id = request.POST.get('user_id')
        value = request.POST.get('value')
        print(f"value {value}")

        # Perform validation if needed

        # Check if user_id and usid are the same, if so, update usid
        existing_clock_in = AddClockin.objects.filter(usid=user_id).first()
        print(f"existing_clock_in {existing_clock_in}")
        if existing_clock_in:
            existing_clock_in.branch = branch
            existing_clock_in.status = value
            existing_clock_in.save()
            return JsonResponse({'message': 'Clock in updated successfully.'})
        else:
            # Insert data into the AddClockIn model
            clock_in = AddClockin(branch=branch, usid=user_id, status=value)
            clock_in.save()
            return JsonResponse({'message': 'Clock in added successfully.'})
    else:
        return JsonResponse({'error': 'Invalid request method.'}, status=400)
    


