from telnetlib import LOGOUT
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import RegisterAll
from .models import RegisterAll,Branch,AddDepartment,AddDepartmentHead,Attendance,PayrollMaathangi,EmpLeaves,WorkFromHome,Visiters,AddPermission,PermissionAdd,ExcelToDB,Holiday,AttnNotes
from django.views.decorators.http import require_GET
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.db.models import Count
from django.views.decorators.cache import cache_control


def LoginPage(request):
    # if 'depart' in request.session:
    #     # Retrieve the department from the session
    #     depart = request.session.get('depart')
    #     # Redirect based on the 'depart' value
    #     if depart == 'ad':
    #         return redirect('index_admin')
    #     elif depart == 'ads':
    #         return redirect('index_administrator')
    #     elif depart == 'emp':
    #         return redirect('index_emp')
    #     elif depart == 'hr':
    #         return redirect('index_hr')
    #     else:
    #         # Handle other departments if needed
    #         return redirect('loginpage')
    # Step 1: Retrieve the current date
    current_date = datetime.now().date()
    print(f"current_date:{current_date}")
    # Step 2: Check the "registerall" table for users with the same DOB as the current date
    users_with_birthday = RegisterAll.objects.filter(dob__month=current_date.month, dob__day=current_date.day)
    print(f"users_with_birthday: {users_with_birthday}")
    # Assuming you want to pass the current user to the template
    return render(request, 'loginpage.html', { 'users_with_birthday': users_with_birthday})