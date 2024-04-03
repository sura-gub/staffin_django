# decorators.py
from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages

def department_required(department):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            user_department = request.session.get('depart')
            if user_department == department:
                return view_func(request, *args, **kwargs)
            else:
               messages.error(request, 'Permission Denied.')

               return redirect('loginpage')  # Redirect to login or another appropriate page
        return wrapper
    return decorator
