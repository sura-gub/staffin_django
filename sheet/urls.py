from django.contrib import admin
from django.urls import path
from sheet import views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.LoginPage, name='loginpage'),
    path('get_nm/', views.get_nm, name='get_nm'),



    path('index_administrator/', views.indexadministrator, name='index_administrator'),
    path('index_hr/', views.indexhr, name='index_hr'),
    path('index_emp/', views.indexemp, name='index_emp'),
    

    path('changepass/', views.changepass, name='changepass'),
    path('index_admin/', views.indexadmin, name='index_admin'),
    path('employee_admin/', views.employee_admin, name='employee_admin'),
    path('employee_view/', views.employee_view, name='employee_view'),
    path('login_user/', views.login_user, name='login_user'),
    path('change_password/', views.change_password, name='change_password'),

    path('change_password_emp/', views.change_password_emp, name='change_password_emp'),
    path('changepass_emp/', views.changepass_emp, name='changepass_emp'),

    path('change_password_adm/', views.change_password_adm, name='change_password_adm'),
    path('changepass_adm/', views.changepass_adm, name='changepass_adm'),
  


    path('logout_view/', views.logout_view, name='logout_view'),   
    path('logout/', views.logout, name='logout'),   

    path('register_admin/', views.register_admin, name='register_admin'),
    path('add_branch/', views.add_branch, name='add_branch'),
    path('update_branch/<int:id>/',views.update_branch,name='update_branch'),

    path('add_depart/', views.add_depart, name='add_depart'),
   path('update_department/<int:department_id>/', views.update_department, name='update_department'),
   path('check_existence/', views.check_existence_view, name='check_existence'),

    path('delete_depart/<int:id>/', views.delete_depart, name='delete_depart'),
    path('departmenthead/', views.departmenthead, name='departmenthead'),
    path('get_department_names/', views.get_department_names, name='get_department_names'),


    path('get_branch_names1/', views.get_branch_names1, name='get_branch_names1'),


    path('update_department_head/<int:id>/', views.update_department_head, name='update_department_head'),   


    path('delete/<int:id>',views.delete,name='delete'),
    path('delete_branch/<int:id>',views.delete_branch,name='delete_branch'),
    path('empinsert/', views.empinsert, name='empinsert'),
    path('get_companies/', views.get_companies, name='get_companies'),
    path('get_department/', views.get_department, name='get_department'),  
    path('get_department_info/', views.get_department_info, name='get_department_info'),   
    path('get_employee_codes_by_company/', views.get_employee_codes_by_company, name='get_employee_codes_by_company'),
    path('get_admin_codes_by_company/', views.get_admin_codes_by_company, name='get_admin_codes_by_company'),
    path('get_office_number/', views.get_office_number, name='get_office_number'),

path('get_branch_name/', views.get_branch_name, name='get_branch_name'),


    path('admininsert/', views.admininsert, name='admininsert'),
    path('traniee_admin/', views.traniee_admin, name='traniee_admin'),
    path('trainee_insert/', views.trainee_insert, name='trainee_insert'),
    path('get_trainee_codes_by_company/', views.get_trainee_codes_by_company, name='get_trainee_codes_by_company'),
    path('delete_emp/<int:id>/', views.delete_emp, name='delete_emp'),
    path('admin_view/', views.admin_view, name='admin_view'),
    path('delete_ad/<int:id>/', views.delete_ad, name='delete_ad'),
    path('trainee_view/', views.trainee_view, name='trainee_view'),
    path('delete_tr/<int:id>/', views.delete_tr, name='delete_tr'),
    path('add_attendance/', views.add_attendance, name='add_attendance'),
    path('fetch_branch/', views.fetch_branch, name='fetch_branch'),
    path('fetch_employee_data/', views.fetch_employee_data, name='fetch_employee_data'),

    path('insert_attendance_data/', views.insert_attendance_data, name='insert_attendance_data'),
     path('insert_attendance_time/', views.insert_attendance_time, name='insert_attendance_time'),
    path('insert_attendance_mng/', views.insert_attendance_mng, name='insert_attendance_mng'),
    path('insert_attendance_evg/', views.insert_attendance_evg, name='insert_attendance_evg'),

    # Admin Update 
    path('get_admin_details/<int:admin_id>/', views.get_admin_details, name='get_admin_details'),
    path('update_admin_details/<int:admin_id>/', views.update_admin_details, name='update_admin_details'),

    # Employee Update
    path('get_employee_details/<int:employee_id>/', views.get_employee_details, name='get_employee_details'),
    path('update_employee_details/<int:employee_id>/', views.update_employee_details, name='update_employee_details'),
    path('fetch_employee_details_pdf/<int:employee_id>/', views.fetch_employee_details_pdf, name='fetch_employee_details_pdf'),

    # Trainee Update
    path('get_trainee_details/<int:trainee_id>/', views.get_trainee_details, name='get_trainee_details'),
    path('update_trainee_details/<int:trainee_id>/', views.update_trainee_details, name='update_employee_details'),


path('birthday_report/',views.birthday_report, name='birthday_report'),
 path('birthday_report_fetch/',views.birthday_report_fetch, name='birthday_report_fetch'),

path('anniversary_report/',views.anniversary_report, name='anniversary_report'),
  path('anniversary_report_fetch/',views.anniversary_report_fetch, name='anniversary_report_fetch'),
 
#empwise_ attendance
 path('empwise/', views.empwise, name='empwise'),
 
path('fetch_data_radio/', views.fetch_data_radio, name='fetch_data_radio'),
path('fetch_attendance/', views.fetch_attendance, name='fetch_attendance'),
path('add_permission/', views.add_permission, name='add_permission'),
path('add_permission1/', views.add_permission1, name='add_permission1'),
path('permission_report/', views.permission_report, name='permission_report'),
 path('delete_permission_record/<int:id>/', views.delete_permission_record, name='delete_permission_record'),
 path('delete_permission_record1/<int:id>/', views.delete_permission_record1, name='delete_permission_record1'),


path('late_report/', views.late_report, name='late_report'),
path('edit_attendance/<str:formatted_date>/', views.edit_attendance, name='edit_attendance'),
path('fetch_user_data/', views.fetch_user_data, name='fetch_user_data'),
path('fetch_halflop/', views.fetch_halflop, name='fetch_halflop'),
path('fetch_od/', views.fetch_od, name='fetch_od'),
path('fetch_cl/', views.fetch_cl, name='fetch_cl'),
path('fetch_halfcl/', views.fetch_halfcl, name='fetch_halfcl'),
path('fetch_halfod/', views.fetch_halfod, name='fetch_halfod'),
path('fetch_holiday/', views.fetch_holiday, name='fetch_holiday'),


  #Salary Calculation
  path('salary_calculation/', views.salary_calculation, name='salary_calculation'),



#salary report
path('salary_report/', views.salary_report, name='salary_report'),
 path('salary_report_retrive/', views.salary_report_retrive, name='salary_report_retrive'),
 path('fetch_all_staff_records/', views.fetch_all_staff_records, name='fetch_all_staff_records'),
 path('fetch_all_staff_records_yearly/', views.fetch_all_staff_records_yearly, name='fetch_all_staff_records_yearly'),

path('add_in_out/', views.add_in_out, name='add_in_out'),
path('fetch_work_schedule/', views.fetch_work_schedule, name='fetch_work_schedule'),
path('delete_record/<int:record_id>/', views.delete_record, name='delete_record'),
path('delete_delete/<int:record_id>/', views.delete_delete, name='delete_delete'),



#salary_approval
path('salary_approval/', views.salary_approval, name='salary_approval'),
path('salary_approval_fetch/', views.salary_approval_fetch, name='salary_approval_fetch'),
path('update_sts/', views.update_sts, name='update_sts'),

#leave_status
 path('leave_status/', views.leave_status, name='leave_status'),
path('leavefetch/', views.leavefetch, name='leavefetch'),
 path('leavedelete/<int:item_id>/', views.leavedelete, name='leavedelete'),

#add_leave
path('add_leave/', views.add_leave, name='add_leave'),
path('leave_insert/', views.leave_insert, name='leave_insert'),
path('emp_leaves_data/',views.emp_leaves_data, name='emp_leaves_data'),
 path('empployee_leave_fetch/',views.empployee_leave_fetch, name='empployee_leave_fetch'),
 path('delete_add_leave_record/<int:id>/', views.delete_add_leave_record, name='delete_add_leave_record'),

 #work_from_home_report
  path('work_from_home_report/', views.work_from_home_report, name='work_from_home_report'),
  path('work_from_home_report_retrieve/', views.work_from_home_report_retrieve, name='work_from_home_report_retrieve'),
  path('update_report/', views.update_report, name='update_report'),


  path('delete_wfh_report/<str:pk>/', views.delete_wfh_report, name='delete_wfh_report'),


   #VISITORS
  path('visiters/', views.visiters, name='visiters'),
  path('visiters_report/', views.visiters_report, name='visiters_report'),

  #Excel to Databse
  path('excel_to_db/', views.excel_to_db, name='excel_to_db'),

    #set_holiday
  path('set_holiday/', views.set_holiday, name='set_holiday'),
  path('update_holidays/', views.update_holidays, name='update_holidays'),
  path('get_branch_names/', views.get_branch_names, name='get_branch_names'),
  path('get_all_holidays/', views.get_all_holidays, name='get_all_holidays'),
  path('delete_holiday/<int:id>/', views.delete_holiday, name='delete_holiday'),
  path('check_date_exists/', views.check_date_exists, name='check_date_exists'),


#Employee leave report
path('employe_leave_report/', views.employe_leave_report, name='employe_leave_report'),
    path('empreport_fetch/', views.empreport_fetch, name='empreport_fetch'),
  path('empport_fetch/<str:user_id>/', views.empport_fetch, name='empport_fetch'),
path('update_stss/', views.update_stss, name='update_stss'),
path('emort_fetch/', views.emort_fetch, name='emort_fetch'),

 path('update_status/<int:leave_id>/', views.update_status, name='update_status'),

#Employee Attendance page
path('attendance/', views.attendance, name='attendance'),  

path('save_notes/', views.save_notes, name='save_notes'),  
path('retrieve_notes/', views.retrieve_notes, name='retrieve_notes'),


#profile for employee
path('date_profile/<int:user_profile>/', views.date_profile, name='date_profile'),
  path('profile/', views.profile, name='profile'),



path('apply_leave/', views.apply_leave, name='apply_leave'),  
path('submit_leave/', views.submit_leave, name='submit_leave'),
path('delete_leave/<int:id>', views.delete_leave, name='delete_leave'),

  #Emplaoyee Attendance
  #Salary Status
  path('salary_status/', views.salary_status, name='salary_status'),
  path('salary_status_fetch/', views.salary_status_fetch, name='salary_status_fetch'),
  path('employee_detail_fetch/', views.employee_detail_fetch, name='employee_detail_fetch'),
  path('employee_salary_record_fetch/', views.employee_salary_record_fetch, name='employee_salary_record_fetch'),


path('process_selected_branch/', views.process_selected_branch, name='process_selected_branch'),


path('profile/update_user_details', views.update_user_details, name='update_user_details'),

#trainee userid  fetch
path('employee_admin/trainee_userid/', views.trainee_userid, name='trainee_userid'),

path('employee_admin/trainee_details/<str:user_id>/', views.fetch_trainee_details, name='fetch_trainee_details'),


#Permission Report
path('permission_report1/', views.permission_report1, name='permission_report1'),
path('permission_report_fetch/', views.permission_report_fetch, name='permission_report_fetch'),

#salary calculation
path('fetch_salary_att_data/', views.fetch_salary_att_data, name='fetch_salary_att_data'),
path('fetch_salary_leave_data/', views.fetch_salary_leave_data, name='fetch_salary_leave_data'),
path('fetch_salary_cl_data/', views.fetch_salary_cl_data, name='fetch_salary_cl_data'),
path('fetch_salary_od_data/', views.fetch_salary_od_data, name='fetch_salary_od_data'),
path('fetch_salary_holiday_data/', views.fetch_salary_holiday_data, name='fetch_salary_holiday_data'),
path('fetch_salary_halfod_data/', views.fetch_salary_halfod_data, name='fetch_salary_halfod_data'),
path('fetch_salary_halfcl_data/', views.fetch_salary_halfcl_data, name='fetch_salary_halfcl_data'),
path('fetch_salary_halflop_data/', views.fetch_salary_halflop_data, name='fetch_salary_halflop_data'),

 path('generate_salary/', views.generate_salary, name='generate_salary'),
path('check_user_id/', views.check_user_id, name='check_user_id'),

 path('employee_payrollmathangi_record/', views.employee_payrollmathangi_record, name='employee_payrollmathangi_record'),
 path('employee_detail_registerall/', views.employee_detail_registerall, name='employee_detail_registerall'),

path('delete_employee_payrollmathangi_record/<int:id>/', views.delete_employee_payrollmathangi_record, name='delete_employee_payrollmathangi_record'),

path('print_id/', views.print_id, name='print_id'),
path('fetch_user_details', views.fetch_user_details, name='fetch_user_details'),
path('update_data/', views.update_data, name='update_data'),
path('download_file/', views.download_file, name='download_file'),


path('check_salary/', views.check_salary, name='check_salary'),

path('fetch_month_year_record_payrollmathangi/', views.fetch_month_year_record_payrollmathangi, name='fetch_month_year_record_payrollmathangi'),


path('add_location/', views.add_location, name='add_location'),
path('add_department_again/', views.add_department_again, name='add_department_again'),
path('department_head/', views.department_head, name='department_head'),
path('validate_employee_id/', views.validate_employee_id, name='validate_employee_id'),
path('validate_employee_id1/', views.validate_employee_id1, name='validate_employee_id1'),

#salary_increment
path('add_salary_increment/', views.add_salary_increment, name='add_salary_increment'),
path('fetch_salary_increment/', views.fetch_salary_increment, name='fetch_salary_increment'),
path('fetch_locations/', views.fetch_locations, name='fetch_locations'),
# path('display_location/', views.display_location, name='display_location'),

path('location/', views.location, name='location'),
# path('update_location/<int:location_id>/', views.update_location, name='update_location'),
    path('delete_location/<int:location_id>/', views.delete_location, name='delete_location'),

    #wallpaper
    path('wallpaper/', views.wallpaper, name='wallpaper'),
    path('upload_wallpaper/', views.upload_wallpaper, name='upload_wallpaper'),
    path('display_last_image/', views.display_last_image, name='display_last_image'),
    path('delete_last_image/', views.delete_last_image, name='delete_last_image'),

    #footer
    path('footer/', views.footer, name='footer'),
   
path('get_branch_options/', views.get_branch_options, name='get_branch_options'),
 path('get_department_head/', views.get_department_head, name='get_department_head'),
 path('get_department_tl/', views.get_department_tl, name='get_department_tl'),

path('admin_view_details/<int:admin_id>/', views.admin_view_details, name='admin_view_details'),
path('save_view_admin_details/', views.save_view_admin_details, name='save_view_admin_details'),

path('employee_view_details/<int:employee_id>/', views.employee_view_details, name='employee_view_details'),
path('save_view_employee_details/', views.save_view_employee_details, name='save_view_employee_details'),

path('trainee_view_details/<int:trainee_id>/', views.trainee_view_details, name='trainee_view_details'),
path('save_view_trainee_details/', views.save_view_trainee_details, name='save_view_trainee_details'),



#user id check
path('check_trainee_id/', views.check_trainee_id, name='check_trainee_id'),
path('check_same_department/', views.check_same_department, name='check_same_department'),

#today_report
path('today_report/', views.today_report, name='today_report'),
path('get_today_present_data/', views.get_today_present_data, name='get_today_present_data'),


path('add_wfh/', views.add_wfh, name='add_wfh'),
path('wfh_status/', views.wfh_status, name='wfh_status'),

# add thwe work from home details 
path('save_work_from_home/', views.save_work_from_home, name='save_work_from_home'),


path('delete_wfh/<int:id>/', views.delete_wfh, name='delete_wfh'),

path('morning_morning/', views.morning_morning, name='morning_morning'),
path('get_late_days/', views.get_late_days, name='get_late_days'),
path('morning_late_report/', views.morning_late_report, name='morning_late_report'),

path('early_by_report/', views.early_by_report, name='early_by_report'),
path('get_early_days/', views.get_early_days, name='get_early_days'),
path('early_by_report_fetch/', views.early_by_report_fetch, name='early_by_report_fetch'),

#salary increment
path('add_increment/', views.add_increment, name='add_increment'),
path('increment_radio/', views.increment_radio, name='increment_radio'),
path('get_user_details/', views.get_user_details, name='get_user_details'),
path('salary_fetch/', views.salary_fetch, name='salary_fetch'),
path('insert_salary/', views.insert_salary, name='insert_salary'),
path('delete_salary_record/', views.delete_salary_record, name='delete_salary_record'),
# path('increment_report/', views.increment_report, name='increment_report'),

# Increament Report
path('increament_report/', views.increament_report, name='increament_report'),
path('increament_report_month_year/', views.increament_report_month_year, name='increament_report_month_year'),
path('increament_report_year/', views.increament_report_year, name='increament_report_year'),

path('check_increment_date/', views.check_increment_date, name='check_increment_date'),

path('increament_report/employee_userid/', views.employee_userid, name='employee_userid'),
path('increament_report/employee_details/<str:user_id>/', views.employee_details, name='employee_details'),
# path('delete_increament_report/<int:id>/', views.delete_increament_report, name='delete_increament_report'),


#enable / disable
path('enable_disable_view/', views.enable_disable_view, name='enable_disable_view'),
path('fetch_status/', views.fetch_status, name='fetch_status'),

path('get_location_options/', views.get_location_options, name='get_location_options'),


#employee permisssion report total

path('delete_totalemployee/<int:id>/', views.delete_totalemployee, name='delete_totalemployee'),
path('total_per_fetch/', views.total_per_fetch, name='total_per_fetch'),
path('total_employee_permission_report/', views.total_employee_permission_report, name='total_employee_permission_report'),



path('add_loan_emp/', views.add_loan_emp, name='add_loan_emp'),
path('insert_loan_record/', views.insert_loan_record, name='insert_loan_record'),
path('fetch_loan_records/', views.fetch_loan_records, name='fetch_loan_records'),
path('delete_loan_record/', views.delete_loan_record, name='delete_loan_record'),

path('add_loan_admin/', views.add_loan_admin, name='add_loan_admin'),
path('get_user_loan_records/', views.get_user_loan_records, name='get_user_loan_records'),
path('update_sts_add_loan/', views.update_sts_add_loan, name='update_sts_add_loan'),


path('loan_report_admin/', views.loan_report_admin, name='loan_report_admin'),
path('loan_report_fetch/', views.loan_report_fetch, name='loan_report_fetch'),


path('add-clock-in/', views.add_clock_in, name='add_clock_in'),
path('view_tick/', views.view_tick, name='view_tick'),



path('error_page/', views.error_page, name='error_page'),




]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

