from django.db import models
from django.db import models, migrations
from django.utils.timezone import now

# Create your models here.

class RegisterAll(models.Model):
    id = models.BigAutoField(primary_key=True)
    depart = models.TextField()
    nm = models.TextField()
    user_id = models.TextField(db_collation='utf8_bin')
    pwd = models.TextField(db_collation='utf8_bin')
    mob = models.TextField()
    addr = models.TextField()
    em_depart = models.TextField()
    em_depart_hed = models.TextField()
    em_depart_tl = models.TextField()
    no_of_cl = models.TextField()
    email = models.TextField()
    pic = models.TextField()
    reg_dt = models.DateField()
    mnth = models.IntegerField()
    yr = models.IntegerField()
    permi = models.TimeField()
    team_ld = models.TextField()
    dsig = models.TextField()
    work_frm = models.TextField()
    work_to = models.TextField()
    sala = models.FloatField()
    dob = models.DateField(default='1900-01-01')
    pf_cd = models.TextField()
    locca = models.TextField(default='')
    bank = models.TextField()
    acc_no = models.TextField()
    ifsc = models.TextField()
    acti = models.TextField()
    doj = models.DateField(default='1900-01-01')
    other_deduct = models.FloatField()
    pf_amt = models.TextField()
    sd_amt = models.TextField()
    company = models.TextField()
    fath_nm = models.CharField(max_length=200)
    blood = models.CharField(max_length=200)
    hm_mob = models.CharField(max_length=50)
    offc_mob = models.CharField(max_length=50)
    pass_chg = models.IntegerField()
    insu_amt = models.FloatField()
    esi_amt = models.FloatField()
    branch_name = models.TextField()

    gender = models.TextField()
    pan_num = models.TextField()
    aadhar_num = models.TextField()
    branch = models.TextField()
    employee_contri = models.TextField()
    employer_contri = models.TextField()
    mr_mrs_ms = models.TextField()
    reliving_dt = models.DateField(default='0001-01-01')
    rejoin_dt = models.DateField(default='0001-01-01')

  

    def __str__(self):
        return self.nm  # You can replace this with any field you want to be displayed in the admin

    class Meta:
        db_table = 'register_all'







class AddDepartment(models.Model): 
    nm=models.CharField(max_length=255) 

    def __str__(self):
        return self.nm  

    class Meta:
        db_table = 'departmts'  


class AddDepartmentHead(models.Model):
    dept=models.CharField(max_length=50)
    desig=models.CharField(max_length=50)
    emp_id=models.CharField(max_length=50)
    name=models.CharField(max_length=50)
    branch=models.CharField(max_length=50)

    def __str__(self):
        return self.name  

    class Meta:
        db_table = 'depart_head'


class Branch(models.Model):
    office_name = models.CharField(max_length=100)
    branch_name = models.CharField(max_length=50)
    addr = models.TextField()
    admin_code = models.CharField(max_length=100)
    employee_code = models.CharField(max_length=100)
    trainee_code = models.CharField(max_length=100)
    office_number = models.CharField(max_length=100)  # New field

    def __str__(self):
        return self.office_name  

    class Meta:
        db_table = 'branches'

class Attendance(models.Model):
    id = models.AutoField(primary_key=True)
    depart = models.TextField()
    user_id = models.TextField()
    work_frm = models.CharField(max_length=200)
    work_to = models.CharField(max_length=200)
    clk_in = models.IntegerField()
    clk_out = models.IntegerField()
    clk_in_dt_tm = models.DateTimeField()
    clk_out_dt_tm = models.DateTimeField()
    clk_in_tm = models.TimeField()
    clk_out_tm = models.TimeField()
    tot_hr = models.TimeField()
    date = models.DateField()
    mnth = models.IntegerField()
    yr = models.IntegerField()
    clkin_ip = models.TextField()
    clkout_ip = models.TextField()
    notes = models.TextField()
    late_resn_status = models.IntegerField()

    def __str__(self):
        return self.depart

    class Meta:
        db_table = 'bk_attendance'


class Leave(models.Model):
    id = models.AutoField(primary_key=True)
    depart = models.CharField(max_length=200)
    user_id = models.CharField(max_length=200)
    lev_dt = models.DateField()
    lev_id = models.IntegerField()
    reason = models.TextField()
    lev_typ = models.CharField(max_length=200)
    applay_dt = models.DateField()
    mnth = models.IntegerField()
    yr = models.IntegerField()
    status = models.IntegerField()  

    def __str__(self):
        return self.lev_dt

    class Meta:
        db_table = 'leaves'

class EmpLeaves(models.Model):
    id = models.AutoField(primary_key=True)
    depart = models.TextField()
    user_id = models.TextField()
    from_dt = models.DateField()
    to_dt = models.DateField()
    tot_days = models.IntegerField()
    reason = models.TextField()
    lev_typ = models.TextField()
    applay_dt = models.DateField()
    mnth = models.IntegerField()
    yr = models.IntegerField()
    status = models.IntegerField()


    def __str__(self):
        return self.from_dt

    class Meta:
        db_table = 'emp_leaves'



#For Salary Report        

class PayrollMaathangi(models.Model):
    id = models.IntegerField(primary_key=True)
    emp_id = models.CharField(max_length=200)
    emp_nm = models.CharField(max_length=200)
    desig = models.CharField(max_length=200)
    doj = models.DateField()
    locc = models.CharField(max_length=200)
    pf_amt = models.FloatField()
    pf_num = models.CharField(max_length=200)
    actual_sal = models.FloatField()
    punch = models.FloatField()
    punch_hlf = models.FloatField()
    cl = models.FloatField()
    cl_hlf = models.FloatField()
    od = models.FloatField()
    od_hlf = models.FloatField()
    holiday = models.FloatField()
    missed_clkin = models.FloatField()
    lop = models.FloatField()
    lop_hlf = models.FloatField()
    missed_clkin_hlf = models.FloatField()
    early_clkout = models.FloatField()
    mng_late = models.CharField(max_length=200)
    earlyby = models.CharField(max_length=200)
    tot_late = models.CharField(max_length=200)
    tot_late_deduct_days = models.FloatField()
    tot_month_days = models.IntegerField()
    min_attnd_need = models.FloatField()
    sal_elig_days = models.FloatField()
    process_dt = models.DateField()
    salary_dt = models.DateField()
    adv_deduct = models.FloatField()
    arr_deduct = models.FloatField()
    sd_deduct = models.FloatField()
    days_extra_deduct = models.FloatField()
    bonus_earn = models.FloatField()
    prv_arr_earn = models.FloatField()
    sts = models.IntegerField()
    salary_month = models.DateField()
    salary = models.FloatField()
    insu_amt = models.FloatField()
    esi_amt = models.FloatField()


    def __str__(self):
        return self.emp_nm  # You can replace this with any field you want to be displayed in the admin

    class Meta:
        db_table = 'payroll_maathangi'


        #MODELS.PY

class WorkFromHome(models.Model):
    req_dt = models.DateField()
    emp_nm = models.CharField(max_length=200)
    emp_id = models.CharField(max_length=50)
    emp_dept = models.CharField(max_length=200)
    emp_desig = models.CharField(max_length=200)
    wfh_start_dt = models.DateField()
    wfh_end_dt = models.DateField()
    monst = models.CharField(max_length=50)
    moned = models.CharField(max_length=50)
    tuest = models.CharField(max_length=50)
    tueed = models.CharField(max_length=50)
    wedst = models.CharField(max_length=50)
    weded = models.CharField(max_length=50)
    thust = models.CharField(max_length=50)
    thued = models.CharField(max_length=50)
    frist = models.CharField(max_length=50)
    fried = models.CharField(max_length=50)
    satst = models.CharField(max_length=50)
    sated = models.CharField(max_length=50)
    sunst = models.CharField(max_length=50)
    suned = models.CharField(max_length=50)
    resn = models.TextField()
    sup_nm = models.CharField(max_length=200)
    app_status = models.CharField(max_length=100)

    def __str__(self):
        return self.emp_nm  # You can replace this with any field you want to be displayed in the admin

    class Meta:
        db_table = 'wfh_status'


class Visiters(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.CharField(max_length=100)
    log_in_tm = models.TimeField()
    log_out_tm = models.TimeField(null=True, blank=True)
    log_in_dt_tm = models.DateTimeField()
    log_out_dt_tm = models.DateTimeField(null=True, blank=True)
    log_dt = models.DateField()
    log_out_dt = models.DateField(null=True, blank=True)
    log_mnth = models.IntegerField()
    log_yr = models.IntegerField()
    ip = models.CharField(max_length=100)
    loctn = models.CharField(max_length=100)

    def __str__(self):
        return self.user  # You can replace this with any field you want to be displayed in the admin

    class Meta:
        db_table = 'visiters'


class AddPermission(models.Model):
    id = models.AutoField(primary_key=True)
    user_id = models.CharField(max_length=100)
    perm_tm = models.CharField(max_length=100)
    perm_dt = models.DateField()
    reson = models.TextField()
    applay_dt = models.DateField()
    mnth = models.CharField(max_length=50)
    yr = models.CharField(max_length=50)  

    def __str__(self):
        return self.user_id  # You can replace this with any field you want to be displayed in the admin

    class Meta:
        db_table = 'emp_permission' 

class PermissionAdd(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    user_id = models.CharField(max_length=100)
    permi_dt = models.DateField()
    permi_mnth = models.IntegerField()
    permi_yr = models.IntegerField()
    permi_tm_start_am = models.CharField(max_length=100)
    permi_tm_end_am = models.CharField(max_length=100)
    permi_24tm_start = models.CharField(max_length=100)
    permi_24tm_end = models.CharField(max_length=100)
    permi_hr = models.CharField(max_length=100)
    permi_frm = models.CharField(max_length=100)
    submit_dt = models.DateField()
    resn = models.TextField()

    def __str__(self):
        return self.name  # You can replace this with any field you want to be displayed in the admin

    class Meta:
        db_table = 'permission_add'  


class ExcelToDB(models.Model):
    id = models.AutoField(primary_key=True)
    emp_id = models.CharField(max_length=20)
    nm = models.CharField(max_length=100)
    shift = models.CharField(max_length=50)
    in_time = models.TimeField()
    out_time = models.TimeField()
    wrk_hr = models.FloatField()
    ot = models.FloatField()
    tot_hr = models.FloatField()
    status = models.CharField(max_length=20)
    remarks = models.TextField()
    date = models.DateField()

    def __str__(self):
        return self.emp_id  # You can replace this with any field you want to be displayed in the admin

    class Meta:
        db_table = 'excel_su' 

class Holiday(models.Model):
    id = models.AutoField(primary_key=True)
    reason = models.CharField(max_length=255)
    holiday_date = models.DateField()
    month = models.CharField(max_length=20)
    year = models.IntegerField()
    branch = models.CharField(max_length=50)

    def __str__(self):
        return self.reason  # You can replace this with any field you want to be displayed in the admin

    class Meta:
        db_table = 'holidays' 



#employee table

class AttnNotes(models.Model):
    id = models.AutoField(primary_key=True)
    user_id = models.CharField(max_length=200)
    note = models.TextField()
    dt = models.DateField()

    def __str__(self):
        return self.note  # You can replace this with any field you want to be displayed in the admin

    class Meta:
        db_table = 'attn_notes'  




class AddLocation(models.Model): 
    id = models.AutoField(primary_key=True)
    location=models.CharField(max_length=255) 

    def __str__(self):
        return self.location  

    class Meta:
        db_table = 'location' 



class AddSalary(models.Model): 
    id = models.AutoField(primary_key=True)
    salary=models.CharField(max_length=255) 
    basic=models.CharField(max_length=255) 
    hr=models.CharField(max_length=255) 
    conv_all=models.CharField(max_length=255) 
    medical_all=models.CharField(max_length=255) 
    spl_all=models.CharField(max_length=255) 
    incre_dt=models.DateField(max_length=255) 
    position=models.CharField(max_length=255) 
    sal_last=models.CharField(max_length=255) 
    user_id = models.CharField(max_length=200)

    def __str__(self):
        return self.basic  

    class Meta:
        db_table = 'salary_increment' 



class Wallpaper(models.Model): 
    id = models.AutoField(primary_key=True)
    wallpaper=models.TextField(max_length=255) 
    

    def __str__(self):
        return self.wallpaper  

    class Meta:
        db_table = 'wallpaper'     


class Enable(models.Model): 
    id = models.AutoField(primary_key=True)
    status=models.TextField(max_length=255) 
    

    def __str__(self):
        return self.status  

    class Meta:
        db_table = 'enable_disable'                                       

class AddLoan(models.Model): 
    id = models.AutoField(primary_key=True)
    user_id = models.CharField(max_length=200)
    name=models.CharField(max_length=255) 
    req_date=models.DateField()
    loan_amount=models.IntegerField() 
    status=models.IntegerField()

    def __str__(self):
        return self.user_id  

    class Meta:
        db_table = 'add_loan' 


class AddClockin(models.Model): 
    id = models.AutoField(primary_key=True)
    usid = models.CharField(max_length=200)
    
    status=models.IntegerField()
    branch=models.TextField() 

    def __str__(self):
        return self.usid  

    class Meta:
        db_table = 'app_clockin'         