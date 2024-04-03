# Generated by Django 5.0.1 on 2024-02-27 05:21

from django.apps import apps
from django.db import migrations, models
from datetime import datetime

def set_default_values(apps, schema_editor):
    RegisterAll = apps.get_model('sheet', 'RegisterAll')
    # Get the current date, month, and year
    current_date = datetime.now().date()
    month = current_date.month
    year = current_date.year
    # Your default values
    defaults = {
        'depart': 'SAD',
        'nm': 'SUPER-ADMIN',
        'user_id': 'master',
        'pwd': '123',
        'mob': '7402616151',
        'addr': 'Marthandam',
        'em_depart': 'Managing Director',
        'em_depart_hed': 'Ratheesh',
        'em_depart_tl': '1',
        'no_of_cl': '12',
        'email': 'sratheesh2019@gmail.com',
        'pic': '',
        'reg_dt': current_date,
        'mnth': month,
        'yr': year,
        'permi': '2:30',
        'team_ld': '0',
        'dsig': 'Director',
        'work_frm': '9:00:00',
        'work_to': '18:00:00',
        'sala': '10000',
        'dob': '2014-07-24',
        'pf_cd': '7474',
        'locca': 'Marthandam',
        'bank': 'Karnataka',
        'acc_no': '6160000006100000',
        'ifsc': 'KAR100100',
        'acti': '0',
        'doj': '2017-04-24',
        'other_deduct': '0',
        'pf_amt': '0',
        'sd_amt': '0',
        'company': 'SESENCE',
        'fath_nm': 'XXX',
        'blood': 'O+',
        'hm_mob': '7402616151',
        'offc_mob': '7402616151',
        'pass_chg': '0',
        'insu_amt': '0',
        'esi_amt': '0',
        'branch_name': 'Marthandam',
        'gender': '',
        'pan_num': '0',
        'aadhar_num': '0',
        'branch': '',
        'employee_contri': '',
        'employer_contri': '',
        'mr_mrs_ms': '',
    }
    # Create an instance with default values
    instance = RegisterAll(**defaults)
    instance.save()


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AddDepartment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nm', models.CharField(max_length=255)),
            ],
            options={
                'db_table': 'departmts',
            },
        ),
        migrations.CreateModel(
            name='AddDepartmentHead',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('dept', models.CharField(max_length=50)),
                ('desig', models.CharField(max_length=50)),
                ('emp_id', models.CharField(max_length=50)),
                ('name', models.CharField(max_length=50)),
                ('branch', models.CharField(max_length=50)),
            ],
            options={
                'db_table': 'depart_head',
            },
        ),
        migrations.CreateModel(
            name='AddLocation',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('location', models.CharField(max_length=255)),
            ],
            options={
                'db_table': 'location',
            },
        ),
        migrations.CreateModel(
            name='AddPermission',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('user_id', models.CharField(max_length=100)),
                ('perm_tm', models.CharField(max_length=100)),
                ('perm_dt', models.DateField()),
                ('reson', models.TextField()),
                ('applay_dt', models.DateField()),
                ('mnth', models.CharField(max_length=50)),
                ('yr', models.CharField(max_length=50)),
            ],
            options={
                'db_table': 'emp_permission',
            },
        ),
        migrations.CreateModel(
            name='AddSalary',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('salary', models.CharField(max_length=255)),
                ('basic', models.CharField(max_length=255)),
                ('hr', models.CharField(max_length=255)),
                ('conv_all', models.CharField(max_length=255)),
                ('medical_all', models.CharField(max_length=255)),
                ('spl_all', models.CharField(max_length=255)),
                ('incre_dt', models.DateField(max_length=255)),
                ('position', models.CharField(max_length=255)),
                ('sal_last', models.CharField(max_length=255)),
                ('user_id', models.CharField(max_length=200)),
            ],
            options={
                'db_table': 'salary_increment',
            },
        ),
        migrations.CreateModel(
            name='Attendance',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('depart', models.TextField()),
                ('user_id', models.TextField()),
                ('work_frm', models.CharField(max_length=200)),
                ('work_to', models.CharField(max_length=200)),
                ('clk_in', models.IntegerField()),
                ('clk_out', models.IntegerField()),
                ('clk_in_dt_tm', models.DateTimeField()),
                ('clk_out_dt_tm', models.DateTimeField()),
                ('clk_in_tm', models.TimeField()),
                ('clk_out_tm', models.TimeField()),
                ('tot_hr', models.TimeField()),
                ('date', models.DateField()),
                ('mnth', models.IntegerField()),
                ('yr', models.IntegerField()),
                ('clkin_ip', models.TextField()),
                ('clkout_ip', models.TextField()),
                ('notes', models.TextField()),
                ('late_resn_status', models.IntegerField()),
            ],
            options={
                'db_table': 'bk_attendance',
            },
        ),
        migrations.CreateModel(
            name='AttnNotes',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('user_id', models.CharField(max_length=200)),
                ('note', models.TextField()),
                ('dt', models.DateField()),
            ],
            options={
                'db_table': 'attn_notes',
            },
        ),
        migrations.CreateModel(
            name='Branch',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('office_name', models.CharField(max_length=100)),
                ('branch_name', models.CharField(max_length=50)),
                ('addr', models.TextField()),
                ('admin_code', models.CharField(max_length=100)),
                ('employee_code', models.CharField(max_length=100)),
                ('trainee_code', models.CharField(max_length=100)),
                ('office_number', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'branches',
            },
        ),
        migrations.CreateModel(
            name='EmpLeaves',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('depart', models.TextField()),
                ('user_id', models.TextField()),
                ('from_dt', models.DateField()),
                ('to_dt', models.DateField()),
                ('tot_days', models.IntegerField()),
                ('reason', models.TextField()),
                ('lev_typ', models.TextField()),
                ('applay_dt', models.DateField()),
                ('mnth', models.IntegerField()),
                ('yr', models.IntegerField()),
                ('status', models.IntegerField()),
            ],
            options={
                'db_table': 'emp_leaves',
            },
        ),
        migrations.CreateModel(
            name='ExcelToDB',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('emp_id', models.CharField(max_length=20)),
                ('nm', models.CharField(max_length=100)),
                ('shift', models.CharField(max_length=50)),
                ('in_time', models.TimeField()),
                ('out_time', models.TimeField()),
                ('wrk_hr', models.FloatField()),
                ('ot', models.FloatField()),
                ('tot_hr', models.FloatField()),
                ('status', models.CharField(max_length=20)),
                ('remarks', models.TextField()),
                ('date', models.DateField()),
            ],
            options={
                'db_table': 'excel_su',
            },
        ),
        migrations.CreateModel(
            name='Holiday',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('reason', models.CharField(max_length=255)),
                ('holiday_date', models.DateField()),
                ('month', models.CharField(max_length=20)),
                ('year', models.IntegerField()),
                ('branch', models.CharField(max_length=50)),
            ],
            options={
                'db_table': 'holidays',
            },
        ),
        migrations.CreateModel(
            name='Leave',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('depart', models.CharField(max_length=200)),
                ('user_id', models.CharField(max_length=200)),
                ('lev_dt', models.DateField()),
                ('lev_id', models.IntegerField()),
                ('reason', models.TextField()),
                ('lev_typ', models.CharField(max_length=200)),
                ('applay_dt', models.DateField()),
                ('mnth', models.IntegerField()),
                ('yr', models.IntegerField()),
                ('status', models.IntegerField()),
            ],
            options={
                'db_table': 'leaves',
            },
        ),
        migrations.CreateModel(
            name='PayrollMaathangi',
            fields=[
                ('id', models.IntegerField(primary_key=True, serialize=False)),
                ('emp_id', models.CharField(max_length=200)),
                ('emp_nm', models.CharField(max_length=200)),
                ('desig', models.CharField(max_length=200)),
                ('doj', models.DateField()),
                ('locc', models.CharField(max_length=200)),
                ('pf_amt', models.FloatField()),
                ('pf_num', models.CharField(max_length=200)),
                ('actual_sal', models.FloatField()),
                ('punch', models.FloatField()),
                ('punch_hlf', models.FloatField()),
                ('cl', models.FloatField()),
                ('cl_hlf', models.FloatField()),
                ('od', models.FloatField()),
                ('od_hlf', models.FloatField()),
                ('holiday', models.FloatField()),
                ('missed_clkin', models.FloatField()),
                ('lop', models.FloatField()),
                ('lop_hlf', models.FloatField()),
                ('missed_clkin_hlf', models.FloatField()),
                ('early_clkout', models.FloatField()),
                ('mng_late', models.CharField(max_length=200)),
                ('earlyby', models.CharField(max_length=200)),
                ('tot_late', models.CharField(max_length=200)),
                ('tot_late_deduct_days', models.FloatField()),
                ('tot_month_days', models.IntegerField()),
                ('min_attnd_need', models.FloatField()),
                ('sal_elig_days', models.FloatField()),
                ('process_dt', models.DateField()),
                ('salary_dt', models.DateField()),
                ('adv_deduct', models.FloatField()),
                ('arr_deduct', models.FloatField()),
                ('sd_deduct', models.FloatField()),
                ('days_extra_deduct', models.FloatField()),
                ('bonus_earn', models.FloatField()),
                ('prv_arr_earn', models.FloatField()),
                ('sts', models.IntegerField()),
                ('salary_month', models.DateField()),
                ('salary', models.FloatField()),
                ('insu_amt', models.FloatField()),
                ('esi_amt', models.FloatField()),
            ],
            options={
                'db_table': 'payroll_maathangi',
            },
        ),
        migrations.CreateModel(
            name='PermissionAdd',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('user_id', models.CharField(max_length=100)),
                ('permi_dt', models.DateField()),
                ('permi_mnth', models.IntegerField()),
                ('permi_yr', models.IntegerField()),
                ('permi_tm_start_am', models.CharField(max_length=100)),
                ('permi_tm_end_am', models.CharField(max_length=100)),
                ('permi_24tm_start', models.CharField(max_length=100)),
                ('permi_24tm_end', models.CharField(max_length=100)),
                ('permi_hr', models.CharField(max_length=100)),
                ('permi_frm', models.CharField(max_length=100)),
                ('submit_dt', models.DateField()),
                ('resn', models.TextField()),
            ],
            options={
                'db_table': 'permission_add',
            },
        ),
        migrations.CreateModel(
            name='RegisterAll',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('depart', models.TextField()),
                ('nm', models.TextField()),
                ('user_id', models.TextField()),
                ('pwd', models.TextField()),
                ('mob', models.TextField()),
                ('addr', models.TextField()),
                ('em_depart', models.TextField()),
                ('em_depart_hed', models.TextField()),
                ('em_depart_tl', models.TextField()),
                ('no_of_cl', models.TextField()),
                ('email', models.TextField()),
                ('pic', models.TextField()),
                ('reg_dt', models.DateField()),
                ('mnth', models.IntegerField()),
                ('yr', models.IntegerField()),
                ('permi', models.TimeField()),
                ('team_ld', models.TextField()),
                ('dsig', models.TextField()),
                ('work_frm', models.TextField()),
                ('work_to', models.TextField()),
                ('sala', models.FloatField()),
                ('dob', models.DateField(default='1900-01-01')),
                ('pf_cd', models.TextField()),
                ('locca', models.TextField(default='')),
                ('bank', models.TextField()),
                ('acc_no', models.TextField()),
                ('ifsc', models.TextField()),
                ('acti', models.TextField()),
                ('doj', models.DateField(default='1900-01-01')),
                ('other_deduct', models.FloatField()),
                ('pf_amt', models.TextField()),
                ('sd_amt', models.TextField()),
                ('company', models.TextField()),
                ('fath_nm', models.CharField(max_length=200)),
                ('blood', models.CharField(max_length=200)),
                ('hm_mob', models.CharField(max_length=50)),
                ('offc_mob', models.CharField(max_length=50)),
                ('pass_chg', models.IntegerField()),
                ('insu_amt', models.FloatField()),
                ('esi_amt', models.FloatField()),
                ('branch_name', models.TextField()),
                ('gender', models.TextField()),
                ('pan_num', models.TextField()),
                ('aadhar_num', models.TextField()),
                ('branch', models.TextField()),
                ('employee_contri', models.TextField()),
                ('employer_contri', models.TextField()),
                ('mr_mrs_ms', models.TextField()),
            ],
            options={
                'db_table': 'register_all',
            },
        ),
        migrations.CreateModel(
            name='Visiters',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('user', models.CharField(max_length=100)),
                ('log_in_tm', models.TimeField()),
                ('log_out_tm', models.TimeField(blank=True, null=True)),
                ('log_in_dt_tm', models.DateTimeField()),
                ('log_out_dt_tm', models.DateTimeField(blank=True, null=True)),
                ('log_dt', models.DateField()),
                ('log_out_dt', models.DateField(blank=True, null=True)),
                ('log_mnth', models.IntegerField()),
                ('log_yr', models.IntegerField()),
                ('ip', models.CharField(max_length=100)),
                ('loctn', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'visiters',
            },
        ),
        migrations.CreateModel(
            name='Wallpaper',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('wallpaper', models.TextField(max_length=255)),
            ],
            options={
                'db_table': 'wallpaper',
            },
        ),
        migrations.CreateModel(
            name='WorkFromHome',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('req_dt', models.DateField()),
                ('emp_nm', models.CharField(max_length=200)),
                ('emp_id', models.CharField(max_length=50)),
                ('emp_dept', models.CharField(max_length=200)),
                ('emp_desig', models.CharField(max_length=200)),
                ('wfh_start_dt', models.DateField()),
                ('wfh_end_dt', models.DateField()),
                ('monst', models.CharField(max_length=50)),
                ('moned', models.CharField(max_length=50)),
                ('tuest', models.CharField(max_length=50)),
                ('tueed', models.CharField(max_length=50)),
                ('wedst', models.CharField(max_length=50)),
                ('weded', models.CharField(max_length=50)),
                ('thust', models.CharField(max_length=50)),
                ('thued', models.CharField(max_length=50)),
                ('frist', models.CharField(max_length=50)),
                ('fried', models.CharField(max_length=50)),
                ('satst', models.CharField(max_length=50)),
                ('sated', models.CharField(max_length=50)),
                ('sunst', models.CharField(max_length=50)),
                ('suned', models.CharField(max_length=50)),
                ('resn', models.TextField()),
                ('sup_nm', models.CharField(max_length=200)),
                ('app_status', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'wfh_status',
            },
        ),
        migrations.RunPython(set_default_values),
    ]
