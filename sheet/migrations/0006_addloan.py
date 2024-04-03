# Generated by Django 5.0.1 on 2024-03-21 12:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sheet', '0005_enable'),
    ]

    operations = [
        migrations.CreateModel(
            name='AddLoan',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('user_id', models.CharField(max_length=200)),
                ('name', models.CharField(max_length=255)),
                ('req_date', models.DateField()),
                ('loan_amount', models.IntegerField()),
                ('status', models.IntegerField()),
            ],
            options={
                'db_table': 'add_loan',
            },
        ),
    ]
