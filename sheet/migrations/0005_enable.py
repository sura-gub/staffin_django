# Generated by Django 5.0.1 on 2024-03-18 06:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sheet', '0004_registerall_rejoin_dt_registerall_reliving_dt'),
    ]

    operations = [
        migrations.CreateModel(
            name='Enable',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('status', models.TextField(max_length=255)),
            ],
            options={
                'db_table': 'enable_disable',
            },
        ),
    ]
