# Generated by Django 5.0.1 on 2024-03-25 12:18

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('sheet', '0007_addclockin'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='addclockin',
            name='name',
        ),
    ]
