# Generated by Django 5.0.6 on 2024-09-10 15:16

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bookingsystem', '0005_bookingrequest'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='bookingrequest',
            name='time_slot',
        ),
        migrations.AddField(
            model_name='bookingrequest',
            name='end_time',
            field=models.TimeField(default=datetime.time(0, 0)),
        ),
        migrations.AddField(
            model_name='bookingrequest',
            name='start_time',
            field=models.TimeField(default=datetime.time(0, 0)),
        ),
    ]
