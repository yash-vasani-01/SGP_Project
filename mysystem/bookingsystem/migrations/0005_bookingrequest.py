# Generated by Django 5.0.6 on 2024-09-10 15:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bookingsystem', '0004_alter_admin_data_institute_name'),
    ]

    operations = [
        migrations.CreateModel(
            name='BookingRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('institute_name', models.CharField(max_length=255)),
                ('hall_name', models.CharField(max_length=255)),
                ('date', models.DateField()),
                ('time_slot', models.CharField(max_length=50)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('accepted', 'Accepted'), ('rejected', 'Rejected')], default='pending', max_length=10)),
                ('requester_name', models.CharField(max_length=50)),
            ],
        ),
    ]
