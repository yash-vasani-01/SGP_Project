from django.db import models
from django.contrib.auth.models import User

class data(models.Model):
    username=models.CharField(max_length=50)
    email=models.EmailField( max_length=254)
    status=models.JSONField(blank=True, default=list)
    def __str__(self):
        return (f"{self.username}")


class admin_data(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE,null=True)
    username = models.CharField(max_length=150)
    email = models.EmailField(max_length=254)
    status=models.JSONField(blank=True, default=list)
    
    
    def __str__(self):
        return self.username
    

class SeminarHall(models.Model):
    institute_name = models.CharField(max_length=255)
    hall_name = models.CharField(max_length=255, null=True)
    location = models.CharField(max_length=255)
    capacity = models.IntegerField()
    audio_system = models.BooleanField(default=False)
    projector = models.BooleanField(default=False)
    internet_wifi = models.BooleanField(default=False)
   
    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['institute_name', 'hall_name'], name='unique_hall_per_institute')
        ]

    def __str__(self):
        return f"{self.hall_name} ({self.institute_name})"
