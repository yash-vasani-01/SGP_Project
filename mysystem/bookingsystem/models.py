from django.db import models


class data(models.Model):
    username=models.CharField(max_length=50)
    email=models.EmailField( max_length=254)
    phone=models.CharField(max_length=10)
    city=models.CharField(max_length=50)
    status=models.JSONField(blank=True, default=list)
def __str__(self):
    return (f"{self.username}")
