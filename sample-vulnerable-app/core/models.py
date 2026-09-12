from django.db import models


class UserProfile(models.Model):
    username = models.CharField(max_length=150)
    email = models.CharField(max_length=254)
    bio = models.TextField(blank=True)


class Feedback(models.Model):
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
