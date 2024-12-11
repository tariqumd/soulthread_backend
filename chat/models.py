from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models

from django.contrib.auth.models import BaseUserManager

class User(AbstractUser):
    groups = models.ManyToManyField(
        Group,
        related_name="custom_user_groups",  # Avoid clash with default User.groups
        blank=True,
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="custom_user_permissions",  # Avoid clash with default User.user_permissions
        blank=True,
    )


class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_messages")
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    sentiment = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return f"{self.sender} to {self.receiver}: {self.content[:20]}"
