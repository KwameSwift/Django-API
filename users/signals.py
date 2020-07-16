# signal that gets fired after a user is save
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Profile, User


# user profile to be created for each new user
@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)


# saving our profile after creating it
@receiver(post_save, sender=User)
def save_profile(sender, instance, **kwargs):
    instance.profile.save()