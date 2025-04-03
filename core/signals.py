from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.contrib.auth import logout
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.contrib.auth.models import User
from .models import Collector, Beach

# Set collector status to 'online' when the user logs in
@receiver(user_logged_in)
def set_status_to_online(sender, request, user, **kwargs):
    try:
        collector = Collector.objects.get(user=user)
        if user.is_active:
            collector.status = 'online'
            collector.save()
    except Collector.DoesNotExist:
        pass

# Set collector status to 'offline' when the user logs out
@receiver(user_logged_out)
def set_status_to_offline(sender, request, user, **kwargs):
    try:
        collector = Collector.objects.get(user=user)
        collector.status = 'offline'
        collector.save()
    except Collector.DoesNotExist:
        pass

# Monitor changes to the Collector's status to handle 'offline' scenario
logout_in_progress = False

@receiver(pre_save, sender=Collector)
def check_collector_status(sender, instance, **kwargs):
    global logout_in_progress
    try:
        existing_collector = Collector.objects.get(id=instance.id)

        # If status changes from 'online' to 'offline'
        if existing_collector.status == 'online' and instance.status == 'offline' and not logout_in_progress:
            logout_in_progress = True
            logout_user(instance.user)  # Log out the associated user
            logout_in_progress = False
    except Collector.DoesNotExist:
        pass

# Sync Collector's is_active with User's is_active
@receiver(post_save, sender=Collector)
def sync_user_status_from_collector(sender, instance, **kwargs):
    user = instance.user
    if user.is_active != instance.is_active:
        user.is_active = instance.is_active
        user.save()

# Sync User's is_active with Collector's is_active
@receiver(post_save, sender=User)
def sync_collector_status_from_user(sender, instance, **kwargs):
    try:
        collector = Collector.objects.get(user=instance)
        if collector.is_active != instance.is_active:
            collector.is_active = instance.is_active
            collector.save()
    except Collector.DoesNotExist:
        pass

# Create a Collector when a new User is created
@receiver(post_save, sender=User)
def create_collector(sender, instance, created, **kwargs):
    if created:
        Collector.objects.create(user=instance)

# Ensure the collector instance is saved whenever the User is saved
@receiver(post_save, sender=User)
def save_collector(sender, instance, **kwargs):
    try:
        instance.collector.save()
    except Collector.DoesNotExist:
        pass


def logout_user(user):
    """
    Log out the user programmatically and mark them as inactive.
    """
    if user.is_authenticated:
        user.is_active = False
        user.save()

        try:
            collector = Collector.objects.get(user=user)
            collector.status = 'offline'
            collector.save()
            print(f"User {user.username} has been marked offline.")
        except Collector.DoesNotExist:
            pass

@receiver(user_logged_in)
def assign_beach_on_login(sender, request, user, **kwargs):
    try:
        collector = user.collector
        if not collector.beach:  # If no assigned beach, assign one
            available_beach = Beach.objects.first()  # Example: assign the first available beach
            if available_beach:
                collector.beach = available_beach
                collector.save()
    except Collector.DoesNotExist:
        pass

@receiver(user_logged_in)
def update_assigned_beach(sender, request, user, **kwargs):
    try:
        collector = user.collector
        if not collector.beach:  # If no beach assigned, assign one dynamically
            # Example logic to assign a beach (adjust as needed)
            beach = Beach.objects.first()  # Example: assign the first beach
            if beach:
                collector.beach = beach
                collector.save()
    except Collector.DoesNotExist:
        pass