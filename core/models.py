import secrets
from arrow import now
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.conf import settings
import qrcode
from io import BytesIO
import cloudinary.uploader
from django.contrib.auth.models import Group
from django.contrib.auth.models import PermissionsMixin

from django.utils import timezone



class CustomUser(AbstractUser):
    is_admin = models.BooleanField(default=False)
    is_cashier = models.BooleanField(default=False)
    is_collector = models.BooleanField(default=False)
    is_tourist = models.BooleanField(default=False)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.username

class Beach(models.Model):
    name = models.CharField(max_length=255, unique=True)  
    description = models.TextField(blank=True, null=True)  
    location = models.CharField(max_length=500)  
    image = models.ImageField(upload_to='beach_photos/', blank=True, null=True) 
    is_active = models.BooleanField(default=True) 

    def __str__(self):
        return self.name
    
class Collector(models.Model): 
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE) 
    contact_number = models.CharField(max_length=15)
    is_active = models.BooleanField(default=True)
    status = models.CharField(max_length=10, choices=[('online', 'Online'), ('offline', 'Offline')], default='offline')

    first_name = models.CharField(max_length=255)
    middle_name = models.CharField(max_length=255, blank=True, null=True)  # Optional
    last_name = models.CharField(max_length=255)
    fullname = models.CharField(max_length=255, blank=True, null=True)
    nickname = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.user.username} - {self.fullname or self.first_name}"

    def save(self, *args, **kwargs):
        # Ensure is_active synchronization with the linked User
        self.user.is_collector = True
        self.user.is_tourist = False  # If becoming a collector, can't be a tourist
        self.user.is_active = self.is_active
        self.user.save()

        collector_group, _ = Group.objects.get_or_create(name="Collector")
        if not self.user.groups.filter(name="Collector").exists():
            self.user.groups.add(collector_group)

        # Ensure consistent active status
        if self.user.is_active != self.is_active:
            self.user.is_active = self.is_active
            self.user.save()

        super().save(*args, **kwargs)



class Tourist(models.Model):

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='tourist')
    # Set 'token' as the primary key
    token = models.CharField(max_length=64, primary_key=True, default=secrets.token_urlsafe)
    
    # QR code URL will be stored here
    qr_code = models.CharField(max_length=255, blank=True, null=True)  # QR code URL from Cloudinary
    
    # Personal details
    first_name = models.CharField(max_length=255)
    middle_name = models.CharField(max_length=255, blank=True, null=True)  # Optional middle name
    last_name = models.CharField(max_length=255)
    fullname = models.CharField(max_length=255, blank=True, null=True)  # Fullname, will be generated on save
    nickname = models.CharField(max_length=255, blank=True, null=True) 
    
    # Additional fields
    email = models.EmailField(unique=True)
    contact_number = models.CharField(max_length=15, blank=True, null=True, validators=[RegexValidator(r'^\d{10,15}$', 'Enter a valid phone number')])
    age = models.IntegerField()  # Age of the tourist
    address = models.TextField()  # Address of the tourist
    
    GENDER_CHOICES = [
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other'),
    ]
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, blank=True, null=True)

    # Tourist Type: Local or Foreign
    TOURIST_TYPE_CHOICES = [
        ('local', 'Local'),
        ('foreign', 'Foreign'),
    ]
    tourist_type = models.CharField(max_length=7, choices=TOURIST_TYPE_CHOICES, default='local')
    
    # Country (only for foreign tourists)
    country = models.CharField(max_length=255, blank=True, null=True)
    
    # Verification status
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.fullname if self.fullname else self.first_name

    def save(self, *args, **kwargs):
        self.user.is_tourist = True
        self.user.is_collector = False  # If becoming a tourist, can't be a collector
        self.user.save()
        
        tourist_group, _ = Group.objects.get_or_create(name="Tourist")
        if not self.user.groups.filter(name="Tourist").exists():
            self.user.groups.add(tourist_group)
        # Generate full name by combining first name, middle name (if exists), and last name
        self.fullname = f"{self.first_name} {self.middle_name or ''} {self.last_name}".strip()
        
        # Generate QR code if not already generated
        if not self.qr_code:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(f"http://127.0.0.1:8000/verify-tourist/?token={self.token}")  # Link to verification page
            qr.make(fit=True)

            # Save the generated QR code as an image
            img_byte_arr = BytesIO()
            qr.make_image(fill="black", back_color="white").save(img_byte_arr, format="PNG")
            img_byte_arr.seek(0)

            # Upload the QR code image to Cloudinary and store the URL
            upload_result = cloudinary.uploader.upload(img_byte_arr, folder="tourist_qr_codes")
            self.qr_code = upload_result['secure_url']

        # Call the parent save method
        super().save(*args, **kwargs)

class Reservation(models.Model):
    tourist = models.ForeignKey('Tourist', on_delete=models.CASCADE, null=True, blank=True)
    beach = models.ForeignKey(Beach, on_delete=models.CASCADE)
    date_reserved = models.DateField()
    num_people = models.IntegerField()
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(default=now)
    approved = models.BooleanField(default=False)  # New field for approval status
    approved_by = models.ForeignKey(Collector, on_delete=models.SET_NULL, null=True, blank=True) 

    def __str__(self):
        return f"{self.tourist.name} - {self.beach.name} ({self.date_reserved}) - Approved: {self.approved}"

class Payment(models.Model):
    PAYMENT_METHODS = [
        ('gcash', 'GCash'),
        ('cash', 'Cash'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('paid', 'Paid'),
        ('failed', 'Failed'),
    ]

    reservation = models.OneToOneField(Reservation, on_delete=models.CASCADE, related_name="payment")
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=10, choices=PAYMENT_METHODS)
    gcash_reference_number = models.CharField(max_length=255, blank=True, null=True)  # New field for GCash reference number
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Payment {self.gcash_reference_number if self.gcash_reference_number else 'No Reference'} - {self.status}"
