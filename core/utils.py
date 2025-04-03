# core/utils.py
from django.core.mail import send_mail
from django.conf import settings

def send_verification_email(email, verification_link):
    subject = 'Please verify your email address'
    message = f'Click the following link to verify your email: {verification_link}'
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
