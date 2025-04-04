
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth.forms import AuthenticationForm
from django.utils.timezone import localdate

from .forms import ResendVerificationForm, ReservationForm 
from .utils import send_verification_email 
from django.http import Http404
from django.contrib.auth import update_session_auth_hash


from .forms import DateFilterForm

from django.db.models.functions import ExtractMonth

import secrets
from urllib.parse import urlparse
import uuid
import matplotlib
import qrcode
from reportlab.lib.utils import ImageReader
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.colors import black, blue, red
import matplotlib.pyplot as plt
from django.core.paginator import Paginator
import io
from io import BytesIO
import cloudinary
import cloudinary.uploader
from django.conf import settings
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.utils import timezone
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib import messages
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Sum, Count, Q
from django.db.models.functions import ExtractMonth
from django.db import transaction
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from datetime import datetime, date, timedelta
from decimal import Decimal
from django.utils import timezone
from django.utils.timezone import now
from django.urls import reverse
from django.core.mail import EmailMultiAlternatives
from reportlab.lib.pagesizes import letter

import pytesseract
from PIL import Image
import re
import csv
from reportlab.lib.utils import simpleSplit

from core.models import Payment, Reservation, CustomUser, Collector, Beach, Tourist
from core.forms import BeachForm, TouristRegistrationForm, ReportForm

import logging


matplotlib.use('Agg') 


logger = logging.getLogger(__name__)

def landing_page(request):
    beaches = Beach.objects.all()
    return render(request, 'landing_page.html', {'beaches': beaches})

# Login view
def login_view(request):
    if request.method == "POST":
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('login_redirect')  # Redirect to your landing page after login
            else:
                messages.error(request, "Invalid username or password")
        else:
            messages.error(request, "Invalid username or password")
    else:
        form = AuthenticationForm()

    return render(request, 'login.html', {'form': form})


def register_tourist(request):
    if request.method == 'POST':
        form = TouristRegistrationForm(request.POST)

        if form.is_valid():
            # Get the email entered by the user
            email = form.cleaned_data['email']
            logger.debug(f"Form is valid, email entered: {email}")

            # Check if the email already exists in CustomUser model
            existing_user = CustomUser.objects.filter(email=email).first()

            if existing_user:
                if existing_user.is_tourist:
                    # Email already registered as a tourist
                    form.add_error('email', 'This email is already registered as a tourist and verified.')
                    return render(request, 'landing_page.html', {
                        'form': form,
                    })
                else:
                    # Email registered but not verified
                    form.add_error('email', 'This email is registered, but not verified. Please check your inbox for verification.')
                    return render(request, 'landing_page.html', {
                        'form': form,
                    })
            
            # If email is unique, proceed with registration
            tourist = form.save(commit=False)
            tourist.token = secrets.token_urlsafe(32)  # Generate a random unique token

            # Generate Correct QR Code URL (WITHOUT `token=`)
            qr_url = tourist.token

            # Generate QR Code
            qr = qrcode.make(qr_url)

            # Convert QR code to an image
            buffer = BytesIO()
            qr.save(buffer, format="PNG")

            # Upload to Cloudinary
            cloudinary_response = cloudinary.uploader.upload(buffer.getvalue(), folder="qr_codes")

            # Save Cloudinary URL to the database
            tourist.qr_code = cloudinary_response["secure_url"]
            tourist.save()

            # Generate the email verification link
            base_url = request.build_absolute_uri('/')
            verification_link = f"{base_url}verify-tourist/{tourist.token}/"

            try:
                # Create the email and send it
                email = EmailMultiAlternatives(
                    subject="Verify Your Email",
                    body=f"Click the link to verify your email: {verification_link}",
                    from_email=settings.EMAIL_HOST_USER,
                    to=[tourist.email],
                )

                # Attach the correct QR code image (from Cloudinary)
                qr_image_url = tourist.qr_code
                email.attach_alternative(
                    f"""
                        <html>
                            <body>
                                <p>Click the link to verify your email: <a href="{verification_link}">Verify Now</a></p>
                                <p>Here is your QR code:</p>
                                <img src="{qr_image_url}" alt="QR Code" />
                            </body>
                        </html>
                    """, "text/html"
                )

                email.send()
                logger.info(f"Verification email sent to {tourist.email}")

                return render(request, 'tourist/verification_sent.html', {
                    'email': tourist.email,
                    'success_message': 'Registration Complete! Please scan your QR code.'
                })

            except Exception as e:
                logger.error(f"Error sending verification email: {str(e)}")
                return render(request, 'landing_page.html', {
                    'form': form,
                    'error_message': 'Error sending verification email. Please try again later.'
                })

        else:
            messages.error(request, 'There were errors in the form. Please try again.')
    else:
        form = TouristRegistrationForm()

    return render(request, 'register.html', {'form': form})

def resend_verification_email(request):
    if request.method == "POST":
        form = ResendVerificationForm(request.POST)
        
        if form.is_valid():
            email = form.cleaned_data["email"]
            try:
                # Check if the email exists in the database
                tourist = Tourist.objects.get(email=email)
                
                if tourist.is_verified:
                    # Tourist already verified, no need to resend email
                    messages.info(request, "This email is already verified.")
                    return render(request, 'tourist/resend_verification_email.html', {'form': form})
                else:
                    # Send a verification email
                    verification_link = f"{request.build_absolute_uri('/verify-tourist/')}{tourist.token}/"
                    try:
                        # Send the email with verification link
                        send_verification_email(tourist.email, verification_link)
                        messages.success(request, f"Verification email has been sent to {email}.")
                        return render(request, 'tourist/resend_verification_email.html', {'form': form})
                    except Exception as e:
                        messages.error(request, f"Error sending email: {str(e)}")
                        return render(request, 'tourist/resend_verification_email.html', {'form': form})

            except Tourist.DoesNotExist:
                # If email doesn't exist in the database
                messages.error(request, "No user found with this email.")
                return render(request, 'tourist/resend_verification_email.html', {'form': form})

    else:
        form = ResendVerificationForm()
    
    return render(request, 'tourist/resend_verification_email.html', {'form': form})


def verify_tourist(request, token):
    tourist = Tourist.objects.filter(token=token).first()  # Find tourist by token
    if tourist:
        tourist.is_verified = True  # Mark as verified
        tourist.save()
        success_message = "Your email has been successfully verified."
        return render(request, "tourist/tourist_verified.html", {'tourist': tourist})  # Display success page
    else:
        return render(request, 'error_page.html', {'error_message': 'Invalid token'}) 
    
def custom_logout(request):
    logout(request)
    return redirect('landing_page')

def is_admin(user):
    return user.is_superuser

def is_cashier(user):
    return user.groups.filter(name="Cashier").exists() 

def is_collector(user):
    return user.groups.filter(name="Collector").exists()

def is_tourist(user):
    return user.groups.filter(name="Tourist").exists()



@login_required
def login_redirect(request):
    # If the user is an admin, redirect to the admin dashboard
    if request.user.is_superuser: 
        return redirect('admin_dashboard')

    # If the user is a cashier, redirect to the cashier dashboard
    if request.user.groups.filter(name="Cashier").exists():
        return redirect('cashier_dashboard')
    
    if request.user.is_collector: 
        return redirect('beach_dashboard')
    
    if hasattr(request.user, 'tourist'):
        if request.user.tourist.is_verified:
            # Tourist is verified, allow access to their dashboard
            return redirect('tourist_dashboard')
        else:
            # Tourist is not verified, show an error message
            messages.error(request, "Your account is not verified yet. Please verify your email.")
            return redirect('resend_verification_email')

    messages.error(request, "You do not have access to any dashboard.")
    return redirect('custom_logout')

@login_required
@user_passes_test(is_tourist)
def tourist_dashboard(request):
    # Get all beaches (for filtering purposes in the template)
    beaches = Beach.objects.all()
    today = localdate()
    # Fetch the tourist object related to the logged-in user
    tourist = get_object_or_404(Tourist, user=request.user)

    # Get search filters from GET parameters (if any)
    search_beach = request.GET.get("search_beach")
    search_payment = request.GET.get("search_payment")

    # If the tourist is not verified, render the not verified page
    if not tourist.is_verified:
        return render(request, "tourist/not_verified.html")

    # Get all reservations for the tourist, preloading related payment and beach objects
    reservations = Reservation.objects.filter(tourist=tourist).select_related("payment", "beach")

    # Apply filtering by beach if a search term was provided
    if search_beach:
        reservations = reservations.filter(beach__id=search_beach)

    # Apply filtering by payment status if a search term was provided
    if search_payment:
        reservations = reservations.filter(payment__payment_method=search_payment)

    reservations = reservations.order_by('-created_at', '-date_reserved')

    
    # Filter out past reservations (only show future reservations)
    reservations = reservations.filter(date_reserved__gte=date.today()) 
    past_reservations = reservations.filter(date_reserved__lt=today)
    # Paginate the reservations, showing 10 per page
    paginator = Paginator(reservations, 10)  # Show 10 reservations per page
    page_number = request.GET.get('page')  # Get the page number from the request
    reservations_page = paginator.get_page(page_number)

    # Fetch all collectors (might be used in the template for the user)
    collector = Collector.objects.select_related('user')  # Only if needed in the template
    
    # Render the dashboard template with the necessary context
    return render(request, "tourist/tourist_dashboard.html", {
        "tourist": tourist,
        "reservations": reservations_page,
        "collector": collector,  # Might be optional depending on template
        "beaches": beaches,
        'past_reservations': past_reservations,
        'today': today
    })


@login_required
@user_passes_test(is_tourist)
def update_reservation(request):
    if request.method == 'POST':
        reservation_id = request.POST.get('reservation_id')
        try:
            reservation = Reservation.objects.get(id=reservation_id)
        except Reservation.DoesNotExist:
            raise Http404("Reservation not found")

        # Ensure payment method is locked to 'cash'
        if reservation.payment.status == 'paid':
            return redirect('tourist_dashboard')

        # Update the reservation's beach and number of people
        beach_id = request.POST.get('beach')
        num_people = request.POST.get('num_people')

        # Make sure the beach exists
        try:
            beach = Beach.objects.get(id=beach_id)
        except Beach.DoesNotExist:
            raise Http404("Beach not found")

        # Update reservation fields
        reservation.beach = beach
        reservation.num_people = num_people

        # Save the reservation
        reservation.save()

        return redirect('tourist_dashboard')


@login_required
@user_passes_test(is_tourist)
def cancel_reservation(request, reservation_id):
    tourist = get_object_or_404(Tourist, user=request.user)
    
    # Now, filter reservations using the Tourist instance
    reservation = get_object_or_404(Reservation, id=reservation_id, tourist=tourist)

    if reservation.payment.status == "paid":
        messages.error(request, "You cannot cancel a paid reservation.")
        return redirect("your_reservations")

    reservation.delete()
    messages.success(request, "Reservation canceled successfully.")

    return redirect('tourist_dashboard')


@login_required
@user_passes_test(is_tourist)
def delete_reservation(request, reservation_id):
    reservation = get_object_or_404(Reservation, id=reservation_id)

    # Ensure the reservation belongs to the logged-in tourist
    if reservation.tourist.user != request.user:
        messages.error(request, "You are not authorized to delete this reservation.")
        return redirect("tourist_dashboard")

    reservation.delete()
    messages.success(request, "Reservation deleted successfully.")
    return redirect("tourist_dashboard")

@login_required
@user_passes_test(is_tourist)
def update_profile(request):
    tourist = get_object_or_404(Tourist, user=request.user)

    if request.method == "POST":
        # Update only the fields that exist in the form
        if request.POST.get("first_name"):
            tourist.first_name = request.POST["first_name"]
        if request.POST.get("last_name"):
            tourist.last_name = request.POST["last_name"]
        if request.POST.get("email"):
            tourist.email = request.POST["email"]
        if request.POST.get("contact_number"):
            tourist.contact_number = request.POST["contact_number"]
        if request.POST.get("gender"):
            tourist.gender = request.POST["gender"]
        if request.POST.get("address"):
            tourist.address = request.POST["address"]
        if request.POST.get("nickname"):
            tourist.nickname = request.POST["nickname"]

        # Handle profile picture upload (Only update if a new file is uploaded)
        if "profile_picture" in request.FILES:
            tourist.user.profile_picture = request.FILES["profile_picture"]
            tourist.user.save()

        # Handle password change only if a new password is provided
        new_password = request.POST.get("password")
        if new_password:
            try:
                tourist.user.set_password(new_password)
                tourist.user.save()
                update_session_auth_hash(request, tourist.user)  # Keep the user logged in
                messages.success(request, "Password updated successfully!")
            except ValidationError:
                messages.error(request, "Invalid password. Please try again.")

        # Save only the changed fields
        tourist.save()

        # Display success message
        messages.success(request, "Profile updated successfully!")
        return redirect("tourist_dashboard")

    return render(request, "tourist_dashboard.html", {"tourist": tourist})

@login_required
@user_passes_test(is_tourist)
@csrf_protect
def create_reservation(request):
    tourist = get_object_or_404(Tourist, user=request.user)

    if request.method == "POST":
        print("POST Data:", request.POST)  # Debugging: Check all posted data

        # Retrieve form data safely
        beach_id = request.POST.get("beach")
        date_reserved = request.POST.get("date")  # Ensure this matches the input 'name' in the form
        num_people = request.POST.get("num_people")
        payment_method = request.POST.get("payment_method")
        gcash_reference_number = request.POST.get("gcash_reference_number")
        total_price = request.POST.get("total_price")

        print("Date Reserved (POST):", date_reserved)  # Debugging

        # Check if date is None or not a string
        if not date_reserved or not isinstance(date_reserved, str):
            messages.error(request, "Invalid reservation date. Please select a valid date.")
            return redirect("create_reservation")

        # Validate and parse the date
        try:
            # Convert the string date into a date object (without time)
            date_reserved_obj = datetime.strptime(date_reserved, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            messages.error(request, "Invalid date format. Please use YYYY-MM-DD.")
            return redirect("create_reservation")

        # Ensure the reservation date is not in the past
        if date_reserved_obj < timezone.now().date():  # Use timezone-aware current date
            messages.error(request, "You cannot select a past date.")
            return redirect("create_reservation")

        # Validate beach selection
        try:
            beach_id = int(beach_id)  # Ensure it's an integer
            beach = Beach.objects.get(id=beach_id)
        except Beach.DoesNotExist:
            messages.error(request, "Invalid beach selection.")
            return redirect("create_reservation")

        # Check for duplicate reservation
        if Reservation.objects.filter(tourist=tourist, beach=beach, date_reserved=date_reserved_obj).exists():
            messages.error(request, "You already have a reservation for this date.")
            return redirect("tourist_dashboard")

        # Validate GCash reference number if payment method is GCash
        if payment_method == "gcash" and gcash_reference_number:
            if Payment.objects.filter(gcash_reference_number=gcash_reference_number).exists():
                messages.error(request, "This GCash reference number has already been used.")
                return redirect("create_reservation")

        # Validate and convert input types
        try:
            num_people = int(num_people)  # Ensure it's an integer
            total_price = Decimal(total_price)  # Convert to Decimal for compatibility
        except ValueError:
            messages.error(request, "Invalid number of people or total price.")
            return redirect("create_reservation")

        # Debugging: Verify inputs before saving
        print("Debugging Reservation Creation:")
        print("Tourist:", tourist)
        print("Beach:", beach)
        print("Date Reserved:", date_reserved_obj)
        print("Number of People:", num_people, type(num_people))
        print("Total Price:", total_price, type(total_price))

        # Create the reservation
        reservation = Reservation.objects.create(
            tourist=tourist,
            beach=beach,
            date_reserved=date_reserved_obj,
            num_people=num_people,
            total_price=total_price,
            created_at=timezone.now() 
        )

        # Create payment record based on the chosen payment method
        if payment_method == "gcash":
            if not gcash_reference_number:
                messages.error(request, "GCash reference number is required for this payment method.")
                return redirect("create_reservation")

            Payment.objects.create(
                reservation=reservation,
                amount=total_price,
                payment_method="gcash",
                gcash_reference_number=gcash_reference_number,
                status="paid"
            )

            messages.success(request, "Reservation successful! Payment completed via GCash.")

        elif payment_method == "cash":
            Payment.objects.create(
                reservation=reservation,
                amount=total_price,
                payment_method="cash",
                status="pending"
            )

            messages.success(request, "Reservation successful! Pay at the beach checkpoint.")
        return redirect("create_reservation")

    # Render the form if it's a GET request
    return render(request, "tourist/create_reservation.html", {
        "beaches": Beach.objects.all(),
        "tourist": tourist,
    })

@login_required
@user_passes_test(is_tourist)
@csrf_protect
def process_gcash_receipt(request):
    if request.method == 'POST' and request.FILES.get('gcash_receipt'):
        try:
            receipt_image = request.FILES['gcash_receipt']
            image = Image.open(receipt_image)

            # Extract text using Tesseract
            extracted_text = pytesseract.image_to_string(image)
            print("Extracted Text:", extracted_text)  # Debugging

            # Check if the specific phone number is present
            if '+63 956 002 9667' not in extracted_text:
                return JsonResponse({'error': 'The uploaded receipt does not contain the required phone number.'}, status=400)

            # Search for a 13-digit reference number
            match = re.search(r'\b\d{13}\b', extracted_text)
            reference_number = match.group(0) if match else None

            if reference_number:
                return JsonResponse({'reference_number': reference_number})
            else:
                return JsonResponse({'error': 'No valid 13-digit reference number found in the receipt.'}, status=400)

        except Exception as e:
            print("Error extracting text:", str(e))
            return JsonResponse({'error': 'Failed to process receipt image. Please try again.'}, status=500)

    return JsonResponse({'error': 'Invalid request method.'}, status=400)


@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    form = DateFilterForm(request.GET or None)

    # Initialize default values for start_date and end_date
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    # If the dates are provided, filter by created_at from the user model
    if start_date and end_date:
        try:
            start_date = timezone.datetime.strptime(start_date, "%Y-%m-%d").date()
            end_date = timezone.datetime.strptime(end_date, "%Y-%m-%d").date()
        except ValueError:
            start_date, end_date = None, None  # If invalid dates, don't filter by date
    else:
        start_date, end_date = None, None

    # Filter tourists based on the provided date range (from the CustomUser's created_at)
    tourists_queryset = Tourist.objects.all().select_related('user')  # Use select_related to fetch the 'user' object with each tourist
    
    if start_date and end_date:
        tourists_queryset = tourists_queryset.filter(user__created_at__range=[start_date, end_date])

    total_tourists = tourists_queryset.count()

    local_tourists = tourists_queryset.filter(tourist_type='local').count()
    foreign_tourists = tourists_queryset.filter(tourist_type='foreign').count()

    # Rest of your logic remains the same...
    gender_counts = tourists_queryset.values('gender').annotate(count=Count('gender'))
    counts = {item['gender']: item['count'] for item in gender_counts}
    male_count = counts.get('male', 0)
    female_count = counts.get('female', 0)
    other_count = counts.get('other', 0)

    collector_approval_counts = Collector.objects.annotate(
        approved_count=Count('reservation', filter=Q(reservation__approved=True))
    ).order_by('-approved_count')

    collector_names = [collector.nickname for collector in collector_approval_counts]
    collector_approvals = [collector.approved_count for collector in collector_approval_counts]

    beach_counts = (
        Reservation.objects.values('beach__name')
        .annotate(count=Count('beach'))
        .order_by('-count')
    )

    beach_labels = [item['beach__name'] for item in beach_counts]
    beach_visits = [item['count'] for item in beach_counts]

    most_visited_beach = beach_counts.first()
    most_visited_beach_name = most_visited_beach['beach__name'] if most_visited_beach else 'None'
    most_visited_beach_count = most_visited_beach['count'] if most_visited_beach else 0

    # Monthly visits count (Jan - May)
    visits_per_month = (
        Reservation.objects
        .annotate(month=ExtractMonth('date_reserved'))
        .values('month')
        .annotate(count=Count('id'))
    )

    month_counts = {month: 0 for month in range(1, 13)}
    for item in visits_per_month:
        month = item['month']
        if 1 <= month <= 12:
            month_counts[month] = item['count']


    total_collectors = Collector.objects.count()
    total_beaches = Beach.objects.count()

    context = {
        'form': form,
        'total_tourists': total_tourists,
        'local_tourists': local_tourists,
        'foreign_tourists': foreign_tourists,
        'male_count': male_count,
        'female_count': female_count,
        'other_count': other_count,
        'beach_labels': beach_labels,
        'beach_visits': beach_visits,
        'most_visited_beach': most_visited_beach_name,
        'most_visited_beach_count': most_visited_beach_count,
        'jan_visits': month_counts[1],
        'feb_visits': month_counts[2],
        'mar_visits': month_counts[3],
        'apr_visits': month_counts[4],
        'may_visits': month_counts[5],
        'collector_names': collector_names,
        'collector_approvals': collector_approvals,
        'total_collectors': total_collectors, 
        'total_beaches': total_beaches,
        'last_updated': timezone.now(),
    }

    return render(request, 'admin/admin_dashboard.html', context)

@login_required
@user_passes_test(is_admin)
def generate_report(request):
    if request.method == 'POST':
        form = ReportForm(request.POST)
        if form.is_valid():
            # Get the 'Prepared By' name from the form
            prepared_by = form.cleaned_data['prepared_by']
            
            # Retrieve filter dates from GET parameters
            start_date = request.GET.get('start_date')
            end_date = request.GET.get('end_date')

            # Convert to datetime if available
            if start_date:
                start_date = datetime.strptime(start_date, '%Y-%m-%d')
            if end_date:
                end_date = datetime.strptime(end_date, '%Y-%m-%d')

            # Gather data with applied filters (if any)
            gender_counts = Tourist.objects.values('gender').annotate(count=Count('gender'))
            counts = {item['gender']: item['count'] for item in gender_counts}
            male_count = counts.get('male', 0)
            female_count = counts.get('female', 0)
            other_count = counts.get('other', 0)

            collector_approval_counts = Collector.objects.annotate(
                approved_count=Count('reservation', filter=Q(reservation__approved=True))
            ).order_by('-approved_count')

            collector_names = [collector.nickname for collector in collector_approval_counts]
            collector_approvals = [collector.approved_count for collector in collector_approval_counts]

            # Filter beach visits by date range if provided
            beach_counts = (
                Reservation.objects
                .filter(date_reserved__gte=start_date if start_date else timezone.now())
                .filter(date_reserved__lte=end_date if end_date else timezone.now())
                .values('beach__name')
                .annotate(count=Count('beach'))
                .order_by('-count')
            )
            beach_labels = [item['beach__name'] for item in beach_counts]
            beach_visits = [item['count'] for item in beach_counts]

            # Tourist types (local/foreign) filtering by date
            local_tourists = Tourist.objects.filter(tourist_type='local')
            if start_date:
                local_tourists = local_tourists.filter(reservation__date_reserved__gte=start_date)
            if end_date:
                local_tourists = local_tourists.filter(reservation__date_reserved__lte=end_date)

            foreign_tourists = Tourist.objects.filter(tourist_type='foreign')
            if start_date:
                foreign_tourists = foreign_tourists.filter(reservation__date_reserved__gte=start_date)
            if end_date:
                foreign_tourists = foreign_tourists.filter(reservation__date_reserved__lte=end_date)

            local_tourists_count = local_tourists.count()
            foreign_tourists_count = foreign_tourists.count()

            # Initialize a dictionary to store visit counts for months (1 to 12)
            month_counts = {month: {'count': 0, 'visitors': 0, 'num_people': 0} for month in range(1, 13)}

            reservations = (
                Reservation.objects
                .filter(approved=True)
                .filter(date_reserved__gte=start_date if start_date else timezone.now())
                .filter(date_reserved__lte=end_date if end_date else timezone.now())
                .values('date_reserved')
                .annotate(month=ExtractMonth('date_reserved'))
                .annotate(reservation_count=Count('id'), people_count=Sum('num_people'))  # Get reservation count and sum of num_people
            )

            for item in reservations:
                month = item['month']
                month_counts[month]['count'] = item['reservation_count']  # Total number of reservations in the month
                month_counts[month]['num_people'] = item['people_count']  # Total number of people for all reservations in the month

            # Calculate unique visitors (tourists) for each month
            for month in range(1, 13):
                unique_visitors = Reservation.objects.filter(
                    approved=True, 
                    date_reserved__month=month
                ).values('tourist').distinct().count()
                month_counts[month]['visitors'] = unique_visitors 

            # Create a PDF response
            response = HttpResponse(content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="admin_dashboard_report_{timezone.now().strftime("%Y-%m-%d_%H-%M-%S")}.pdf"'

            # Create PDF canvas
            buffer = BytesIO()
            pdf = canvas.Canvas(buffer, pagesize=A4)
            pdf.setTitle("Admin Dashboard Report")

            # Report Title - Centered
            pdf.setFont("Helvetica-Bold", 14)
            pdf.drawCentredString(300, 800, "Admin Dashboard Report")
            pdf.setFont("Helvetica", 10)
            pdf.drawCentredString(300, 780, f"Generated on: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}")

            y_position = 740

            # Function to handle page breaks
            def check_page_break(y_position):
                if y_position < 50:  # Adjust this as needed
                    pdf.showPage()  # Create a new page
                    pdf.setFont("Helvetica-Bold", 14)
                    pdf.drawCentredString(300, 800, "Admin Dashboard Report")
                    pdf.setFont("Helvetica", 10)
                    pdf.drawCentredString(300, 780, f"Generated on: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    return 740  # Reset the y_position for the new page
                return y_position

            # Tourist Demographics Section - Centered
            pdf.setFont("Helvetica-Bold", 12)
            pdf.drawCentredString(300, y_position, "Tourist Demographics")
            y_position -= 20
            pdf.setFont("Helvetica", 10)
            pdf.drawCentredString(300, y_position, f"Total Tourists: {local_tourists_count + foreign_tourists_count}")
            pdf.drawCentredString(300, y_position - 20, f"Local Tourists: {local_tourists_count}")
            pdf.drawCentredString(300, y_position - 40, f"Foreign Tourists: {foreign_tourists_count}")
            y_position -= 60

            # Gender Distribution Table
            pdf.setFont("Helvetica-Bold", 12)
            pdf.drawCentredString(300, y_position, "Gender Distribution")
            y_position -= 20
            pdf.setFont("Helvetica", 10)
            pdf.drawCentredString(300, y_position, f"Male: {male_count}")
            pdf.drawCentredString(300, y_position - 20, f"Female: {female_count}")
            pdf.drawCentredString(300, y_position - 40, f"Other: {other_count}")
            y_position -= 60

            # Beach Statistics Section - Centered
            pdf.setFont("Helvetica-Bold", 12)
            pdf.drawCentredString(300, y_position, "Beach Statistics")
            y_position -= 20
            pdf.setFont("Helvetica", 10)
            pdf.drawCentredString(300, y_position, f"Most Visited Beach: {beach_labels[0] if beach_labels else 'None'}")
            pdf.drawCentredString(300, y_position - 20, f"Visit Count: {beach_visits[0] if beach_visits else 0}")
            y_position -= 60

            # Monthly Visits Table - Centered
            pdf.setFont("Helvetica-Bold", 12)
            pdf.drawCentredString(300, y_position, "Monthly Visits")
            y_position -= 20

            # Table Header
            pdf.setFont("Helvetica-Bold", 10)
            pdf.drawString(100, y_position, "Month")
            pdf.drawString(200, y_position, "Approved Visitors")
            pdf.drawString(300, y_position, "Total Visits")
            pdf.drawString(400, y_position, "Total People")
            y_position -= 20
                        
            # Define months array
            months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

            # Prepare the data for the monthly visits table
            for i, month in enumerate(months, 1):  # Month index is 1-12
                visit_count = month_counts.get(i, 0)['count']  # Get the visit count for each month
                approved_count = month_counts.get(i, 0)['visitors']  # Unique visitors count for the month
                total_people = month_counts.get(i, 0)['num_people']  # Total people for the month
                
                # Add rows for the table
                pdf.setFont("Helvetica", 10)
                pdf.drawString(100, y_position, f"{month}")
                pdf.drawRightString(200, y_position, f"{approved_count}")
                pdf.drawRightString(300, y_position, f"{visit_count}")
                pdf.drawRightString(400, y_position, f"{total_people}")
                
                y_position -= 20

                # Check page break
                y_position = check_page_break(y_position)

            # Collector Approvals Section - Centered
            pdf.setFont("Helvetica-Bold", 12)
            pdf.drawCentredString(300, y_position, "Collector Approvals")
            y_position -= 20
            for name, count in zip(collector_names, collector_approvals):
                pdf.setFont("Helvetica", 10)
                pdf.drawCentredString(300, y_position, f"{name}: {count}")
                y_position -= 20

            y_position -= 60  # Adjust to position at the bottom of the page
            pdf.setFont("Helvetica", 10)
            pdf.drawCentredString(300, y_position, f"Prepared By: {prepared_by}")

            pdf.save()
            buffer.seek(0)
            response.write(buffer.read())
            return response
        else:
            form = ReportForm()

    return render(request, 'admin_dashboard.html', {'form': form})




@login_required
@user_passes_test(is_admin)
def create_beach(request):
    if request.method == 'POST':
        form = BeachForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, "Beach has been created successfully.")
            return redirect('beach_list')  # Adjust to your desired redirect
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = BeachForm()
    
    return render(request, 'admin/create_beach.html', {'form': form})




@login_required
@user_passes_test(is_admin)
def create_beach(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        location = request.POST.get('location')
        description = request.POST.get('description', '')
        image = request.FILES.get('image', None)  # Handle image upload

        # Validation
        if not name or not location:
            messages.error(request, "Name and location are required.")
            return redirect('create_beach')

        if Beach.objects.filter(name=name).exists():
            messages.error(request, "A beach with this name already exists.")
            return redirect('create_beach')

        # Create Beach
        Beach.objects.create(
            name=name,
            location=location,
            description=description,
            image=image  # Save image if provided
        )

        messages.success(request, "Beach created successfully.")
        return redirect('create_beach')

    return render(request, 'admin/create_beach.html')

@login_required
@user_passes_test(is_admin)
def edit_beach(request, beach_id):
    beach = get_object_or_404(Beach, id=beach_id)

    if request.method == 'POST':
        beach.name = request.POST.get('name')
        beach.location = request.POST.get('location')
        beach.description = request.POST.get('description')

        if 'image' in request.FILES:
            beach.image = request.FILES['image']

        beach.save()
        return redirect('manage_beaches')

    return render(request, 'edit_beach.html', {'beach': beach})

@login_required
@user_passes_test(is_admin)
def create_user(request):
    beaches = Beach.objects.all().order_by('name')   # Pass existing beaches for selection

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        contact_number = request.POST.get('contact_number')
        profile_picture = request.FILES.get('profile_picture')

        # New fields
        first_name = request.POST.get('first_name')
        middle_name = request.POST.get('middle_name')
        last_name = request.POST.get('last_name')
        nickname = request.POST.get('nickname')


        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect('create_user')

        try:
            validate_password(password)
        except ValidationError as e:
            messages.error(request, e)
            return redirect('create_user')


        fullname = f"{first_name} {middle_name + ' ' if middle_name else ''}{last_name}"  # Generate fullname

        with transaction.atomic():
            # Create User
            user = CustomUser(username=username, first_name=first_name, last_name=last_name)
            user.set_password(password)
            if profile_picture:
                user.profile_picture = profile_picture
            user.save()

            # Create Collector with synchronized names
            collector = Collector.objects.create(
                user=user,
                contact_number=contact_number,
                nickname=nickname,
                first_name=first_name,
                middle_name=middle_name,
                last_name=last_name,
                fullname=fullname
            )
            collector.save()

        messages.success(request, "User and Collector created successfully.")
        return redirect('create_user')

    return render(request, 'admin/create_user.html', {'beaches': beaches})




@login_required
@user_passes_test(is_admin)
def toggle_collector_status(request, id):
    # Retrieve the Collector object by ID
    collector = get_object_or_404(Collector, id=id)
    
    # Toggle the `is_active` status
    collector.is_active = not collector.is_active
    collector.save()

    # Redirect to the page where you were managing collectors
    return redirect('manage_users')


@login_required
@user_passes_test(is_admin)
def delete_collector(request, id):
    # Retrieve the Collector object by ID
    collector = get_object_or_404(Collector, id=id)

    # Retrieve the associated CustomUser
    user = collector.user

    # Delete profile picture from Cloudinary if it exists
    if user.profile_picture:
        try:
            filename = user.profile_picture.url.split("/")[-1].split(".")[0]
            public_id = f"profile_pictures/{filename}"
            cloudinary.uploader.destroy(public_id)
        except Exception as e:
            messages.error(request, f"Error deleting profile picture: {e}")
            return redirect('manage_users')

    # Delete the CustomUser and Collector
    user.delete()  # This will automatically delete the collector if there's a ForeignKey with on_delete=models.CASCADE

    messages.success(request, "Collector and associated User deleted successfully.")
    return redirect('manage_users')


@login_required
@user_passes_test(is_admin)
def manage_users(request):
    collectors = Collector.objects.select_related('user').order_by('user__username')

    return render(request, 'admin/manage_user.html', {
        'collectors': collectors
    })

@login_required
@user_passes_test(is_admin)
def delete_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)

    print("Attempting to delete User with ID:", user_id)  # Debugging line

    # Delete associated Collector if exists
    try:
        collector = Collector.objects.get(user=user)
        print("Deleting associated Collector with ID:", collector.id)  # Debugging line
        collector.delete()
    except Collector.DoesNotExist:
        print("No associated Collector found.")  # Debugging line

    # Delete profile picture from Cloudinary if it exists
    if user.profile_picture:
        try:
            filename = user.profile_picture.url.split("/")[-1].split(".")[0]
            public_id = f"profile_pictures/{filename}"
            cloudinary.uploader.destroy(public_id)
        except Exception as e:
            messages.error(request, f"Error deleting profile picture: {e}")
            return redirect('manage_users')

    user.delete()
    messages.success(request, "User and Collector deleted successfully.")
    return redirect('manage_users')


@login_required
@user_passes_test(is_admin)
def manage_beaches(request):
    beaches = Beach.objects.all()
    return render(request, 'admin/manage_beach.html', {'beaches': beaches})

@login_required
@user_passes_test(is_admin)
def toggle_beach_status(request, beach_id):
    beach = get_object_or_404(Beach, id=beach_id)
    beach.is_active = not beach.is_active
    beach.save()
    messages.success(request, "Beach status updated successfully.")
    return redirect('manage_beaches')


@login_required
@user_passes_test(is_admin)
def delete_beach(request, beach_id):
    beach = get_object_or_404(Beach, id=beach_id)

    if beach.image:
        try:
            filename = beach.image.url.split("/")[-1].split(".")[0]
            public_id = f"beach_images/{filename}"
            cloudinary.uploader.destroy(public_id)
        except Exception as e:
            messages.error(request, f"Error deleting beach image: {e}")
            return redirect('manage_beaches')

    beach.delete()
    messages.success(request, "Beach deleted successfully.")
    return redirect('manage_beaches')

@login_required
@user_passes_test(is_admin)
def manage_tourists(request):
    tourists = Tourist.objects.all()
    return render(request, 'admin/manage_tourists.html', {'tourists': tourists})

@login_required
@user_passes_test(is_admin)
def delete_tourist(request, token):
    tourist = get_object_or_404(Tourist, token=token)

    # Delete QR code from Cloudinary if it exists
    if tourist.qr_code:
        print("QR Code URL:", tourist.qr_code)  # Debugging

        try:
            # Extract Correct Public ID with Folder Name
            filename = tourist.qr_code.split("/")[-1].split(".")[0]  # Extract filename
            public_id = f"tourist_qr_codes/{filename}"  # Add folder name
            print("Corrected Public ID:", public_id)  # Debugging

            # Attempt to delete from Cloudinary
            result = cloudinary.uploader.destroy(public_id)
            print("Cloudinary Response:", result)  # Debugging
        except Exception as e:
            print("Error deleting QR Code from Cloudinary:", e)  # Debugging

    # Delete tourist from database
    tourist.delete()

    messages.success(request, "Tourist and QR Code deleted successfully.")
    return redirect('manage_tourists')

@login_required
@user_passes_test(is_cashier)
def cashier_dashboard(request):
    """View for the cashier dashboard."""

    total_cash = float(Payment.objects.filter(payment_method='cash', status='paid').aggregate(Sum('amount'))['amount__sum'] or 0)
    total_gcash = float(Payment.objects.filter(payment_method='gcash', status='paid').aggregate(Sum('amount'))['amount__sum'] or 0)
    total_pending = float(Payment.objects.filter(status='pending').aggregate(Sum('amount'))['amount__sum'] or 0)

    # Stats Overview Data
    total_revenue = float(Payment.objects.filter(status='paid').aggregate(Sum('amount'))['amount__sum'] or 0)
    total_transactions = Payment.objects.count()
    pending_payments = Payment.objects.filter(status='pending').count()
    paid_payments = Payment.objects.filter(status='paid').count()
    todays_earnings = float(Payment.objects.filter(status='paid', created_at__date=timezone.now().date()).aggregate(Sum('amount'))['amount__sum'] or 0)

    # Sales Overview (Last 7 Days)
    sales_dates = [(timezone.now().date() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
    sales_data = [
        float(Payment.objects.filter(status='paid', created_at__date=date_str).aggregate(Sum('amount'))['amount__sum'] or 0)
        for date_str in sales_dates
    ]

    # Payment Method Breakdown
    payment_data = [
        float(Payment.objects.filter(payment_method='cash', status='paid').aggregate(Sum('amount'))['amount__sum'] or 0),
        float(Payment.objects.filter(payment_method='gcash', status='paid').aggregate(Sum('amount'))['amount__sum'] or 0),
    ]

    # Earnings Breakdown (Daily, Monthly, Yearly)
    today = timezone.now().date()
    current_month = timezone.now().month
    current_year = timezone.now().year

    earnings_data = [
        float(Payment.objects.filter(status='paid', created_at__date=today).aggregate(Sum('amount'))['amount__sum'] or 0),
        float(Payment.objects.filter(status='paid', created_at__month=current_month, created_at__year=current_year).aggregate(Sum('amount'))['amount__sum'] or 0),
        float(Payment.objects.filter(status='paid', created_at__year=current_year).aggregate(Sum('amount'))['amount__sum'] or 0),
    ]

    # Transaction Status Breakdown
    transaction_status_data = [
        pending_payments,
        paid_payments,
        Payment.objects.filter(status='failed').count(),
    ]

    # Revenue by Payment Method Over Time (Last 7 Days)
    revenue_method_dates = sales_dates  # Reuse the same date range
    cash_revenue_data = [
        float(Payment.objects.filter(payment_method='cash', status='paid', created_at__date=date_str).aggregate(Sum('amount'))['amount__sum'] or 0)
        for date_str in revenue_method_dates
    ]
    gcash_revenue_data = [
        float(Payment.objects.filter(payment_method='gcash', status='paid', created_at__date=date_str).aggregate(Sum('amount'))['amount__sum'] or 0)
        for date_str in revenue_method_dates
    ]

    context = {
        'total_revenue': total_revenue,
        'total_transactions': total_transactions,
        'pending_payments': pending_payments,
        'paid_payments': paid_payments,
        'todays_earnings': todays_earnings,
        'sales_dates': sales_dates,
        'sales_data': sales_data,
        'payment_data': payment_data,
        'earnings_data': earnings_data,
        'transaction_status_data': transaction_status_data,
        'revenue_method_dates': revenue_method_dates,
        'cash_revenue_data': cash_revenue_data,
        'gcash_revenue_data': gcash_revenue_data,
        'total_cash': total_cash,
        'total_gcash': total_gcash,
        'total_pending': total_pending,
    }

    return render(request, 'cashier/cashier_dashboard.html', context)

@login_required
@user_passes_test(lambda u: u.groups.filter(name="Cashier").exists())
def cashier_transactions(request):
    # Fetch GCash payments
    gcash_payments = Payment.objects.filter(payment_method="gcash").order_by('-created_at')

    # Fetch Cash payments (with filtering)
    cash_payments = Payment.objects.filter(payment_method="cash")
    beaches = Beach.objects.all()
    collectors = Collector.objects.all()

    search_beach = request.GET.get("search_beach")
    search_date = request.GET.get("search_date")
    search_approved_by = request.GET.get('search_approved_by')
    search_payment_status = request.GET.get('search_payment_status')

    if search_beach:
        cash_payments = cash_payments.filter(reservation__beach__id=search_beach)

    if search_date:
        cash_payments = cash_payments.filter(created_at__date=search_date)

    if search_approved_by:
        cash_payments = cash_payments.filter(reservation__approved_by__id=search_approved_by)
    
    if search_payment_status:
        cash_payments = cash_payments.filter(status=search_payment_status)

    paginator = Paginator(cash_payments, 10)  # Show 10 payments per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    
    cash_payments = cash_payments.order_by('-created_at')

    total_cash_amount = cash_payments.aggregate(total_amount=Sum('amount'))['total_amount'] or 0

    total_gcash_amount = gcash_payments.aggregate(total_amount=Sum('amount'))['total_amount'] or 0

    context = {
        "gcash_payments": gcash_payments,
        "cash_payments": cash_payments,
        "beaches": beaches,
        "collectors": collectors,
        'search_beach': search_beach,
        'search_date': search_date,
        'search_approved_by': search_approved_by,
        'total_cash_amount': total_cash_amount,  
        'total_gcash_amount': total_gcash_amount, 
        'page_obj': page_obj,
    }
    return render(request, "cashier/cashier_view_transactions.html", context)

@login_required
@user_passes_test(is_cashier)
def update_payment_status(request, payment_id):  # Change to match the URL parameter
    payment = get_object_or_404(Payment, id=payment_id)  # Query using ID

    if request.method == "POST":
        new_status = request.POST.get("payment_status")
        if new_status in ["pending", "paid", "failed"]:  # Ensure the status is valid
            payment.status = new_status
            payment.save()
            messages.success(request, f"Payment status updated to {payment.get_status_display()}")
        else:
            messages.error(request, "Invalid payment status selected.")

    return redirect("cashier_transactions")


@login_required
@user_passes_test(lambda u: u.groups.filter(name="Cashier").exists())
def cashier_generate_report(request):
    # Fetch necessary data
    total_revenue = Payment.objects.filter(status='paid').aggregate(Sum('amount'))['amount__sum'] or 0
    total_transactions = Payment.objects.count()
    total_cash = Payment.objects.filter(payment_method='cash').aggregate(Sum('amount'))['amount__sum'] or 0
    total_gcash = Payment.objects.filter(payment_method='gcash').aggregate(Sum('amount'))['amount__sum'] or 0
    pending_payments = Payment.objects.filter(status='pending').count()

    
    # Create PDF response
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="cashier_report.pdf"'
    
    p = canvas.Canvas(response, pagesize=letter)
    
    # Set font for the title to bold (Helvetica-Bold)
    p.setFont("Helvetica-Bold", 16)
    
    # Calculate the width of the title to center it
    title = "Cashier Dashboard Report"
    title_width = p.stringWidth(title, "Helvetica-Bold", 16)
    page_width, _ = letter  # Get the width of the page
    title_x = (page_width - title_width) / 2  # Center the title horizontally

    # Title (centered and bold)
    p.drawString(title_x, 750, title)
    
    # Set font for the rest of the text
    p.setFont("Helvetica", 12)

    
    # Report Data
    p.drawString(100, 700, f"Total Revenue: ₱{total_revenue:,.2f}")
    p.drawString(100, 680, f"Total Transactions: {total_transactions}")
    p.drawString(100, 660, f"Total Cash Transactions: ₱{total_cash:,.2f}")
    p.drawString(100, 640, f"Total GCash Transactions: ₱{total_gcash:,.2f}")
    p.drawString(100, 620, f"Pending Payments: {pending_payments}")

    collectors = Collector.objects.all()
    y_position = 580  # Starting y position for the collectors' information

    for collector in collectors:
        # Calculate total collected by each collector
        total_collected = Payment.objects.filter(reservation__approved_by=collector).aggregate(Sum('amount'))['amount__sum'] or 0
        collector_name = collector.fullname or f"{collector.first_name} {collector.last_name}"
        
        # Add collector information to the PDF
        p.drawString(100, y_position, f"{collector_name}: ₱{total_collected:,.2f}")
        y_position -= 20 
    
    # More sections can be added here

    # Save PDF and return
    p.showPage()
    p.save()
    
    return response


@login_required
@user_passes_test(lambda u: u.groups.filter(name="Cashier").exists())
def cashier_generate_csv_report(request):
    # Fetch all payments data for CSV export
    payments = Payment.objects.all()

    # Prepare response for CSV download
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="cashier_report.csv"'

    writer = csv.writer(response)
    
    # Add headers to the CSV
    writer.writerow(['Transaction ID', 'Payment Method', 'Amount', 'Status', 'Date'])
    
    # Write each payment data to the CSV
    for payment in payments:
        writer.writerow([payment.id, payment.payment_method, payment.amount, payment.status, payment.created_at])

    return response

@login_required
@user_passes_test(is_collector)
def beach_dashboard(request):
    if not hasattr(request.user, 'collector'):
        return redirect('landing_page')

    collector = request.user.collector
    today = timezone.now().date()

    # Get only today's reservations
    reservations = Reservation.objects.filter(date_reserved=today).order_by('-date_reserved')

    payments = Payment.objects.filter(status="paid")

    # Calculate total reservations, approved reservations, and pending payments for today
    total_reservations = reservations.count()
    approved_reservations = reservations.filter(approved=True).count()
    pending_payments = Payment.objects.filter(reservation__in=reservations, status='pending').count()

    # Calculate total earnings only from paid payments for today's reservations
    total_earnings_today = Payment.objects.filter(
        reservation__in=reservations, 
        status='paid'
    ).aggregate(total_earnings=Sum('amount'))['total_earnings'] or 0  # Default to 0 if no payments

    # Get payment status for today's reservations
    payments = Payment.objects.filter(reservation__in=reservations).order_by('-reservation__date_reserved')

    context = {
        'collector': collector,
        'reservations': reservations,
        'payments': payments,
        'total_reservations': total_reservations,
        'approved_reservations': approved_reservations,
        'pending_payments': pending_payments,
        'total_earnings_today': total_earnings_today,  # Now only includes paid payments
        'selected_date': today,  # Display today's date in the template
    }

    return render(request, 'beach/beach_dashboard.html', context)


@login_required
@user_passes_test(is_collector)
def generate_pdf_report(request):
    collector = request.user.collector  # Get the logged-in collector
    collector_name = collector.fullname or "Collector"
    today = timezone.now().date()  # Get today's date

    # Get only today's reservations and payments
    reservations = Reservation.objects.filter(date_reserved=today).order_by('-date_reserved')
    payments = Payment.objects.filter(reservation__in=reservations, status='paid')

    # Summary calculations
    total_reservations = reservations.count()
    approved_reservations = reservations.filter(approved=True).count()
    pending_payments = Payment.objects.filter(reservation__in=reservations, status='pending').count()
    total_earnings_today = payments.aggregate(total_earnings=Sum('amount'))['total_earnings'] or 0

    # Create a new PDF response
    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = 'attachment; filename="dashboard_report.pdf"'

    # Create PDF canvas
    p = canvas.Canvas(response, pagesize=letter)
    width, height = letter

    # Title
    p.setFont("Helvetica-Bold", 16)
    p.drawString(180, height - 50, "Collector Dashboard Report")

    # Collector's Name
    p.setFont("Helvetica", 12)
    p.drawString(50, height - 80, f"Collector: ")
    p.drawString(200, height - 80, f"{collector_name}")
    # Date
    p.drawString(50, height - 100, f"Date: ")
    
    p.drawString(200, height - 100, f"{today}")

    # Summary Metrics
    p.drawString(50, height - 130, f"Total Reservations: ")
    p.drawString(200, height - 130, f"{total_reservations}")
    p.drawString(50, height - 150, f"Approved Reservations: ")
    p.drawString(200, height - 150, f"{approved_reservations}")
    p.drawString(50, height - 170, f"Pending Payments: ")
    p.drawString(200, height - 170, f"{pending_payments}")
    p.drawString(50, height - 190, f"Earnings Today: ")
    p.drawString(200, height - 190, f"₱{total_earnings_today:.2f}")

    # Reservations Section
    y_position = height - 230
    p.setFont("Helvetica-Bold", 12)
    p.drawString(50, y_position, "Reservations:")
    p.setFont("Helvetica", 10)
    y_position -= 20

    if reservations:
        for res in reservations:
            status = "Approved" if res.approved else "Pending"
            tourist_name = res.tourist.nickname if res.tourist else "N/A"
            p.drawString(50, y_position, f"Tourist: ")
            p.drawString(100, y_position, f"{tourist_name}")
            p.drawString(250, y_position, f"Date: ")
            p.drawString(300, y_position, f"{res.date_reserved}")
            p.drawString(450, y_position, f"People: ")
            p.drawString(500, y_position, f"{res.num_people}")
            p.drawString(650, y_position, f"Status: ")
            p.drawString(700, y_position, f"{status}")
            y_position -= 20
    else:
        p.drawString(50, y_position, "No reservations recorded.")
        y_position -= 20

    # Payments Section
    y_position -= 30
    p.setFont("Helvetica-Bold", 12)
    p.drawString(50, y_position, "Payments:")
    p.setFont("Helvetica", 10)
    y_position -= 20

    if payments:
        for pay in payments:
            p.drawString(50, y_position, f"Date: ")
            p.drawString(100, y_position, f"{pay.reservation.date_reserved}")
            p.drawString(250, y_position, f"Amount: ")
            p.drawString(300, y_position, f"₱{pay.amount:.2f}")
            y_position -= 20
    else:
        p.drawString(50, y_position, "No payments recorded.")

    # Save and return PDF
    p.showPage()
    p.save()
    return response



@login_required 
@user_passes_test(is_collector)
def beach_reservation(request):
    collector = None

    if request.user.is_authenticated:
        try:
            collector = Collector.objects.get(user=request.user)
        except Collector.DoesNotExist:
            collector = None  # Handle if the user is not a collector

    beaches = Beach.objects.all()  # Adjust this if necessary

    return render(request, "beach/beach_reservation1.html", {
        'beaches': beaches,
        'collector': collector,
    })

@login_required
@user_passes_test(is_collector)
def approve_reservation(request, reservation_id):
    reservation = get_object_or_404(Reservation, id=reservation_id)

    # Ensure the reservation belongs to the collector's beach
    if reservation.beach != request.user.collector.beach:
        return redirect('beach_dashboard')  # Or some other error page
    
    reservation.approved = True
    reservation.approved_by = request.user.collector
    reservation.save()

    return redirect('beach_dashboard')

@login_required
@user_passes_test(is_collector)
def edit_collector_profile(request, collector_id):
    collector = get_object_or_404(CustomUser, id=collector_id)

    if request.method == 'POST':
        collector.username = request.POST.get('nickname')

        if 'profile_picture' in request.FILES:
            collector.profile_picture = request.FILES['profile_picture']

        collector.save()
        return redirect('beach_dashboard')  # Adjust the redirect as needed

    return render(request, 'beach/edit_profile.html', {'collector': collector})


@login_required
@user_passes_test(is_collector)
@csrf_exempt  # TEMPORARY: Ensure CSRF is not blocking the request for debugging
def beach_create_reservation(request):
    if request.method == "POST":
        try:
            beach_id = request.POST.get("beach")
            num_people = int(request.POST.get("num_people"))
            total_price = float(request.POST.get("total_price"))

            beach = Beach.objects.get(id=beach_id)

            # Save the reservation
            reservation = Reservation.objects.create(
                beach=beach,
                date_reserved=timezone.now(),
                num_people=num_people,
                total_price=total_price,
                created_at=timezone.now(),
                approved=True,
                approved_by=request.user.collector
            )

            # Automatically create the payment
            Payment.objects.create(
                reservation=reservation,
                amount=total_price,
                payment_method="cash",
                status="paid"
            )

            receipt_data = {
                'beach_name': reservation.beach.name,
                'num_people': reservation.num_people,
                'total_price': reservation.total_price,
                'payment_method': 'cash',
                'status': 'paid',
                'reservation_date': reservation.date_reserved.strftime('%Y-%m-%d %H:%M:%S'),
                'collector_full_name': reservation.approved_by.fullname
            }

            return JsonResponse({'status': 'success', 'receipt_data': receipt_data})

        except Exception as e:
            print(f"Error occurred: {e}")  # Check console for the exact error
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)


@login_required
@user_passes_test(is_collector)
def beach_qrscanner(request):
    collector = None

    if request.user.is_authenticated:
        try:
            collector = Collector.objects.get(user=request.user)
        except Collector.DoesNotExist:
            collector = None

    tourists = Tourist.objects.all()  # Adjust this if specific filtering is needed

    return render(request, "beach/beach_qrscanner.html", {
        'tourists': tourists,
        'collector': collector,
        
    })


@login_required
@user_passes_test(is_collector)
def beach_qrscanner_token(request, token):
    # Get the tourist associated with the token
    tourist = get_object_or_404(Tourist, token=token)

    # Get all reservations associated with the tourist
    reservations = Reservation.objects.filter(tourist=tourist)

    # Paginate the reservations
    paginator = Paginator(reservations, 10)  # 10 reservations per page
    page_number = request.GET.get('page')  # Get the page number from the query string
    page_obj = paginator.get_page(page_number)

    # Check if the user is authenticated and get the collector
    collector = None
    if request.user.is_authenticated:
        try:
            collector = Collector.objects.get(user=request.user)
        except Collector.DoesNotExist:
            collector = None

    # Render the template with the paginated reservations
    return render(request, "beach/beach_qrscanner_token.html", {
        'tourist': tourist,  # Pass the tourist object
        'collector': collector,  # Pass the collector object
        'reservations': page_obj,  # Pass the paginated reservations (page_obj)
    })


@login_required
@user_passes_test(is_collector)
def get_reservations(request):
    qr_code = request.GET.get('qr_code')

    if not qr_code:
        logger.warning("No QR code provided in request.")
        return JsonResponse({"success": False, "message": "No QR code provided."})

    logger.info(f"Received QR Code: {qr_code}")

    # Extract Token
    parsed_url = urlparse(qr_code)
    path_segments = [seg for seg in parsed_url.path.split("/") if seg]
    token_value = path_segments[-1] if path_segments else qr_code

    logger.info(f"Extracted Token: {token_value}")

    try:
        tourist = Tourist.objects.get(token=token_value)  # Use token instead of qr_code
    except Tourist.DoesNotExist:
        logger.warning(f"Tourist with token '{token_value}' not found.")
        return JsonResponse({"success": False, "message": f"Tourist with token '{token_value}' not found."})

    reservations = Reservation.objects.filter(tourist=tourist).select_related('beach', 'payment')

    logger.info(f"Found {reservations.count()} reservations for Token: {token_value}")

    if reservations.exists():
        data = {
            "success": True,
            "reservations": [
                {
                    "id": res.id,  # 🔥 Ensure ID is included!
                    "beach_name": res.beach.name,
                    "date_reserved": res.date_reserved.strftime("%Y-%m-%d"),
                    "num_people": res.num_people,
                    "payment_method": res.payment.payment_method if hasattr(res, 'payment') else "N/A",
                    "payment_status": res.payment.status if hasattr(res, 'payment') else "No Payment"
                }
                for res in reservations
            ]
        }
    else:
        data = {"success": False, "message": f"No reservations found for Token: {token_value}"}

    return JsonResponse(data)

@login_required
@user_passes_test(is_collector)
@csrf_exempt  # Allow AJAX POST requests
def confirm_payment_tourist(request, reservation_id):
    if request.method == "POST":
        try:
            reservation = Reservation.objects.get(id=reservation_id)

            # Ensure it's a cash payment and is pending
            if reservation.payment.payment_method == "cash" and reservation.payment.status == "pending":
                reservation.payment.status = "paid"
                reservation.payment.save()
                return JsonResponse({"success": True, "message": "Payment confirmed."})
            else:
                return JsonResponse({"success": False, "message": "Payment already confirmed or invalid payment method."})

        except Reservation.DoesNotExist:
            return JsonResponse({"success": False, "message": "Reservation not found."})

    return JsonResponse({"success": False, "message": "Invalid request method."})



@login_required
@user_passes_test(is_collector)
def scan_qr_code(request, qr_code):
    try:
        tourist = Tourist.objects.get(qr_code=qr_code)
        reservations = Reservation.objects.filter(tourist=tourist, payment_status="pending")

        if reservations.exists():
            data = {
                "status": "success",
                "tourist": {
                    "name": tourist.name,
                    "email": tourist.email,
                    "contact_number": tourist.contact_number,
                },
                "reservations": [
                    {
                        "beach": res.beach.name,
                        "date": res.date_reserved.strftime("%Y-%m-%d"),
                        "num_people": res.num_people,
                        "total_price": str(res.total_price),
                        "payment_method": res.payment_method,
                        "payment_status": res.payment_status,
                    }
                    for res in reservations
                ]
            }
        else:
            data = {"status": "no_reservation"}
    except Tourist.DoesNotExist:
        data = {"status": "error", "message": "Invalid QR Code"}

    return JsonResponse(data)



@login_required
@user_passes_test(is_collector)
@csrf_exempt
def approve_reservation(request, reservation_id):
    if request.method == "POST":
        try:
            reservation = Reservation.objects.get(id=reservation_id)

            # If already approved, block further changes
            if reservation.approved:
                return JsonResponse({"success": False, "message": "Reservation is already approved!"})

            # Mark as approved
            reservation.approved = True

            # If payment method is cash and still pending, mark as paid
            if reservation.payment_method == "cash" and reservation.payment_status == "pending":
                reservation.payment_status = "paid"

            reservation.save()

            return JsonResponse({"success": True, "message": "Reservation approved successfully!"})

        except Reservation.DoesNotExist:
            return JsonResponse({"success": False, "message": "Reservation not found."})

    return JsonResponse({"success": False, "message": "Invalid request method."})


@login_required
@user_passes_test(is_collector)
def toggle_approval(request, reservation_id):
    collector = get_object_or_404(Collector, user=request.user)  # Get the collector based on logged-in user
    reservation = get_object_or_404(Reservation, id=reservation_id)
    tourist = reservation.tourist  # Access the tourist directly from the reservation

    if not reservation.approved:
        reservation.approved = True  # Mark as approved

        # Update the payment status if the payment method is 'cash'
        if reservation.payment.payment_method == 'cash' and reservation.payment.status == 'pending':
            reservation.payment.status = 'paid'  # Update status to 'paid' upon approval
            reservation.payment.save()

        reservation.approved_by = collector  # Assign the approving collector
        reservation.date_reserved = timezone.now()

        reservation.save()

    return redirect('beach_scanner_token', token=tourist.token)  # Redirect using tourist's token
