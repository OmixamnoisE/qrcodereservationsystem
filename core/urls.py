from django.urls import path
from . import views

urlpatterns = [
    path('', views.landing_page, name='landing_page'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_tourist, name='register_tourist'),
    path('logout/', views.custom_logout, name='logout'),
    
    path('admin-login/', views.login_redirect, name='login_redirect'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('generate-report/', views.generate_report, name='generate_report'),
    path('create-user/', views.create_user, name='create_user'),
    path('delete_user/<int:user_id>/', views.delete_user, name='delete_user'),
    path('edit-collector-profile/', views.edit_collector_profile, name='edit_collector_profile'),
    path('create-beach/', views.create_beach, name='create_beach'),
    path('edit-beach/<int:beach_id>/', views.edit_beach, name='edit_beach'),
    path('manage-tourists/', views.manage_tourists, name='manage_tourists'),
    path('delete-tourist/<str:token>/', views.delete_tourist, name='delete_tourist'),
    path('admin-users/', views.manage_users, name='manage_users'),
    path('admin-users/toggle-collector-status/<int:id>/', views.toggle_collector_status, name='toggle_collector_status'),
    path('admin-users/delete-collector/<int:id>/', views.delete_collector, name='delete_collector'),
    path('admin-users/delete/<int:user_id>/', views.delete_user, name='delete_user'),
    path('admin-beaches/', views.manage_beaches, name='manage_beaches'),
    path('admin-beach/toggle/<int:beach_id>/', views.toggle_beach_status, name='toggle_beach_status'),
    path('admin-beach/delete/<int:beach_id>/', views.delete_beach, name='delete_beach'),

    path('cashier-dashboard/', views.cashier_dashboard, name='cashier_dashboard'),
    path("cashier-transactions/", views.cashier_transactions, name="cashier_transactions"),
    path("update-payment-status/<int:payment_id>/", views.update_payment_status, name="update_payment_status"),
    path('generate_report/', views.cashier_generate_report, name='cashier_generate_report'),  # For PDF
    path('generate_csv_report/', views.cashier_generate_csv_report, name='cashier_generate_csv_report'),

    path('beach-dashboard/', views.beach_dashboard, name='beach_dashboard'),
    path('generate-pdf/', views.generate_pdf_report, name='generate_pdf_report'),
    path('beach-dashboard/approve_reservation/<int:reservation_id>/', views.approve_reservation, name='approve_reservation'),
    path('edit-collector-profile/<int:collector_id>/', views.edit_collector_profile, name='edit_collector_profile'),
    path('beach-reservation/', views.beach_reservation, name='beach_reservation'),
    path("beach-create-reservation/", views.beach_create_reservation, name="beach_create_reservation"),
    path('beach-qrscanner/', views.beach_qrscanner, name='beach_qrscanner'),
    path('beach_scanner_token/<str:token>/', views.beach_qrscanner_token, name='beach_qrscanner_token'),
    path('get-reservations/', views.get_reservations, name='get_reservations'), 
    path("confirm-payment-tourist/<int:reservation_id>/", views.confirm_payment_tourist, name="confirm_payment_tourist"),
    path("scan_qr/<str:qr_code>/", views.scan_qr_code, name="scan_qr_code"),
    path('process-gcash-receipt/', views.process_gcash_receipt, name='process_gcash_receipt'),
    path('approve-reservation/<int:reservation_id>/', views.approve_reservation, name='approve_reservation'),
    path('toggle_reservation_approval/<int:reservation_id>/', views.toggle_approval, name='toggle_approval'),
    path('beach_scanner_token/<str:token>/', views.beach_qrscanner_token, name='beach_scanner_token'),
    
    
    path("verify-tourist/<str:token>/", views.verify_tourist, name="verify_tourist"),
    path('resend-verification-email/', views.resend_verification_email, name='resend_verification_email'),
    path('tourist-dashboard/', views.tourist_dashboard, name='tourist_dashboard'),
    path('update-reservation/', views.update_reservation, name='update_reservation'),
    path('reservation/cancel/<int:reservation_id>/', views.cancel_reservation, name='cancel_reservation'),
    path("delete-reservation/", views.delete_reservation, name="delete_reservation"),
    path("update-profile/", views.update_profile, name="update_profile"),
    path("create-reservation/", views.create_reservation, name="create_reservation"),
]
