from django import forms
from django.contrib.auth import get_user_model 
from .models import Beach, Tourist, Reservation, Payment

CustomUser = get_user_model()

class BeachForm(forms.ModelForm):
    class Meta:
        model = Beach
        fields = ['name', 'description', 'location', 'image']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'w-full border border-gray-300 rounded-md px-4 py-2',
                'placeholder': 'Enter beach name'
            }),
            'location': forms.TextInput(attrs={
                'class': 'w-full border border-gray-300 rounded-md px-4 py-2',
                'placeholder': 'Enter beach location'
            }),
            'description': forms.Textarea(attrs={
                'class': 'w-full border border-gray-300 rounded-md px-4 py-2',
                'rows': 4,
                'placeholder': 'Describe the beach, amenities, and attractions...'
            }),
            'image': forms.ClearableFileInput(attrs={
                'class': 'w-full border border-gray-300 rounded-md px-4 py-2 bg-white cursor-pointer'
            }),
        }

class TouristRegistrationForm(forms.ModelForm):
    username = forms.CharField(max_length=150)
    password1 = forms.CharField(widget=forms.PasswordInput)
    password2 = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = Tourist
        fields = [
            'first_name', 'middle_name', 'last_name', 'nickname', 'email', 
            'contact_number', 'age', 'address', 'gender', 'tourist_type', 'country'
        ]

    def clean(self):
        cleaned_data = super().clean()
        tourist_type = cleaned_data.get("tourist_type")

        if tourist_type == "local":
            cleaned_data["country"] = "Philippines"  # Force country to Philippines

        return cleaned_data

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match.")
        return password2

    def save(self, commit=True):
        # Create the user account
        user = CustomUser.objects.create_user(
            username=self.cleaned_data['username'],
            email=self.cleaned_data['email'],
            password=self.cleaned_data['password1']
        )

        # Save tourist details
        tourist = super().save(commit=False)
        tourist.user = user

        # Ensure country is "Philippines" if tourist_type is "local"
        if tourist.tourist_type == "local":
            tourist.country = "Philippines"

        if commit:
            tourist.save()
        return tourist

    
class ResendVerificationForm(forms.Form):
    email = forms.EmailField()



class ReservationForm(forms.ModelForm):
    # Use the Payment model's PAYMENT_METHODS for the payment_method field
    payment_method = forms.ChoiceField(
        choices=Payment.PAYMENT_METHODS,  # Use the choices from the Payment model
        required=False
    )

    class Meta:
        model = Reservation
        fields = ['date_reserved', 'num_people']


class DateFilterForm(forms.Form):
    start_date = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}), label="Start Date")
    end_date = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}), label="End Date")


class ReportForm(forms.Form):
    prepared_by = forms.CharField(label='Prepared By', max_length=100)