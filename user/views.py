import secrets, base64
from django.contrib.auth import authenticate, logout, login, update_session_auth_hash
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.http import JsonResponse

from pass_manager.crypt import encrypt_main_key, decrypt_main_key, encrypt_aes_256, decrypt_aes_256, hash_password
from pass_manager.models import Data
from pass_manager.otp import generate_otp
from django.utils.safestring import mark_safe
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages

from django.contrib.auth import get_user_model

User = get_user_model()


def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        user_password = request.POST['password']

        # Check if username or email already exists
        if User.objects.filter(username=username).exists():
            error_message = 'Username already taken. Please choose a different one or <a href="/login/">login</a>'
            messages.error(request, mark_safe(error_message))
            return redirect('/register/')

        if User.objects.filter(email=email).exists():
            error_message = 'Email already taken. Please use a different one or <a href="/login/">login</a>'
            messages.error(request, mark_safe(error_message))
            return redirect('/register/')

        # Check if password is too short
        if len(user_password) < 8:
            messages.warning(request, 'Password is too short. Please choose at least 8 symbols or generate reliable')
            return redirect('/register/')

        salt = secrets.token_bytes(32)
        encrypted_main_key = encrypt_main_key(user_password, salt)

        request.session['user_password'] = user_password
        # Create the user
        user = User.objects.create_user(username=username, email=email, password=user_password, salt=salt,
                                        encrypted_main_key=encrypted_main_key)
        user.save()

        user = authenticate(request, username=username, password=user_password)

        login(request, user)
        return redirect('/', {"username": username})

    return render(request, 'registration.html')


def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        user_password = request.POST['password']

        user = authenticate(request, username=username, password=user_password)
        if user is not None:
            login(request, user)
            request.session['user_password'] = user_password
            user_password = request.session.get('user_password')

            return redirect('/', {"username": username, 'user_password': user_password})
        else:
            return render(request, 'login_failed.html')

    return render(request, 'login.html')


def user_logout(request):
    logout(request)
    return redirect('/')


def user_info(request, user_id):
    if not request.user.is_authenticated:
        return redirect('/')
    encrypted_main_key = User.objects.get(id=user_id).encrypted_main_key
    salt = User.objects.get(id=user_id).salt

    user_password = request.session.get('user_password')
    main_key = decrypt_main_key(user_password, salt, encrypted_main_key)

    user = User.objects.get(id=user_id)
    all_services = Data.objects.filter(user=user)

    service_data = []
    for service in all_services:
        otp_secret = decrypt_aes_256(service.totp_secret, main_key)
        otp = ''
        time_remaining = ''
        if otp_secret:
            otp, time_remaining = generate_otp(otp_secret)

        service_data.append(
            {
                'id': service.id,
                'service_name': decrypt_aes_256(service.service_name, main_key),
                'service_url': decrypt_aes_256(service.service_url, main_key),
                'login': decrypt_aes_256(service.login, main_key),
                'password': decrypt_aes_256(service.password, main_key),
                'totp_secret': otp_secret,
                'notes': decrypt_aes_256(service.notes, main_key),
                'otp': otp,
                'time_remaining': time_remaining
            }
        )
    return render(request, 'user_page.html', {'services': service_data, 'user_id': user_id})

def change_password(request, user_id):
    if not request.user.is_authenticated:
        return redirect('/')

    encrypted_main_key = User.objects.get(id=user_id).encrypted_main_key
    salt = User.objects.get(id=user_id).salt
    tmp = User.objects.get(id=user_id)

    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            old_password = form.cleaned_data['old_password']
            new_password = form.cleaned_data['new_password1']
            user = form.save()
            tmp.set_password(new_password)
            tmp.save()
            update_session_auth_hash(request, user)

            main_key = decrypt_main_key(old_password, salt, encrypted_main_key)
            main_key = base64.b64encode(main_key).decode('utf-8')
            temp_encryption_key = hash_password(new_password, salt)

            encrypted_main_key = encrypt_aes_256(str(main_key), temp_encryption_key)
            tmp.encrypted_main_key = encrypted_main_key
            tmp.save()

            user = authenticate(request, username=tmp.username, password=new_password)
            if user is not None:
                login(request, user)
                return render(request, 'change_succes.html', {'user_id': user_id, 'user_password': new_password})
            else:
                messages.error(request, 'Failed to log in with the new password.')
    else:
        form = PasswordChangeForm(request.user)

    return render(request, 'change_password.html', {'form': form})

def about(request):
    return render(request, 'about.html')
