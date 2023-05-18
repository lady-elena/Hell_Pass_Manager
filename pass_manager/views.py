from django.core.checks import messages
from user.views import user_info
from .crypt import encrypt_aes_256, decrypt_main_key
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseNotFound, HttpResponse
from .models import Data
from django.contrib.auth import get_user_model
from .forms import UserForm

User = get_user_model()


def main_page(request):
    """
    Renders the main page where users can register, log in, or generate a random password without registration and saving it.
    """
    user_id = request.user.id
    return render(request, "main_page.html", {'user_id': user_id, })


def save_data(request, user_id):
    if not request.user.is_authenticated:
        return redirect('/')

    encrypted_main_key = User.objects.get(id=user_id).encrypted_main_key
    salt = User.objects.get(id=user_id).salt
    user_password = request.session.get('user_password')
    if user_password is None:
        error_message = 'Session expired. Please <a href="/login/">login</a> again.'
        return redirect('/login/')

    if request.method == "POST":
        service_name = request.POST['service_name']
        service_url = request.POST['service_url']
        login = request.POST['login']
        password = request.POST['password']
        totp_secret = request.POST['totp_secret']
        notes = request.POST['notes']

        main_key = decrypt_main_key(user_password, salt, encrypted_main_key)

        new_data = Data(
            user_id=user_id,
            service_name=encrypt_aes_256(service_name, main_key),
            service_url=encrypt_aes_256(service_url, main_key),
            login=encrypt_aes_256(login, main_key),
            password=encrypt_aes_256(password, main_key),
            totp_secret=encrypt_aes_256(totp_secret, main_key),
            notes=encrypt_aes_256(notes, main_key)
        )
        new_data.save()

        return render(request, 'success.html', {"user_id": user_id})

    return render(request, 'save_data.html', {"user_id": user_id})


def edit_item(request, item_id):
    if not request.user.is_authenticated:
        return redirect('/')

    try:
        item = Data.objects.get(id=item_id)
    except Data.DoesNotExist:
        return HttpResponseNotFound()

    form = UserForm()
    if request.method == "POST":
        form = UserForm(request.POST)
        if form.is_valid():
            service_name = form.cleaned_data["service_name"]
            service_url = form.cleaned_data["service_url"]
            login = form.cleaned_data["login"]
            password = form.cleaned_data["password"]
            totp_secret = form.cleaned_data["totp_secret"]
            notes = form.cleaned_data["notes"]

            return HttpResponse(f"<h2>Edit</h2>")
    return render(request, "index.html", {"form": form})

    # user_id = Data.objects.get(id=item_id).user_id
    # user_info(request, user_id)
    #
    # encrypted_main_key = User.objects.get(id=user_id).encrypted_main_key
    # salt = User.objects.get(id=user_id).salt
    # edited_data = User.objects.get(id=user_id)
    #
    # if request.method == 'POST':
    #     form = UserForm(request.user, request.POST)
    #     if form.is_valid():
    #         old_password = form.cleaned_data['old_password']
    #         new_password = form.cleaned_data['new_password1']
    #         user = form.save()
    #         tmp.set_password(new_password)
    #         tmp.save()
    #         update_session_auth_hash(request, user)
    #
    #         main_key = decrypt_main_key(old_password, salt, encrypted_main_key)
    #         main_key = base64.b64encode(main_key).decode('utf-8')
    #         temp_encryption_key = hash_password(new_password, salt)
    #
    #         encrypted_main_key = encrypt_aes_256(str(main_key), temp_encryption_key)
    #         tmp.encrypted_main_key = encrypted_main_key
    #         tmp.save()
    #
    #         user = authenticate(request, username=tmp.username, password=new_password)
    #         if user is not None:
    #             login(request, user)
    #             return render(request, 'change_succes.html', {'user_id': user_id, 'user_password': new_password})
    #         else:
    #             messages.error(request, 'Failed to log in with the new password.')
    # else:
    #     form = PasswordChangeForm(request.user)
    #
    # return render(request, 'change_password.html', {'form': form})

    # if request.method == 'POST':
    #     item.service_name = request.POST.get('service_name', item.service_name)
    #     item.service_url = request.POST.get('service_url', item.service_url)
    #     item.login = request.POST.get('login', item.login)
    #     item.password = request.POST.get('password', item.password)
    #     item.totp_secret = request.POST.get('totp_secret', item.totp_secret)
    #     item.notes = request.POST.get('notes', item.notes)
    #
    #     item.save()
    #
    #     try:
    #         data = Data.objects.get(id=item_id)
    #         data.service_name = service_name
    #         data.service_url = service_url
    #         data.login = login
    #         data.password = password
    #         data.otp = otp
    #         data.notes = notes
    #         data.save()
    #         return JsonResponse({"success": True})
    #     except Data.DoesNotExist:
    #         return JsonResponse({"error": "Item not found"})
    #
    #     return HttpResponse('done')
    #
    # return render(request, 'edit.html', {'item': item})


def delete_item(request, item_id):
    if not request.user.is_authenticated:
        return redirect('/')
    item = Data.objects.filter(id=item_id)
    item.delete()
    return JsonResponse({"success": True})
