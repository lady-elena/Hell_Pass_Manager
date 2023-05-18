from django.urls import path
import user.views

urlpatterns = [
    path("register/", user.views.register),
    path("login/", user.views.user_login),
    path("logout/", user.views.user_logout),
    path("profile/<int:user_id>/", user.views.user_info),
    path("change_password/<int:user_id>/", user.views.change_password),
    path("about/", user.views.about)

]
