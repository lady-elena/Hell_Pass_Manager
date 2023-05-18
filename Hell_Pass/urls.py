from django.urls import path
from django.urls import include

urlpatterns = [
    path('', include("pass_manager.urls")),
    path('', include("user.urls")),
]
