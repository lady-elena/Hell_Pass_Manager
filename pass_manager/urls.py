from django import views
from django.contrib import admin
from django.urls import path
from pass_manager import views, otp

urlpatterns = [
    path('', views.main_page),
    path("getotp/<str:secret_key>/", otp.generate_otp),
    path("save/<int:user_id>/", views.save_data),
    path("delete_item/<int:item_id>/", views.delete_item),
    path('edit_item/<int:item_id>/', views.edit_item)

]
