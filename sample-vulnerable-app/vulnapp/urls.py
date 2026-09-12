from django.urls import path

from core import views

urlpatterns = [
    path("users/search", views.search_users),
    path("users/<int:user_id>", views.user_detail),
    path("feedback", views.submit_feedback),
    path("ping", views.ping_host),
    path("reports/export", views.export_report),
]
