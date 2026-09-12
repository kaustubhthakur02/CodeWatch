import os
import re
import subprocess

from django.db import connection
from django.http import HttpResponse, JsonResponse

from .models import UserProfile


def search_users(request):
    query = request.GET.get("q", "")
    sql = "SELECT id, username, email FROM core_userprofile WHERE username LIKE %%s"
    with connection.cursor() as cursor:
        cursor.execute(sql, ["%" + query + "%"])
        rows = cursor.fetchall()
    return JsonResponse({"results": rows})


def user_detail(request, user_id):
    sql = "SELECT id, username, email, bio FROM core_userprofile WHERE id = %s"
    with connection.cursor() as cursor:
        cursor.execute(sql, [user_id])
        row = cursor.fetchone()
    return JsonResponse({"user": row})


def submit_feedback(request):
    message = request.POST.get("message")
    from .models import Feedback

    Feedback.objects.create(message=message)
    return HttpResponse("ok")


def export_report(request):
    table = request.GET.get("table", "core_userprofile")
    order = request.GET.get("order_by", "id")
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM " + table + " ORDER BY " + order)
        rows = cursor.fetchall()
    return JsonResponse({"table": table, "rows": rows})


def ping_host(request):
    host = request.GET.get("host", "127.0.0.1")
    if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host):
        return HttpResponse('invalid host', status=400)
    result = subprocess.run(['ping', '-n', '1', host], shell=False, capture_output=True, text=True, timeout=5).stdout
    return HttpResponse(result)
