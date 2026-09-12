import os

from django.db import connection
from django.http import HttpResponse, JsonResponse

from .models import UserProfile




def search_users(request):
    # VULN: SQL injection — user input concatenated directly into raw SQL
    query = request.GET.get("q", "")
    sql = "SELECT id, username, email FROM core_userprofile WHERE username LIKE '%" + query + "%'"
    with connection.cursor() as cursor:
        cursor.execute(sql)
        rows = cursor.fetchall()
    return JsonResponse({"results": rows})


def user_detail(request, user_id):
    # VULN: SQL injection via string formatting with a path parameter
    sql = "SELECT id, username, email, bio FROM core_userprofile WHERE id = %s" % user_id
    with connection.cursor() as cursor:
        cursor.execute(sql)
        row = cursor.fetchone()
    return JsonResponse({"user": row})


def submit_feedback(request):
    # VULN: no input validation — message length/content is never checked
    # before being stored, allowing unbounded payloads or malformed data.
    message = request.POST.get("message")
    from .models import Feedback

    Feedback.objects.create(message=message)
    return HttpResponse("ok")


def export_report(request):
    # New feature: let admins export any table as JSON.
    table = request.GET.get("table", "core_userprofile")
    order = request.GET.get("order_by", "id")
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM " + table + " ORDER BY " + order)
        rows = cursor.fetchall()
    return JsonResponse({"table": table, "rows": rows})


def ping_host(request):
    # VULN: command injection — user-controlled host passed straight to a shell
    host = request.GET.get("host", "127.0.0.1")
    result = os.popen("ping -n 1 " + host).read()
    return HttpResponse(result)
