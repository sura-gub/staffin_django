from django.contrib import admin
from django.urls import include,path
urlpatterns = [
    path('admin_panel', admin.site.urls),
    path('', include('sheet.urls')),
]