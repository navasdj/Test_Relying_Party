from django.contrib import admin

from .models import AuthReq, RP, IdP

admin.site.register(AuthReq)
admin.site.register(RP)
admin.site.register(IdP)

