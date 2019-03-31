from django.urls import path

from . import views 

app_name = 'rpclient'
urlpatterns = [
	path('', views.index, name='index'),
	path('oidc/', views.oidc, name='oidc'),	
	path('iniciaAuth/', views.iniciaAuth, name='iniciaAuth'), 
	path('requesttoken/', views.requesttoken, name='requesttoken'),
	path('requestcode/', views.requestcode, name='requestcode'),
	]
