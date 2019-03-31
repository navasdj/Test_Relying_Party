from django.db import models

class AuthReq(models.Model):
	response_type = models.CharField(max_length=100)
	client_id = models.CharField(max_length=100)
	redirect_uri = models.CharField(max_length=200)
	state = models.CharField(max_length=100)
	codeA = models.CharField(max_length=100)
	nonce = models.CharField(max_length=100)
	hostIdP = models.CharField(max_length=100)
	def __str__(self):
		return self.state
	

class IdP(models.Model):
	host = models.CharField(max_length=100)
	url_acces_token = models.CharField(max_length=100)
	url_authorize = models.CharField(max_length=100)
	url_user_info = models.CharField(max_length=100)
	public_key = models.CharField(max_length=1000) 
	def __str__(self):
		return self.host

class RP(models.Model):
	host = models.CharField(max_length=100)
	client_id = models.CharField(max_length=100)
	client_password = models.CharField(max_length=100)
	redirect_uri = models.CharField(max_length=100)
	scope = models.CharField(max_length=100)
	grant_type = models.CharField(max_length=100)
