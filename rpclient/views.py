from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.template import loader 
from django.shortcuts import render, get_object_or_404
from .models import AuthReq, RP, IdP

from jwt.algorithms import RSAAlgorithm
from Crypto.PublicKey import RSA
from urllib.parse import parse_qsl
from jwkest import long_to_base64
from random import *

import requests
import json
import base64
import jwt
import time
import rsa

# ###########################
# Initial request for webapp.
# ###########################
def index(request):	
	return render(request, 'rpclient/index.html')


# #############################################################
# Show list of RP and IdP available for Authentication Request.
# #############################################################
def iniciaAuth(request):
	listRP = RP.objects.order_by('-host')
	listIdP = IdP.objects.order_by('-host')		
	return render(request, 'rpclient/authorization.html', {'listRP': listRP, 'listIdP': listIdP})


# ##################################################################### 
# Get information from RP and IdP and makes and Authentication Request.
# #####################################################################
def requestcode(request):		
	rp_id = request.POST.get("RPs",False)
	idp_id = request.POST.get("IdPs",False)
	if rp_id == False or idp_id == False:
		tipoE = "Error getting RP and IdP information from Authentication Request." 
		return render(request, 'rpclient/error.html', {'tipoE': tipoE})
	objRP = RP.objects.get(pk=rp_id)
	objIdP = IdP.objects.get(pk=idp_id)
	
	url_idp = objIdP.url_authorize
	respType = "code"
	min_char = 20
	max_char = 20
	char_set = '1234567890.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
	state = "".join(choice(char_set) for x in range(randint(min_char, max_char)))
	min_char = 15
	max_char = 15
	nonce = "".join(choice(char_set) for x in range(randint(min_char, max_char)))
	acr = "2"

	# application/x-www-form-urlencoded format.	
	url_param = "?client_id=" + objRP.client_id
	url_param = url_param + "&response_type=" + respType
	url_param = url_param + "&scope=" + objRP.scope
	url_param = url_param + "&redirect_uri=" + objRP.redirect_uri
	url_param = url_param + "&nonce=" + nonce
	url_param = url_param + "&state=" + state
	url_param = url_param + "&acr_values=" + acr
	
	authenticationR = AuthReq()
	authenticationR.response_type = respType
	authenticationR.client_id = objRP.client_id
	authenticationR.redirect_uri = objRP.redirect_uri
	authenticationR.state = state	
	#authenticationR.nonce = '0' # Nonce created by IdP 
	authenticationR.nonce = nonce 
	authenticationR.hostIdP = objIdP.host
	authenticationR.save()

	response = HttpResponseRedirect(url_idp + url_param)  
	response.set_cookie('stateOIDC', str(state))  
	return response


# #####################
# Token Access Request. 
# #####################
def requesttoken(request):
	if request.method == 'GET':
		tipoE = "Error with Token Request. Bad http pettion (GET instead of POST)."
		return render(request, 'rpclient/error.html', {'tipoE': tipoE})
	code = request.POST.get("Auth_code",False)
	RP_host = request.POST.get("RP_host",False)
	IdP_url_authorize = request.POST.get("IdP_url_authorize",False)
	if code == False or RP_host == False or IdP_url_authorize == False:
		tipoE = "Error with Token Request. There is not Auth_Code."
		return render(request, 'rpclient/error.html', {'tipoE': tipoE})

	IdP_token = IdP.objects.filter(url_authorize__icontains=IdP_url_authorize).first()
	objRP = RP.objects.filter(host__icontains=RP_host).first()
	
	# Request token
	if request.is_secure():
		H = 'https://'
	else:
		H = 'http://'
	if (RP_host.find(H) != -1):
		HostRP = RP_host[len(H):] 
	else:
		HostRP = RP_host
	userpass = objRP.client_id + ":" + objRP.client_password
	payload = {'code': code, 'grant_type': 'authorization_code', 'redirect_uri': objRP.redirect_uri}
	credenciales = base64.b64encode(userpass.encode('utf-8'))	
	headers = {'Host': HostRP, 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': "Basic " + credenciales.decode('utf-8')}
	if not IdP_token.url_acces_token.endswith('/'):
		IdP_access_token = IdP_token.url_acces_token + "/"
	else:
		IdP_access_token = IdP_token.url_acces_token
	pt = requests.post(IdP_access_token, data=payload, headers=headers)	

	# Get token
	try:	
		tokenj = json.loads(pt.text)
	except: 
		tipoE = "Error getting Token. Not Token found."
		return render(request, 'rpclient/error.html', {'tipoE': tipoE})
	try:
		tokenID = tokenj["id_token"]
	except KeyError:
		tipoE = "Error parsing Token. There is not Token_ID." 
		return render(request, 'rpclient/error.html', {'tipoE': tipoE})

	# Validate signature from Token.
	Pkey = IdP_token.public_key.replace('\\n', '\n')
	if IdP_token.public_key == "":
		tipoE = "Error. There is not public key from IdP."
		return render(request, 'rpclient/error.html', {'tipoE': tipoE})
	pub_key = RSA.importKey(Pkey)
	n = long_to_base64(pub_key.n)
	e = long_to_base64(pub_key.e)
	key_json = '{"kty": "RSA","alg": "RS256","use": "sig", "kid": "RP for testing", "n": "' + n + '", "e": "' + e + '"}'
	p_key = RSAAlgorithm.from_jwk(key_json)
	
	try:
		decodee = jwt.decode(tokenID, p_key, algorithm='RS256', audience=objRP.client_id)
	except jwt.exceptions.InvalidSignatureError:
		tipoE = "Error. Invalid signature from Token." 
		return render(request, 'rpclient/error.html', {'tipoE': tipoE})
	
	# Show Token.
	HeaderTokenID = tokenID.split('.')[0]
	BodyTokenID = tokenID.split('.')[1]
	SignatureTokenID = tokenID.split('.')[2] 

	HeaderTokenID = base64.b64decode(HeaderTokenID + "===").decode('utf-8')
	BodyTokenID = base64.b64decode(BodyTokenID + "===").decode('utf-8')
	HeaderTokenID = json.loads(HeaderTokenID)
	BodyTokenID = json.loads(BodyTokenID)

	try:
		authenticationR = AuthReq.objects.get(codeA=code)
	except  AuthReq.DoesNotExist:
		tipoE = "Error handling code associated to Token."
		return render(request, 'rpclient/error.html', {'tipoE': tipoE})

	if 'nonce' in BodyTokenID:
		if authenticationR.nonce != '0': # Nonce created by RP: Check it.
			if BodyTokenID['nonce'] != authenticationR.nonce:
				tipoE = "Error. Nonce mismatch."
				return render(request, 'rpclient/error.html', {'tipoE': tipoE})
	else:
		tipoE = "Error. Nonce not found in Token."
		return render(request, 'rpclient/error.html', {'tipoE': tipoE})

	return render(request, 'rpclient/showtoken.html', {'pt': pt.url, 'tokenj': tokenj, 'HeaderTokenID': HeaderTokenID, 'BodyTokenID': BodyTokenID} )


# #######################
# Get Auth_Code from IdP.
# #######################
def oidc(request):
	if request.method == 'GET':    	
		code = request.GET.get('code',False)
		scope = request.GET.get('scope',False)
		state = request.GET.get('state',False)
		if code == False or scope == False:
			tipoE = "Error getting Authentication Request whitout 'code', 'scope' or 'state' parameters." 
			return render(request, 'rpclient/error.html', {'tipoE': tipoE})			
		try:
			authenticationR = AuthReq.objects.get(state=state)
		except  AuthReq.DoesNotExist:
			raise Http404("Error with state parameter in Auth Request.")

		if 'stateOIDC' in request.COOKIES:
			valueC = request.COOKIES['stateOIDC']
			if authenticationR.state != valueC:
				tipoE = "Error retrying parameters. 'state' mismach"
				return render(request, 'rpclient/error.html', {'tipoE': tipoE})
		else:
			tipoE = "Error retrying parameters. No 'state' found"
			return render(request, 'rpclient/error.html', {'tipoE': tipoE})			
		authenticationR.codeA = code
		authenticationR.save()
		if request.is_secure():
			H = 'https://'
		else:
			H = 'http://'
		try:			
			objRP = RP.objects.get(host=H+request.META['HTTP_HOST'])			
		except 	RP.DoesNotExist:
			raise Http404("RP does not exist.")
		objIdP = IdP.objects.get(host=authenticationR.hostIdP)
		return render(request, 'rpclient/requesttoken.html', {'authenticationR': authenticationR, 'objRP': objRP, 'objIdP': objIdP})
	else:
		tipoE = "Error getting Authentication Request with POST (instead of GET)."
		return render(request, 'rpclient/error.html', {'tipoE': tipoE})
