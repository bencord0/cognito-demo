import base64
import boto3
import json
import requests
from datetime import datetime, timedelta, timezone
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.shortcuts import redirect, render
from allauth.socialaccount.models import SocialAccount, SocialToken
from urllib.parse import quote_plus

sts = boto3.client('sts', region_name='eu-west-2')


@login_required
def index(request):
    return render(request, 'index.html')


@login_required
def signin(request):
    try:
        signin_url = generate_signin_url(request.user)
    except requests.exceptions.HTTPError:
        # Force a re-login to fetch new tokens
        logout(request)

    return redirect(signin_url, permanent=False)


def generate_signin_url(user):
    socialtoken = SocialToken.objects.get(account__user=user)
    socialaccount = SocialAccount.objects.get(user=user)

    now = datetime.now(tz=timezone.utc)
    if socialtoken.expires_at < now:
        # Token has expired
        socialtoken = refresh_token(socialtoken)

    id_token = socialtoken.id_token

    # Exchange the id_token for an IAM credential
    session_name = f'Slack_{socialaccount.uid}'
    credentials = sts.assume_role_with_web_identity(
        RoleArn='arn:aws:iam::055237546114:role/SlackUser',
        RoleSessionName=session_name,
        WebIdentityToken=id_token,
    )['Credentials']

    temporary_credentials = json.dumps({
        'sessionId': credentials['AccessKeyId'],
        'sessionKey': credentials['SecretAccessKey'],
        'sessionToken': credentials['SessionToken'],
    })
    session = quote_plus(temporary_credentials)

    params = f'Action=getSigninToken&SessionDuration=3600&Session={session}'
    token_url = f'https://signin.aws.amazon.com/federation?{params}'

    # Exchange for a signin token
    signin_token = requests.get(token_url).json()['SigninToken']

    destination = quote_plus('https://console.aws.amazon.com')
    params = f'Action=login&Issuer=localhost&Destination={destination}&SigninToken={signin_token}'
    signin_url = f'https://signin.aws.amazon.com/federation?{params}'
    return signin_url


def refresh_token(token: SocialToken) -> SocialToken:
    client_id = token.app.client_id
    client_secret = token.app.secret
    refresh_token = token.token_secret

    basic_token = base64.b64encode(f'{client_id}:{client_secret}'.encode()).decode()
    payload = {
        'grant_type': 'refresh_token',
        'client_id': client_id,
        'refresh_token': refresh_token,
    }

    token_url = 'https://condi.auth.eu-west-2.amazoncognito.com/oauth2/token'
    response = requests.post(token_url, headers={
        'Authorization': f'Basic {basic_token}',
    }, data=payload)

    # Raises `requests.exceptions.HTTPError`
    response.raise_for_status()

    new_tokens = response.json()
    token.token = new_tokens['access_token']
    token.id_token = new_tokens['id_token']
    new_expiry = datetime.now(timezone.utc) + timedelta(seconds=new_tokens['expires_in'])
    token.expiry = new_expiry
    token.save()

    return token
