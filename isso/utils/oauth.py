# -*- encoding: utf-8 -*-

from __future__ import unicode_literals

import json

from werkzeug.exceptions import NotFound
from requests_oauthlib import OAuth2Session

class OAuthProvider(object):

    def __init__(self, conf):
        provider = type(self).__name__.lower()
        self.client_id = conf.get("oauth-" + provider, "client_id")
        self.client_secret = conf.get("oauth-" + provider, "client_secret")
        self.redirect_uri = 'http://localhost:8080/auth/callback/' + provider
        self.oauth2 = OAuth2Session(self.client_id,
                                    scope=self.scope,
                                    redirect_uri=self.redirect_uri)
    def signin(self):
        return self.oauth2.authorization_url(self.auth_url,
                                             access_type="offline",
                                             approval_prompt="force")[0]

    def callback(self, request_url):
        request_url = request_url.replace('http://', 'https://')
        self.oauth2.fetch_token(
            self.token_url,
            client_secret=self.client_secret,
            authorization_response=request_url
        )
        r = json.loads(self.oauth2.get(self.profile_url).content)
        print json.dumps(r, indent=4, separators=(',', ': '))
        user_data = (
            r[self.keys[0]],
            r.get(self.keys[1]),
            r.get(self.keys[2]),
        )
        return user_data

class Github(OAuthProvider):

    scope = None
    keys = ('login', 'email', 'blog',)
    auth_url = "https://github.com/login/oauth/authorize"
    token_url = "https://github.com/login/oauth/access_token"
    profile_url = "https://api.github.com/user"

class Google(OAuthProvider):

    scope = [
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ]
    keys = ('name', 'email', 'none')
    auth_url = "https://accounts.google.com/o/oauth2/auth"
    token_url = "https://accounts.google.com/o/oauth2/token"
    profile_url = "https://www.googleapis.com/oauth2/v1/userinfo"



def get_provider(conf, provider):
    if not provider in conf.get("auth", "providers"):
        raise NotFound
    providers = {
        'github': Github,
        'google': Google
    }
    try:
        return providers[provider]
    except KeyError:
        raise NotFound
