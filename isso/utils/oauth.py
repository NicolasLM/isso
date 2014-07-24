# -*- encoding: utf-8 -*-

from __future__ import unicode_literals

import json

from werkzeug.exceptions import NotFound
from requests_oauthlib import OAuth2Session

class Github(object):

    def __init__(self, conf):
        self.client_id = conf.get("oauth-github", "client_id")
        self.client_secret = conf.get("oauth-github", "client_secret")
        self.auth_url = conf.get("oauth-github", "auth_url")
        self.token_url = conf.get("oauth-github", "token_url")
        self.oauth2 = OAuth2Session(self.client_id)

    def signin(self):
        return self.oauth2.authorization_url(self.auth_url)[0]

    def callback(self, request_url):
        request_url = request_url.replace('http://', 'https://')
        self.oauth2.fetch_token(
            self.token_url,
            client_secret=self.client_secret,
            authorization_response=request_url
        )
        r = json.loads(self.oauth2.get('https://api.github.com/user').content)
        user_data = (
            r['login'],
        )
        return user_data


def get_provider(conf, provider):
    if not provider in conf.get("auth", "providers"):
        raise NotFound
    providers = {
        'github': Github
    }
    try:
        return providers[provider]
    except KeyError:
        raise NotFound
