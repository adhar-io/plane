# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import os
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse

import pytz
import requests

# Module imports
from plane.authentication.adapter.oauth import OauthAdapter
from plane.license.utils.instance_value import get_configuration_value
from plane.authentication.adapter.error import (
    AUTHENTICATION_ERROR_CODES,
    AuthenticationException,
)

# Keycloak is reached over the cluster network in a platform install, so a
# discovery or token call must not be able to hang a gunicorn worker.
DISCOVERY_TIMEOUT = 5
USERINFO_TIMEOUT = 10

# The three discovery entries this provider needs. `authorization_endpoint` is
# browser-facing; the other two are called by the API server (backchannel).
FRONTCHANNEL_ENDPOINTS = ("authorization_endpoint",)
BACKCHANNEL_ENDPOINTS = ("token_endpoint", "userinfo_endpoint")


def _not_configured():
    # The detail is deliberately not echoed into redirect query params: the
    # issuer is operator-supplied configuration, not user input.
    return AuthenticationException(
        error_code=AUTHENTICATION_ERROR_CODES["KEYCLOAK_NOT_CONFIGURED"],
        error_message="KEYCLOAK_NOT_CONFIGURED",
    )


def _normalise_issuer(value):
    """Enforce an http(s) URL with a host and drop trailing slashes.

    Mirrors the Gitea provider's host validation — a scheme-less or non-HTTP
    issuer is a configuration error, never something to try to "fix up".
    """
    parsed = urlparse(value)
    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        raise _not_configured()
    return value.rstrip("/")


class KeycloakOAuthProvider(OauthAdapter):
    """Generic OIDC login against Keycloak.

    Endpoints come from the issuer's OpenID discovery document rather than being
    assembled by hand: Keycloak moved its realm paths from `/auth/realms/<realm>`
    to `/realms/<realm>` in version 17, so hardcoding either shape breaks on the
    other. `KEYCLOAK_ISSUER_URL` is therefore the single thing an operator must
    set (e.g. `https://keycloak.example.com/realms/adhar`) and everything else is
    read from `<issuer>/.well-known/openid-configuration`.

    Split-horizon deployments (the Adhar platform is one) can additionally set
    `KEYCLOAK_INTERNAL_ISSUER_URL`, e.g.
    `http://keycloak.keycloak.svc.cluster.local:8080/keycloak/realms/adhar`.
    Discovery, the code-for-token exchange and the userinfo call then go to that
    address over the private network, while the browser is still sent to the
    public issuer for the login page. This is the same frontchannel/backchannel
    split Keycloak itself documents (`hostname-strict-backchannel`), and it means
    the API server never has to trust the public ingress certificate.
    """

    provider = "keycloak"
    scope = "openid email profile"

    def __init__(self, request, code=None, state=None, callback=None):
        (
            KEYCLOAK_CLIENT_ID,
            KEYCLOAK_CLIENT_SECRET,
            KEYCLOAK_ISSUER_URL,
            KEYCLOAK_INTERNAL_ISSUER_URL,
        ) = get_configuration_value(
            [
                {
                    "key": "KEYCLOAK_CLIENT_ID",
                    "default": os.environ.get("KEYCLOAK_CLIENT_ID"),
                },
                {
                    "key": "KEYCLOAK_CLIENT_SECRET",
                    "default": os.environ.get("KEYCLOAK_CLIENT_SECRET"),
                },
                {
                    "key": "KEYCLOAK_ISSUER_URL",
                    "default": os.environ.get("KEYCLOAK_ISSUER_URL"),
                },
                {
                    "key": "KEYCLOAK_INTERNAL_ISSUER_URL",
                    "default": os.environ.get("KEYCLOAK_INTERNAL_ISSUER_URL"),
                },
            ]
        )

        if not (KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET and KEYCLOAK_ISSUER_URL):
            raise _not_configured()

        self.issuer = _normalise_issuer(KEYCLOAK_ISSUER_URL)
        self.internal_issuer = _normalise_issuer(KEYCLOAK_INTERNAL_ISSUER_URL) if KEYCLOAK_INTERNAL_ISSUER_URL else None

        endpoints = self.__discover()
        self.token_url = endpoints["token_endpoint"]
        self.userinfo_url = endpoints["userinfo_endpoint"]
        authorization_endpoint = endpoints["authorization_endpoint"]

        redirect_uri = f"{'https' if request.is_secure() else 'http'}://{request.get_host()}/auth/keycloak/callback/"
        url_params = {
            "client_id": KEYCLOAK_CLIENT_ID,
            "scope": self.scope,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
        }
        auth_url = f"{authorization_endpoint}?{urlencode(url_params)}"

        super().__init__(
            request,
            self.provider,
            KEYCLOAK_CLIENT_ID,
            self.scope,
            redirect_uri,
            auth_url,
            self.token_url,
            self.userinfo_url,
            KEYCLOAK_CLIENT_SECRET,
            code,
            callback=callback,
        )

    def __discover(self):
        """Read the three endpoints this provider needs from OIDC discovery.

        A realm that is unreachable or not yet imported is a configuration
        problem, not a user error, so it surfaces as KEYCLOAK_NOT_CONFIGURED
        rather than a provider error — the operator has something to fix.
        """
        discovery_base = self.internal_issuer or self.issuer
        well_known = f"{discovery_base}/.well-known/openid-configuration"
        try:
            response = requests.get(well_known, timeout=DISCOVERY_TIMEOUT)
            if not response.ok:
                raise _not_configured()
            document = response.json()
        except AuthenticationException:
            raise
        except (requests.RequestException, ValueError):
            raise _not_configured()

        if not isinstance(document, dict):
            raise _not_configured()

        missing = [key for key in FRONTCHANNEL_ENDPOINTS + BACKCHANNEL_ENDPOINTS if not document.get(key)]
        if missing:
            raise _not_configured()

        if self.internal_issuer:
            return self.__route(document)
        return {key: document[key] for key in FRONTCHANNEL_ENDPOINTS + BACKCHANNEL_ENDPOINTS}

    def __route(self, document):
        """Pin each endpoint to the right side of a split-horizon deployment.

        Keycloak builds every endpoint as `<some issuer>/protocol/openid-connect/…`,
        but which issuer it reports depends on how it was reached and on its
        `hostname` settings: an internal discovery call may return internal
        backchannel URLs, the public frontend URL, or even a frontend URL with
        the wrong scheme when the proxy headers are missing. Rather than depend
        on that, strip whichever issuer prefix the endpoint carries and re-base
        it: browser-facing endpoints onto the public issuer, server-to-server
        endpoints onto the internal one. Endpoints with an unrecognised prefix
        are left alone — nothing is ever invented.
        """
        reported_issuer = str(document.get("issuer") or "").rstrip("/")
        known_prefixes = [prefix for prefix in (self.internal_issuer, self.issuer, reported_issuer) if prefix]

        def rebase(endpoint, base):
            for prefix in known_prefixes:
                if endpoint.startswith(prefix + "/"):
                    return base + endpoint[len(prefix) :]
            return endpoint

        routed = {}
        for key in FRONTCHANNEL_ENDPOINTS:
            routed[key] = rebase(document[key], self.issuer)
        for key in BACKCHANNEL_ENDPOINTS:
            routed[key] = rebase(document[key], self.internal_issuer)
        return routed

    def set_token_data(self):
        data = {
            "code": self.code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        headers = {"Accept": "application/json"}
        token_response = self.get_user_token(data=data, headers=headers)
        super().set_token_data(
            {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token", None),
                "access_token_expired_at": (
                    datetime.now(tz=pytz.utc) + timedelta(seconds=token_response.get("expires_in"))
                    if token_response.get("expires_in")
                    else None
                ),
                "refresh_token_expired_at": (
                    datetime.now(tz=pytz.utc) + timedelta(seconds=token_response.get("refresh_expires_in"))
                    if token_response.get("refresh_expires_in")
                    else None
                ),
                "id_token": token_response.get("id_token", ""),
            }
        )

    def set_user_data(self):
        user_info_response = self.get_user_response()

        email = user_info_response.get("email")
        # An unverified address must never log in. Keycloak can federate or
        # self-register users, so `email` alone is an unproven claim: accepting it
        # would let anyone who can register assert an existing user's address and
        # take over that account — the same hole that was closed for the Gitea
        # provider in GHSA-7j95-vh8g-f365.
        if not email or not user_info_response.get("email_verified"):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OAUTH_PROVIDER_UNVERIFIED_EMAIL"],
                error_message="OAUTH_PROVIDER_UNVERIFIED_EMAIL",
            )

        # `sub` is the only claim Keycloak guarantees is stable and unique for the
        # life of the account; username and email can both be changed in the realm.
        provider_id = user_info_response.get("sub")
        if not provider_id:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["KEYCLOAK_OAUTH_PROVIDER_ERROR"],
                error_message="KEYCLOAK_OAUTH_PROVIDER_ERROR",
            )

        super().set_user_data(
            {
                "email": email,
                "user": {
                    "provider_id": str(provider_id),
                    "email": email,
                    "avatar": user_info_response.get("picture"),
                    "first_name": (
                        user_info_response.get("given_name")
                        or user_info_response.get("name")
                        or user_info_response.get("preferred_username")
                    ),
                    "last_name": user_info_response.get("family_name") or "",
                    "is_password_autoset": True,
                },
            }
        )
