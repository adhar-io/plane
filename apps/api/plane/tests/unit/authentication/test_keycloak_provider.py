# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Keycloak / generic OIDC provider.

The security property under test is the one that was retrofitted into the Gitea
provider as GHSA-7j95-vh8g-f365: an OAuth provider must never accept an
unverified email address. Keycloak realms routinely allow self-registration and
identity-provider federation, so `email` on its own is an unproven claim — if it
is trusted, anyone who can register in the realm can assert an existing Plane
user's address and take that account over.
"""

from unittest.mock import MagicMock, patch

import pytest

from plane.authentication.adapter.error import AuthenticationException
from plane.authentication.provider.oauth.keycloak import KeycloakOAuthProvider

ISSUER = "https://keycloak.example.com/realms/adhar"
DISCOVERY = {
    "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
    "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
    "userinfo_endpoint": f"{ISSUER}/protocol/openid-connect/userinfo",
}


def _request():
    request = MagicMock()
    request.is_secure.return_value = True
    request.get_host.return_value = "plane.example.com"
    request.session = {}
    return request


INTERNAL_ISSUER = "http://keycloak.keycloak.svc.cluster.local:8080/keycloak/realms/adhar"


def _configured(issuer=ISSUER, internal_issuer=""):
    return patch(
        "plane.authentication.provider.oauth.keycloak.get_configuration_value",
        return_value=("plane", "a-secret", issuer, internal_issuer),
    )


def _discovered(document=None, ok=True):
    response = MagicMock()
    response.ok = ok
    response.json.return_value = DISCOVERY if document is None else document
    return patch("plane.authentication.provider.oauth.keycloak.requests.get", return_value=response)


def _provider():
    with _configured(), _discovered():
        return KeycloakOAuthProvider(request=_request(), state="state")


@pytest.mark.unit
class TestKeycloakEmailVerification:
    def test_unverified_email_is_rejected(self):
        provider = _provider()
        with patch.object(
            provider,
            "get_user_response",
            return_value={"sub": "uuid-1", "email": "victim@example.com", "email_verified": False},
        ):
            with pytest.raises(AuthenticationException) as exc:
                provider.set_user_data()
        assert "UNVERIFIED_EMAIL" in str(exc.value.error_message)

    def test_missing_email_verified_claim_is_rejected(self):
        """An absent claim is not a passing claim."""
        provider = _provider()
        with patch.object(provider, "get_user_response", return_value={"sub": "uuid-1", "email": "victim@example.com"}):
            with pytest.raises(AuthenticationException):
                provider.set_user_data()

    def test_verified_email_is_accepted_and_keyed_on_sub(self):
        provider = _provider()
        with patch.object(
            provider,
            "get_user_response",
            return_value={
                "sub": "uuid-1",
                "email": "person@example.com",
                "email_verified": True,
                "given_name": "Person",
                "family_name": "Example",
                "preferred_username": "person",
            },
        ):
            provider.set_user_data()
        data = provider.user_data
        assert data["email"] == "person@example.com"
        # `sub` is the only claim the realm guarantees is stable — username and
        # email can both be edited by an admin or the user.
        assert data["user"]["provider_id"] == "uuid-1"
        assert data["user"]["is_password_autoset"] is True

    def test_missing_sub_is_rejected(self):
        provider = _provider()
        with patch.object(
            provider,
            "get_user_response",
            return_value={"email": "person@example.com", "email_verified": True},
        ):
            with pytest.raises(AuthenticationException):
                provider.set_user_data()


@pytest.mark.unit
class TestKeycloakConfiguration:
    def test_endpoints_come_from_discovery(self):
        """Never assembled by hand: the realm path moved from /auth/realms to
        /realms in Keycloak 17, so either hardcoded shape breaks on the other."""
        provider = _provider()
        assert provider.token_url == DISCOVERY["token_endpoint"]
        assert provider.userinfo_url == DISCOVERY["userinfo_endpoint"]
        assert provider.get_auth_url().startswith(DISCOVERY["authorization_endpoint"])

    def test_callback_uri_is_the_keycloak_one(self):
        assert "/auth/keycloak/callback/" in _provider().redirect_uri

    def test_unset_configuration_is_not_configured(self):
        with patch(
            "plane.authentication.provider.oauth.keycloak.get_configuration_value",
            return_value=("", "", "", ""),
        ):
            with pytest.raises(AuthenticationException):
                KeycloakOAuthProvider(request=_request(), state="state")

    @pytest.mark.parametrize("issuer", ["keycloak.example.com/realms/adhar", "ftp://x/realms/a", "https://"])
    def test_issuer_must_be_an_http_url(self, issuer):
        """A scheme-less or non-HTTP issuer is a configuration error, and the
        detail must not be echoed back into redirect query parameters."""
        with _configured(issuer=issuer):
            with pytest.raises(AuthenticationException):
                KeycloakOAuthProvider(request=_request(), state="state")

    def test_unreachable_realm_reports_not_configured(self):
        with _configured(), _discovered(ok=False):
            with pytest.raises(AuthenticationException) as exc:
                KeycloakOAuthProvider(request=_request(), state="state")
        assert "NOT_CONFIGURED" in str(exc.value.error_message)

    def test_discovery_missing_an_endpoint_reports_not_configured(self):
        incomplete = {"authorization_endpoint": DISCOVERY["authorization_endpoint"]}
        with _configured(), _discovered(document=incomplete):
            with pytest.raises(AuthenticationException):
                KeycloakOAuthProvider(request=_request(), state="state")


@pytest.mark.unit
class TestKeycloakSplitHorizon:
    """`KEYCLOAK_INTERNAL_ISSUER_URL` routes server-to-server calls over the
    private network while browsers keep using the public issuer."""

    def _internal_discovery(self, reported_issuer):
        return {
            "issuer": reported_issuer,
            "authorization_endpoint": f"{reported_issuer}/protocol/openid-connect/auth",
            "token_endpoint": f"{reported_issuer}/protocol/openid-connect/token",
            "userinfo_endpoint": f"{reported_issuer}/protocol/openid-connect/userinfo",
        }

    def test_discovery_is_fetched_from_the_internal_issuer(self):
        with (
            _configured(internal_issuer=INTERNAL_ISSUER),
            _discovered(document=self._internal_discovery(INTERNAL_ISSUER)) as get,
        ):
            KeycloakOAuthProvider(request=_request(), state="state")
        assert get.call_args.args[0] == f"{INTERNAL_ISSUER}/.well-known/openid-configuration"

    def test_browser_goes_public_and_server_goes_internal(self):
        with (
            _configured(internal_issuer=INTERNAL_ISSUER),
            _discovered(document=self._internal_discovery(INTERNAL_ISSUER)),
        ):
            provider = KeycloakOAuthProvider(request=_request(), state="state")
        assert provider.get_auth_url().startswith(f"{ISSUER}/protocol/openid-connect/auth?")
        assert provider.token_url == f"{INTERNAL_ISSUER}/protocol/openid-connect/token"
        assert provider.userinfo_url == f"{INTERNAL_ISSUER}/protocol/openid-connect/userinfo"

    def test_wrong_scheme_frontend_url_from_keycloak_is_corrected(self):
        """Keycloak behind `proxy=edge` reached without X-Forwarded-Proto reports
        its public hostname with the request's scheme (http), which the browser
        could never use on a TLS-only ingress. The reported issuer is still a
        recognised prefix, so the endpoints are re-based onto the configured
        public and internal issuers."""
        reported = ISSUER.replace("https://", "http://")
        with _configured(internal_issuer=INTERNAL_ISSUER), _discovered(document=self._internal_discovery(reported)):
            provider = KeycloakOAuthProvider(request=_request(), state="state")
        assert provider.get_auth_url().startswith(f"{ISSUER}/protocol/openid-connect/auth?")
        assert provider.token_url == f"{INTERNAL_ISSUER}/protocol/openid-connect/token"

    def test_unrecognised_endpoint_hosts_are_left_alone(self):
        """Nothing is invented: an endpoint on a host that is neither issuer is
        passed through untouched."""
        elsewhere = "https://login.example.org/oidc"
        document = self._internal_discovery(INTERNAL_ISSUER)
        document["token_endpoint"] = f"{elsewhere}/token"
        with _configured(internal_issuer=INTERNAL_ISSUER), _discovered(document=document):
            provider = KeycloakOAuthProvider(request=_request(), state="state")
        assert provider.token_url == f"{elsewhere}/token"

    def test_without_internal_issuer_discovery_is_used_verbatim(self):
        provider = _provider()
        assert provider.token_url == DISCOVERY["token_endpoint"]
        assert provider.get_auth_url().startswith(DISCOVERY["authorization_endpoint"])

    @pytest.mark.parametrize("internal", ["keycloak.keycloak.svc:8080/realms/adhar", "ftp://x/realms/a"])
    def test_internal_issuer_must_be_an_http_url(self, internal):
        with _configured(internal_issuer=internal):
            with pytest.raises(AuthenticationException):
                KeycloakOAuthProvider(request=_request(), state="state")
