"""Tests for GitHub App installation tokens."""

import base64
import io
import json
import urllib.error
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.services import github_app


def _unb64url(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


@pytest.fixture
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def pem(rsa_key):
    return rsa_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


@pytest.fixture
def app_settings(pem):
    with patch("app.services.github_app.settings") as mock_settings:
        mock_settings.GITHUB_APP_ID = "4711"
        mock_settings.GITHUB_APP_PRIVATE_KEY = base64.b64encode(pem).decode()
        yield mock_settings


class TestConfiguration:
    def test_needs_both_id_and_key(self, app_settings):
        assert github_app.is_configured()
        app_settings.GITHUB_APP_ID = ""
        assert not github_app.is_configured()

    def test_accepts_raw_pem(self, app_settings, pem):
        app_settings.GITHUB_APP_PRIVATE_KEY = pem.decode()
        assert isinstance(github_app._load_private_key(), rsa.RSAPrivateKey)


class TestJwt:
    def test_is_signed_with_the_app_key(self, app_settings, rsa_key):
        header, payload, signature = github_app._app_jwt().split(".")

        rsa_key.public_key().verify(
            _unb64url(signature), f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256()
        )
        assert json.loads(_unb64url(header)) == {"alg": "RS256", "typ": "JWT"}

    def test_claims_stay_within_githubs_ten_minute_limit(self, app_settings):
        claims = json.loads(_unb64url(github_app._app_jwt().split(".")[1]))

        assert claims["iss"] == "4711"
        assert claims["exp"] - claims["iat"] <= 600


class TestInstallationToken:
    def test_returns_token_for_installed_repo(self, app_settings):
        with patch.object(github_app, "_request", side_effect=[{"id": 42}, {"token": "ghs_abc"}]) as req:
            assert github_app.installation_token("owner", "repo") == "ghs_abc"

        assert req.call_args_list[0].args[:2] == ("GET", "/repos/owner/repo/installation")
        assert req.call_args_list[1].args[:2] == ("POST", "/app/installations/42/access_tokens")

    def test_returns_none_when_app_not_installed(self, app_settings):
        not_found = urllib.error.HTTPError("url", 404, "Not Found", {}, io.BytesIO())
        with patch.object(github_app, "_request", side_effect=not_found):
            assert github_app.installation_token("owner", "public-repo") is None

    def test_other_errors_are_raised(self, app_settings):
        unauthorized = urllib.error.HTTPError("url", 401, "Unauthorized", {}, io.BytesIO())
        with patch.object(github_app, "_request", side_effect=unauthorized), pytest.raises(urllib.error.HTTPError):
            github_app.installation_token("owner", "repo")
