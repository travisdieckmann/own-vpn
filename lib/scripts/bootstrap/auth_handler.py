import json
from typing import Optional
import requests
import base64, hashlib, secrets
from urllib.parse import urlparse, parse_qs


class AuthHandler:
    def __init__(
        self,
        base_url: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        auth_endpoint: Optional[str] = None,
        token_endpoint: Optional[str] = None,
    ) -> None:
        self.base_url = base_url
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope

        self.session = requests.Session()

        if not auth_endpoint or not token_endpoint:
            discovery_url = f"{base_url}/.well-known/openid-configuration"
            discovery_response = self.session.get(discovery_url)
            discovery_data = discovery_response.json()

        self.auth_endpoint = auth_endpoint or discovery_data["authorization_endpoint"]
        self.token_endpoint = token_endpoint or discovery_data["token_endpoint"]

    def make_auth_request(self, code_challenge: str, challenge_method: str):
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "code_challenge": code_challenge,
            "code_challenge_method": challenge_method,
        }

        authorization_response = self.session.get(self.auth_endpoint, params=params)

        content = authorization_response.content.decode()
        loginname_form_url = f"{self.base_url}{__class__.parse_form_action(content)}"
        csrf_token = __class__.parse_csrf_token(content)
        auth_request_id = __class__.parse_auth_request_id(content)

        return loginname_form_url, csrf_token, auth_request_id

    def send_loginname(
        self,
        loginname_url: str,
        username: str,
        csrf_token: str,
        auth_request_id: str,
    ):
        login_payload = {
            "gorilla.csrf.Token": csrf_token,
            "authRequestID": auth_request_id,
            "loginName": username,
        }

        # Submit the login form
        loginname_response = self.session.post(loginname_url, data=login_payload)
        content = loginname_response.content.decode()

        if __class__.invalid_login_form(content):
            raise RuntimeError("Login form Username failed!")

        password_url = f"{self.base_url}{__class__.parse_form_action(content)}"
        csrf_token = __class__.parse_csrf_token(content)
        auth_request_id = __class__.parse_auth_request_id(content)
        return password_url, csrf_token, auth_request_id

    def send_password(
        self,
        password_url: str,
        username: str,
        password: str,
        csrf_token: str,
        auth_request_id: str,
    ):
        password_payload = {
            "gorilla.csrf.Token": csrf_token,
            "authRequestID": auth_request_id,
            "loginName": username,
            "password": password,
        }

        # Submit the login form
        password_response = self.session.post(
            password_url, data=password_payload, allow_redirects=False
        )
        if password_response.status_code == 200:
            content = password_response.content.decode()
            if __class__.is_second_factor_form(content):
                print("Skipping second factor...")
                password_response = self.skip_second_factor(content)

        if password_response.status_code != 302:
            raise RuntimeError("Login form Password failed!")
        auth_callback_url = password_response.headers["location"]
        return auth_callback_url

    def skip_second_factor(self, content: str) -> requests.Response:
        password_url = f"{self.base_url}{__class__.parse_form_action(content)}"
        csrf_token = __class__.parse_csrf_token(content)
        auth_request_id = __class__.parse_auth_request_id(content)

        second_factor_payload = {
            "gorilla.csrf.Token": csrf_token,
            "authRequestID": auth_request_id,
            "skip": "true",
        }
        skip_second_response = self.session.post(
            password_url, data=second_factor_payload, allow_redirects=False
        )
        return skip_second_response

    def get_authorization_code(self, auth_callback_url: str) -> str:
        auth_callback_response = self.session.get(
            auth_callback_url, allow_redirects=False
        )
        redirected_url = auth_callback_response.headers["location"]
        parsed_url = urlparse(redirected_url)

        # If we were redirected to the redirect URI, we'll have the authorization code in the URL
        if parsed_url.netloc != urlparse(self.redirect_uri).netloc:
            raise RuntimeError("Login Failed! Failed to get authorization code")

        query_params = parse_qs(parsed_url.query) or {}
        authorization_code = query_params.get("code", [])[0]
        return authorization_code

    def get_authorization_tokens(
        self, authorization_code: str, code_verifier: str
    ) -> dict[str, str]:
        token_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "code_verifier": code_verifier,
        }

        token_response = self.session.post(self.token_endpoint, data=token_data)
        tokens = token_response.json()
        return tokens

    def authenticate(self, username: str, password: str):
        code_verifier = __class__.generate_code_verifier()
        code_challenge = __class__.generate_code_challenge(code_verifier)

        loginname_url, csrf_token, auth_request_id = self.make_auth_request(
            code_challenge, "S256"
        )

        password_url, csrf_token, auth_request_id = self.send_loginname(
            username=username,
            loginname_url=loginname_url,
            csrf_token=csrf_token,
            auth_request_id=auth_request_id,
        )

        auth_callback_url = self.send_password(
            password_url=password_url,
            username=username,
            password=password,
            csrf_token=csrf_token,
            auth_request_id=auth_request_id,
        )

        authorization_code = self.get_authorization_code(auth_callback_url)

        authorization_token = self.get_authorization_tokens(
            authorization_code, code_verifier
        )
        return authorization_token

    def get_access_token(self, username: str, password: str) -> Optional[str]:
        tokens = self.authenticate(username=username, password=password)
        return tokens.get("access_token")

    @staticmethod
    def generate_code_verifier() -> str:
        return (
            base64.urlsafe_b64encode(secrets.token_bytes(32))
            .rstrip(b"=")
            .decode("utf-8")
        )

    @staticmethod
    def generate_code_challenge(code_verifier) -> str:
        code_challenge_hash = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        return (
            base64.urlsafe_b64encode(code_challenge_hash).rstrip(b"=").decode("utf-8")
        )

    @staticmethod
    def parse_csrf_token(content: str) -> str:
        split_str = '<input type="hidden" name="gorilla.csrf.Token" value="'
        return content.split(split_str)[1].split('">')[0]

    @staticmethod
    def parse_auth_request_id(content: str) -> str:
        split_str = '<input type="hidden" name="authRequestID" value="'
        return content.split(split_str)[1].split('" />')[0]

    @staticmethod
    def parse_form_action(content: str) -> str:
        split_str = '<form action="'
        return content.split(split_str)[1].split('" method="POST">')[0]

    @staticmethod
    def is_second_factor_form(content: str) -> bool:
        return "<title>2-Factor Setup</title>" in content

    @staticmethod
    def invalid_login_form(content: str) -> bool:
        if (
            not "<title>Welcome Back!</title>" in content
            and not 'for="password">Password</label>' in content
        ):
            return True
        return False


if __name__ == "__main__":
    config = {}
    with open("./management.json", "r") as f:
        config = json.load(f)

    if not config:
        raise RuntimeError("Unable to read configuration from './management.json'")

    env_data = []
    with open("./.env", "r") as f:
        env_data = f.readlines()

    if not env_data:
        raise RuntimeError("Unable to read credentials from './.env'")

    username = ""
    password = ""
    for line in env_data:
        if line.startswith("Username: "):
            username = line.split("Username:")[1].strip()
        if line.startswith("Password: "):
            password = line.split("Password:")[1].strip()

    # OIDC Configuration
    auth_endpoint = config["PKCEAuthorizationFlow"]["ProviderConfig"][
        "AuthorizationEndpoint"
    ]
    parsed_url = urlparse(auth_endpoint)
    base_url = f"{parsed_url.scheme}://{parsed_url.hostname}"
    client_id = config["PKCEAuthorizationFlow"]["ProviderConfig"]["ClientID"]
    redirect_uri = config["PKCEAuthorizationFlow"]["ProviderConfig"]["RedirectURLs"][0]
    scope = config["PKCEAuthorizationFlow"]["ProviderConfig"]["Scope"]

    authorizer = AuthHandler(
        base_url=base_url,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
    )

    access_token = authorizer.get_access_token(username=username, password=password)
    print(access_token)
