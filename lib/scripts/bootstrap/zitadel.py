import os
import sys
import json
import time
import requests
from datetime import datetime
from typing import Optional, Tuple

from utils import timestamp_to_datetime
from vpn_types import ZitadelIdpDetails


class Zitadel:
    def __init__(self, http_schema: str, domain: str, port: int, base_dir: str):
        self.http_schema = http_schema
        self.domain = domain
        self.base_url = f"{self.http_schema}://{self.domain}"
        self.port = port
        self.token_path = os.path.join(base_dir, "machinekey", "zitadel-admin-sa.token")
        self.config_path = os.path.join(base_dir, "zitadel.env")
        self.pat = self.get_pat()
        self.project_id = None
        self.is_new = not os.path.exists(self.config_path)

    def setup(
        self,
        admin_username: str,
        admin_password: str,
        force_pword_change: bool = True,
        delete_auto_service_user: bool = True,
    ) -> ZitadelIdpDetails:
        print("\nInitializing Zitadel with NetBird's applications\n")

        self.pat = self.get_pat(True)

        self.wait_api()

        print("Creating new zitadel project")
        self.project_id = self.create_new_project()

        zitadel_dev_mode = "true" if self.http_schema == "http" else "false"

        print("Creating new Zitadel SPA Dashboard application")
        redirect_urls_dashboard = [
            f"{self.base_url}/nb-auth",
            f"{self.base_url}/nb-silent-auth",
        ]
        dashboard_application_client_id = self.create_new_application(
            "Dashboard",
            redirect_urls_dashboard,
            f"{self.base_url}/",
            zitadel_dev_mode,
            "false",
        )

        print("Creating new Zitadel SPA Cli application")
        redirect_urls_cli = ["http://localhost:53000/", "http://localhost:54000/"]
        cli_application_client_id = self.create_new_application(
            "Cli",
            redirect_urls_cli,
            "http://localhost:53000/",
            "true",
            "true",
        )

        self.machine_user_id = self.create_service_user()
        service_user_client_id, service_user_client_secret = (
            self.create_service_user_secret(self.machine_user_id)
        )

        _ = self.add_organization_user_manager(self.machine_user_id)

        human_user_id = self.create_admin_user(
            admin_username, admin_password, force_pword_change
        )

        _ = self.add_instance_admin(human_user_id)

        if delete_auto_service_user:
            resp = self.delete_auto_service_user()
            if not resp:
                print("Failed to delete auto service user")
                print("Please remove it manually")

        return ZitadelIdpDetails(
            project_id=self.project_id,
            idp_mgmt_client_id=service_user_client_id,
            idp_mgmt_client_secret=service_user_client_secret,
            client_id_dashboard=dashboard_application_client_id,
            redirect_urls_dashboard=redirect_urls_dashboard,
            client_id_cli=cli_application_client_id,
            redirect_urls_cli=redirect_urls_cli,
            human_user_id=human_user_id,
            machine_user_id=self.machine_user_id,
        )

    def get_pat(self, wait: bool = False) -> Optional[str]:
        pat = None
        if wait and not os.path.exists(self.token_path):
            print("Waiting for Zitadel's PAT to be created ", end="", flush=True)
            while not os.path.exists(self.token_path):
                print(".", end="", flush=True)
                time.sleep(1)
            print(" done")

        print("Reading Zitadel PAT")
        if os.path.exists(self.token_path):
            with open(self.token_path, "r") as f:
                pat = f.read().strip()
        if wait and (pat == "null" or not pat):
            raise RuntimeError("Failed getting Zitadel PAT")
        return pat

    @property
    def request_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.pat}",
            "Content-Type": "application/json",
        }

    def wait_api(self):
        print("Waiting for Zitadel to become ready ", end="", flush=True)
        while True:
            try:
                response = requests.get(
                    f"{self.base_url}/auth/v1/users/me",
                    headers=self.request_headers,
                )
                if response.status_code == 200:
                    break
            except:
                pass
            print(".", end="", flush=True)
            time.sleep(1)
        print(" done")

    def create_new_project(self):
        response = requests.post(
            f"{self.base_url}/management/v1/projects",
            headers=self.request_headers,
            json={"name": "NETBIRD"},
        )
        parsed_response = response.json().get("id")
        self.handle_zitadel_request_response(
            parsed_response, "create_new_project", response.text
        )
        return parsed_response

    def create_new_application(
        self,
        application_name: str,
        redirect_urls: list[str],
        logout_url: str,
        zitadel_dev_mode: str,
        device_code: str,
    ) -> str:
        grant_types = (
            [
                "OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
                "OIDC_GRANT_TYPE_DEVICE_CODE",
                "OIDC_GRANT_TYPE_REFRESH_TOKEN",
            ]
            if device_code == "true"
            else ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE", "OIDC_GRANT_TYPE_REFRESH_TOKEN"]
        )

        data = {
            "name": application_name,
            "redirectUris": redirect_urls,
            "postLogoutRedirectUris": [logout_url],
            "responseTypes": ["OIDC_RESPONSE_TYPE_CODE"],
            "grantTypes": grant_types,
            "appType": "OIDC_APP_TYPE_USER_AGENT",
            "authMethodType": "OIDC_AUTH_METHOD_TYPE_NONE",
            "version": "OIDC_VERSION_1_0",
            "devMode": zitadel_dev_mode == "true",
            "accessTokenType": "OIDC_TOKEN_TYPE_JWT",
            "accessTokenRoleAssertion": True,
            "skipNativeAppSuccessPage": True,
        }

        response = requests.post(
            f"{self.base_url}/management/v1/projects/{self.project_id}/apps/oidc",
            headers=self.request_headers,
            json=data,
        )
        parsed_response: str = response.json().get("clientId")
        self.handle_zitadel_request_response(
            parsed_response, "create_new_application", response.text
        )
        return parsed_response

    def create_service_user(self) -> str:
        response = requests.post(
            f"{self.base_url}/management/v1/users/machine",
            headers=self.request_headers,
            json={
                "userName": "netbird-service-account",
                "name": "Netbird Service Account",
                "description": "Netbird Service Account for IDP management",
                "accessTokenType": "ACCESS_TOKEN_TYPE_JWT",
            },
        )
        parsed_response = response.json().get("userId")
        self.handle_zitadel_request_response(
            parsed_response, "create_service_user", response.text
        )
        return parsed_response

    def create_service_user_secret(self, user_id: str) -> Tuple[str, str]:
        response = requests.put(
            f"{self.base_url}/management/v1/users/{user_id}/secret",
            headers=self.request_headers,
            json={},
        )
        response_json = response.json()
        client_id = response_json.get("clientId")
        self.handle_zitadel_request_response(
            client_id, "create_service_user_secret_id", response.text
        )
        client_secret = response_json.get("clientSecret")
        self.handle_zitadel_request_response(
            client_secret, "create_service_user_secret", response.text
        )
        return client_id, client_secret

    def add_organization_user_manager(self, user_id: str) -> datetime:
        response = requests.post(
            f"{self.base_url}/management/v1/orgs/me/members",
            headers=self.request_headers,
            json={"userId": user_id, "roles": ["ORG_USER_MANAGER"]},
        )
        parsed_response = response.json().get("details", {}).get("creationDate")
        self.handle_zitadel_request_response(
            parsed_response, "add_organization_user_manager", response.text
        )
        return timestamp_to_datetime(parsed_response)

    def create_admin_user(
        self, username: str, password: str, force_password_change: bool = True
    ) -> str:
        response = requests.post(
            f"{self.base_url}/management/v1/users/human/_import",
            headers=self.request_headers,
            json={
                "userName": username,
                "profile": {"firstName": "Zitadel", "lastName": "Admin"},
                "email": {"email": username, "isEmailVerified": True},
                "password": password,
                "passwordChangeRequired": force_password_change,
            },
        )
        parsed_response = response.json().get("userId")
        self.handle_zitadel_request_response(
            parsed_response, "create_admin_user", response.text
        )
        return parsed_response

    def set_user_password(
        self, user_id, password: str, force_password_change: bool = True
    ) -> bool:
        response = requests.post(
            f"{self.base_url}/management/v1/users/{user_id}/password",
            headers=self.request_headers,
            json={"password": password, "noChangeRequired": not force_password_change},
        )

        return response.status_code == 200

    def add_instance_admin(self, user_id: str) -> datetime:
        response = requests.post(
            f"{self.base_url}/admin/v1/members",
            headers=self.request_headers,
            json={"userId": user_id, "roles": ["IAM_OWNER"]},
        )
        parsed_response = response.json().get("details", {}).get("creationDate")
        self.handle_zitadel_request_response(
            parsed_response, "add_instance_admin", response.text
        )
        return timestamp_to_datetime(parsed_response)

    def delete_auto_service_user(self) -> datetime:
        response = requests.get(
            f"{self.base_url}/auth/v1/users/me",
            headers=self.request_headers,
        )
        user_id = response.json().get("user", {}).get("id")
        self.handle_zitadel_request_response(
            user_id, "delete_auto_service_user_get_user", response.text
        )
        response = requests.delete(
            f"{self.base_url}/admin/v1/members/{user_id}",
            headers=self.request_headers,
        )
        parsed_response = response.json().get("details", {}).get("changeDate")
        self.handle_zitadel_request_response(
            parsed_response,
            "delete_auto_service_user_remove_instance_permissions",
            response.text,
        )
        response = requests.delete(
            f"{self.base_url}/management/v1/orgs/me/members/{user_id}",
            headers=self.request_headers,
        )
        parsed_response = response.json().get("details", {}).get("changeDate")
        self.handle_zitadel_request_response(
            parsed_response,
            "delete_auto_service_user_remove_org_permissions",
            response.text,
        )
        return parsed_response

    @staticmethod
    def handle_zitadel_request_response(parsed_response, function_name, response):
        if parsed_response is None:
            raise RuntimeError(
                f"ERROR calling {function_name}: {json.loads(response)['message']}"
            )
        time.sleep(1)
