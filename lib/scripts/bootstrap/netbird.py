import requests
from typing import Any, Optional, Union
from collections.abc import Callable
import time


class Netbird:
    def __init__(self, base_url: str, token: Union[str, dict[str, str]]):
        self.base_url = base_url
        self.token: str = token if isinstance(token, str) else token["access_token"]

        self.__session = requests.Session()
        self.__session.headers["Authorization"] = f"Bearer {self.token}"
        self.__session.headers["Accept"] = "application/json"

    def url(self, uri: str) -> str:
        return f"{self.base_url}{uri}"

    @staticmethod
    def filter_items(
        items: list[dict[str, Any]], filter_method
    ) -> list[dict[str, Any]]:
        if not filter_method:
            return items
        return list(filter(filter_method, items))

    def wait_for_ready(self, timeout: int = 60) -> bool:
        start_time = time.time()
        print("Waiting for Netbird API to be ready ", end="", flush=True)
        while True:
            try:
                respons = self.__session.get(self.url("/api/peers"))
                if respons.status_code == 200:
                    print(" done")
                    return True
            except requests.exceptions.RequestException:
                if time.time() - start_time > timeout:
                    raise RuntimeError("Timeout waiting for Netbird API to be ready")
            print(".", end="", flush=True)
            time.sleep(1)

    def list_peers(self, filter_method: Optional[Callable] = None):
        uri = "/api/peers"
        response = self.__session.get(self.url(uri))
        return self.filter_items(response.json(), filter_method)

    def list_users(
        self, service_user: bool = False, filter_method: Optional[Callable] = None
    ) -> list[dict[str, Any]]:
        uri = "/api/users"
        response = self.__session.get(
            self.url(uri), params={"service_user": service_user}
        )
        return self.filter_items(response.json(), filter_method)

    def create_user(
        self,
        role: str = "user",
        auto_groups: list[str] = [],
        is_service_user: bool = False,
        name: Optional[str] = None,
        email: Optional[str] = None,
    ) -> dict[str, Any]:
        uri = f"/api/users"
        parameters = {
            "role": role,
            "auto_groups": auto_groups,
            "is_service_user": is_service_user,
        }
        if name:
            parameters["name"] = name
        if email:
            parameters["email"] = email
        response = self.__session.post(self.url(uri), json=parameters)
        return response.json()

    def list_tokens(self, user_id: str) -> list[dict[str, Any]]:
        uri = f"/api/users/{user_id}/tokens"
        response = self.__session.get(self.url(uri))
        return response.json()

    def create_token(
        self, user_id: str, token_name: str, expires_in: int
    ) -> dict[str, Any]:
        uri = f"/api/users/{user_id}/tokens"
        response = self.__session.post(
            self.url(uri), json={"name": token_name, "expires_in": expires_in}
        )
        return response.json()

    def delete_token(self, user_id: str, token_id: str) -> str:
        uri = f"/api/users/{user_id}/tokens/{token_id}"
        response = self.__session.delete(self.url(uri))
        if response.status_code > 299:
            raise RuntimeError(
                f"Delete Token | Status Code: {response.status_code} | Msg: {response.text}"
            )
        return response.text

    def list_setup_keys(
        self, filter_method: Optional[Callable] = None
    ) -> list[dict[str, Any]]:
        uri = "/api/setup-keys"
        response = self.__session.get(self.url(uri))
        return self.filter_items(response.json(), filter_method)

    def get_setup_key(self, key_id: str) -> dict[str, Any]:
        uri = f"/api/setup-keys/{key_id}"
        response = self.__session.get(self.url(uri))
        return response.json()

    def create_setup_key(
        self,
        name: str,
        type: str,
        expires_in_secs: int,
        auto_groups: list[str] = [],
        usage_limit: int = 0,
        ephemeral: bool = False,
    ) -> dict[str, Any]:
        uri = "/api/setup-keys"
        parameters = {
            "name": name,
            "type": type,
            "expires_in": expires_in_secs,
            "auto_groups": auto_groups,
            "usage_limit": usage_limit,
            "ephemeral": ephemeral,
        }
        response = self.__session.post(self.url(uri), json=parameters)
        return response.json()

    def update_setup_key(
        self,
        key_id: str,
        name: str,
        type: str,
        expires_in_secs: int,
        revoked: bool = False,
        auto_groups: list[str] = [],
        usage_limit: int = 0,
        ephemeral: bool = False,
    ) -> dict[str, Any]:
        uri = f"/api/setup-keys/{key_id}"
        parameters = {
            "name": name,
            "type": type,
            "expires_in": expires_in_secs,
            "revoked": revoked,
            "auto_groups": auto_groups,
            "usage_limit": usage_limit,
            "ephemeral": ephemeral,
        }
        response = self.__session.put(self.url(uri), json=parameters)
        return response.json()

    def list_groups(
        self, filter_method: Optional[Callable] = None
    ) -> list[dict[str, Any]]:
        uri = "/api/groups"
        response = self.__session.get(self.url(uri))
        return self.filter_items(response.json(), filter_method)

    def get_group(self, group_id: str) -> dict[str, Any]:
        uri = f"/api/groups/{group_id}"
        response = self.__session.get(self.url(uri))
        return response.json()

    def create_group(self, name: str, peers: list[str] = []) -> dict[str, Any]:
        uri = "/api/groups"
        parameters = {"name": name, "peers": peers}
        response = self.__session.post(self.url(uri), json=parameters)
        return response.json()

    def update_group(
        self, group_id: str, name: str, peers: list[str] = []
    ) -> dict[str, Any]:
        uri = f"/api/groups/{group_id}"
        parameters = {"name": name, "peers": peers}
        response = self.__session.put(self.url(uri), json=parameters)
        return response.json()

    def delete_group(self, group_id: str) -> str:
        uri = f"/api/groups/{group_id}"
        response = self.__session.delete(self.url(uri))
        if response.status_code > 299:
            raise RuntimeError(
                f"Delete Group | Status Code: {response.status_code} | Msg: {response.text}"
            )
        return response.text
