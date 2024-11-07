import os
import re
import sys
from typing import Optional
from datetime import datetime, timedelta, timezone

from vpn_types import HostConfig, db_engine_validate
from utils import generate_random_string, Metadata


class VpnEnvironment:
    def __init__(self, config_path: str):
        self.config_path = config_path
        host_config = self.get_host_config()
        self.domain = host_config["domain"]
        self.local_domain = host_config["local_domain"]
        self.port = host_config["port"]
        self.http_schema = host_config["http_schema"]
        self.base_url = f"{self.http_schema}://{self.domain}"
        self.base_url_w_port = f"{self.http_schema}://{self.domain}:{self.port}"
        self.zitadel_db_engine = db_engine_validate(os.environ.get("ZITADEL_DATABASE"))
        self.zitadel_externalsecure = host_config["zitadel_externalsecure"]
        self.zitadel_tls_mode = host_config["zitadel_tls_mode"]
        self.zitadel_masterkey = generate_random_string(32, use_base64=True)
        self._client_id_dashboard: str = ""
        self._redirect_urls_dashboard: list[str] = []
        self.scopes_dashboard: str = "openid profile email offline_access"
        self._client_id_cli: str = ""
        self._redirect_urls_cli: list[str] = []
        self.scopes_cli: str = "openid"
        self._idp_mgmt_client_id: str = ""
        self._idp_mgmt_client_secret: str = ""
        self.zitadel_admin_username = f"admin@{self.domain}"
        self.zitadel_admin_password = generate_random_string(32, use_safe_symbols=True)
        self.turn_user = "self"
        self.turn_password = generate_random_string(43, use_base64=True)
        self.turn_external_ip = __class__.get_turn_external_ip()
        self.turn_min_port = 49152
        self.turn_max_port = 65535

        self.postgres_root_password = f"{generate_random_string(43, use_base64=True)}@"
        self.postgres_zitadel_password = (
            f"{generate_random_string(43, use_base64=True)}@"
        )
        self.secret_arn: Optional[str] = os.environ.get("SECRET_ARN")

    @property
    def client_id_dashboard(self) -> str:
        return self._client_id_dashboard

    @client_id_dashboard.setter
    def client_id_dashboard(self, value: str) -> None:
        self._client_id_dashboard = value

    @property
    def redirect_urls_dashboard(self) -> list[str]:
        return self._redirect_urls_dashboard

    @redirect_urls_dashboard.setter
    def redirect_urls_dashboard(self, value: list[str]) -> None:
        self._redirect_urls_dashboard = value

    @property
    def client_id_cli(self) -> str:
        return self._client_id_cli

    @client_id_cli.setter
    def client_id_cli(self, value: str) -> None:
        self._client_id_cli = value

    @property
    def redirect_urls_cli(self) -> list[str]:
        return self._redirect_urls_cli

    @redirect_urls_cli.setter
    def redirect_urls_cli(self, value: list[str]) -> None:
        self._redirect_urls_cli = value

    @property
    def idp_mgmt_client_id(self) -> str:
        return self._idp_mgmt_client_id

    @idp_mgmt_client_id.setter
    def idp_mgmt_client_id(self, value: str) -> None:
        self._idp_mgmt_client_id = value

    @property
    def idp_mgmt_client_secret(self) -> str:
        return self._idp_mgmt_client_secret

    @idp_mgmt_client_secret.setter
    def idp_mgmt_client_secret(self, value: str) -> None:
        self._idp_mgmt_client_secret = value

    @staticmethod
    def get_zitadel_token_expiration_date():
        return (
            (datetime.now(timezone.utc) + timedelta(seconds=1800))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )

    @staticmethod
    def get_turn_external_ip():
        turn_external_ip_config = "# external-ip="
        try:
            ip = Metadata().public_ipv4()
            if ip:
                turn_external_ip_config = f"external-ip={ip}"
        except:
            pass
        return turn_external_ip_config

    @staticmethod
    def check_nb_domain(domain):
        if not domain:
            print("The NETBIRD_DOMAIN variable cannot be empty.", file=sys.stderr)
            return False
        if domain == "netbird.example.com":
            print("The NETBIRD_DOMAIN cannot be netbird.example.com", file=sys.stderr)
            return False
        if len(domain) > 253:
            return False

        # Regex for domain validation
        domain_regex = re.compile(
            r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.[A-Za-z0-9-]{1,63})*(?:\.[A-Za-z]{2,63})$"
        )
        return bool(domain_regex.match(domain))

    @staticmethod
    def read_nb_domain():
        while True:
            domain = input(
                "Enter the domain you want to use for NetBird (e.g. netbird.my-domain.com): "
            )
            if __class__.check_nb_domain(domain):
                return domain

    @staticmethod
    def domain_to_local_domain(domain: str) -> str:
        segments = domain.split(".")
        segments[-1] = "local"
        return ".".join(segments)

    @staticmethod
    def get_host_config() -> HostConfig:
        host_config: HostConfig = {
            "domain": "",
            "local_domain": "",
            "use_ip": False,
            "zitadel_externalsecure": False,
            "zitadel_tls_mode": "none",
            "port": 80,
            "caddy_secure_domain": "",
            "http_schema": "http",
        }

        if os.environ.get("NETBIRD_USE_IP", "FALSE").upper() == "TRUE":
            host_config["domain"] = Metadata().local_ipv4()
            host_config["local_domain"] = (
                host_config["domain"].replace(".", "-") + ".local"
            )

        if not __class__.check_nb_domain(os.environ.get("NETBIRD_DOMAIN")):
            host_config["domain"] = __class__.read_nb_domain()
        else:
            host_config["domain"] = os.environ.get("NETBIRD_DOMAIN", "")

        host_config["local_domain"] = __class__.domain_to_local_domain(
            host_config["domain"]
        )
        host_config["zitadel_externalsecure"] = True
        host_config["zitadel_tls_mode"] = "external"
        host_config["port"] = 443
        host_config["caddy_secure_domain"] = (
            f", {host_config['domain']}:{host_config['port']}"
        )
        host_config["http_schema"] = "https"

        return host_config
