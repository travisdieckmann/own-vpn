from enum import Enum
from typing import TypedDict, Optional, Any


class DbEngine(Enum):
    POSTGRES = "postgres"
    COCKROACH = "cockroach"


def db_engine_validate(value: Optional[str]) -> DbEngine:
    if value:
        try:
            return DbEngine(value)
        except ValueError:
            raise ValueError(f"Invalid database engine: {value}")
    else:
        return DbEngine.POSTGRES


class HostConfig(TypedDict):
    domain: str
    local_domain: str
    use_ip: bool
    zitadel_externalsecure: bool
    zitadel_tls_mode: str
    port: int
    caddy_secure_domain: str
    http_schema: str


class ZitadelIdpDetails(TypedDict):
    project_id: str
    idp_mgmt_client_id: str
    idp_mgmt_client_secret: str
    client_id_dashboard: str
    redirect_urls_dashboard: list[str]
    client_id_cli: str
    redirect_urls_cli: list[str]
    human_user_id: str
    machine_user_id: str


class VpnServiceTokens(TypedDict):
    base_url: str
    service_user_pat: str
    service_user_token_details: dict[str, Any]
    setup_key: str
    setup_key_details: dict[str, Any]
