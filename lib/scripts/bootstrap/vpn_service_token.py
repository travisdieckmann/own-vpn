import json
from os import environ
from typing import Any
from datetime import datetime, timezone, timedelta

from netbird import Netbird
from vpn_types import VpnServiceTokens
from utils import timestamp_to_datetime


def get_vpn_service_tokens(
    base_url: str,
    token: str,
    service_user_name: str = "NetbirdServer",
    service_user_token_name: str = "ServerToken",
    service_token_expires_days: int = 365,
    service_token_renewal_days: int = 30,
    setup_key_name: str = "ServerEgressKey",
    setup_key_expires_secs: int = 31536000,
    egress_group_name: str = "ServerEgressNode",
):

    netbird = Netbird(base_url, token)

    print("\nConfiguring Netbird Server for Peering\n")
    netbird.wait_for_ready()

    service_users = netbird.list_users(
        service_user=True, filter_method=lambda u: u["name"] == service_user_name
    )
    if not service_users:
        service_user = netbird.create_user(
            role="admin", is_service_user=True, name=service_user_name
        )
    else:
        service_user: dict[str, Any] = service_users[0]
    print(f'Netbird service_user: {service_user["id"]} | {service_user["name"]}')

    service_user_tokens = netbird.list_tokens(service_user["id"]) or []
    # print(f"service_user_tokens: {json.dumps(service_user_tokens)}")
    service_user_tokens = list(
        filter(lambda t: t["name"] == service_user_token_name, service_user_tokens)
    )
    service_user_token = None  # type: ignore
    if service_user_tokens:
        service_user_token: dict[str, Any] = service_user_tokens[0]

        if datetime.now(timezone.utc) + timedelta(
            days=service_token_renewal_days
        ) > timestamp_to_datetime(service_user_token["expiration_date"]):
            netbird.delete_token(service_user["id"], service_user_token["id"])
            service_user_token = None  # type: ignore

    plain_token = token
    if not service_user_token:
        service_user_token = netbird.create_token(
            service_user["id"],
            service_user_token_name,
            service_token_expires_days,
        )
        plain_token = service_user_token["plain_token"]
        # TODO - Save service token
        service_user_token = service_user_token["personal_access_token"]

    print(
        f'Netbird service_user_token: {service_user_token["id"]} | {service_user_token["name"]}'
    )

    groups = netbird.list_groups(lambda g: g["name"] == egress_group_name)
    # print(f"groups: {json.dumps(groups)}")

    if groups:
        group = groups[0]
    else:
        group = netbird.create_group(egress_group_name)

    print(f'Netbird server egress group: {group["id"]} | {group["name"]}')

    setup_keys = netbird.list_setup_keys(lambda k: k["name"] == setup_key_name)

    if setup_keys:
        setup_key = setup_keys[0]
        renew_date = datetime.now(timezone.utc) + timedelta(
            days=service_token_renewal_days
        )
        if any(
            (
                timestamp_to_datetime(setup_key["expires"]) > renew_date,
                setup_key["revoked"] == True,
                group["id"] not in setup_key["auto_groups"],
            )
        ):
            setup_key = netbird.update_setup_key(
                setup_key["id"],
                setup_key["name"],
                "reusable",
                setup_key_expires_secs,
                auto_groups=[group["id"]],
            )
    else:
        setup_key = netbird.create_setup_key(
            setup_key_name, "reusable", setup_key_expires_secs, [group["id"]]
        )
    print(f'Netbird setup_key: {setup_key["id"]} | {setup_key["name"]}')
    print("\nNetbird Server Configuration Complete\n")

    return VpnServiceTokens(
        base_url=base_url,
        service_user_pat=plain_token,
        service_user_token_details=service_user_token,
        setup_key=setup_key["key"],
        setup_key_details=setup_key,
    )


if __name__ == "__main__":
    from auth_handler import AuthHandler
    from urllib.parse import urlparse

    # Configuration
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
    if not access_token:
        raise RuntimeError("Unable to obtain access token")

    get_vpn_service_tokens(base_url=base_url, token=access_token)
