import os
import json
import subprocess
import time
from typing import Optional

from zitadel import Zitadel
from auth_handler import AuthHandler
from vpn_environment import VpnEnvironment
from vpn_types import DbEngine, VpnServiceTokens
from config_file_renderer import ConfigFileRenderer
from vpn_service_token import get_vpn_service_tokens
from utils import DockerCompose, check_jq, store_credentials


class VpnDeployer:
    def __init__(self, config_path: str):
        check_jq()

        self.docker = DockerCompose(working_dir=config_path)
        self.env = VpnEnvironment(config_path)
        self.config_renderer = ConfigFileRenderer(self.env)
        self.zitadel = Zitadel(
            self.env.http_schema,
            self.env.domain,
            self.env.port,
            self.env.config_path,
        )

    def deploy(self, server_as_peer: bool = False):

        if self.zitadel.is_new:
            print("Performing first-time setup!")
            print("Pausing for 5 seconds...")
            time.sleep(5)

            machinekey_path = os.path.join(self.env.config_path, "machinekey")
            os.makedirs(machinekey_path, exist_ok=True)
            os.chmod(machinekey_path, 0o777)

            print("Rendering initial files...")
            self.config_renderer.docker_compose()
            self.config_renderer.zitadel_config()
            self.config_renderer.caddy_file()
            self.config_renderer.file_write(
                os.path.join(self.env.config_path, "dashboard.env"), ""
            )
            self.config_renderer.file_write(
                os.path.join(self.env.config_path, "turnserver.conf"), ""
            )
            self.config_renderer.file_write(
                os.path.join(self.env.config_path, "management.json"), ""
            )

            self.init_crdb()

            self.docker.start_zitadel()

            zitadel_idp_details = self.zitadel.setup(
                self.env.zitadel_admin_username,
                self.env.zitadel_admin_password,
                not server_as_peer,
                not server_as_peer,
            )

            self.env.client_id_dashboard = zitadel_idp_details["client_id_dashboard"]
            self.env.redirect_urls_dashboard = zitadel_idp_details[
                "redirect_urls_dashboard"
            ]
            self.env.client_id_cli = zitadel_idp_details["client_id_cli"]
            self.env.redirect_urls_cli = zitadel_idp_details["redirect_urls_cli"]
            self.env.idp_mgmt_client_id = zitadel_idp_details["idp_mgmt_client_id"]
            self.env.idp_mgmt_client_secret = zitadel_idp_details[
                "idp_mgmt_client_secret"
            ]

            print("\nRendering NetBird files...\n")
            self.config_renderer.turn_server_conf()
            self.config_renderer.management_json()
            self.config_renderer.dashboard_env()
            self.config_renderer.file_writelines(
                ".env",
                [
                    f"Username: {self.env.zitadel_admin_username}",
                    f"Password: {self.env.zitadel_admin_password}",
                ],
            )
            store_credentials(
                self.env.secret_arn,
                {
                    "Username": self.env.zitadel_admin_username,
                    "Password": self.env.zitadel_admin_password,
                },
            )

        self.docker.start_services()

        if server_as_peer:
            vpn_service_tokens_path = os.path.join(self.env.config_path, "peer.json")
            token = self.get_auth_token(vpn_service_tokens_path)

            vpn_service_tokens = get_vpn_service_tokens(
                base_url=f"{self.env.base_url}",
                token=token,
            )

            self.config_renderer.file_write(
                vpn_service_tokens_path, dict(vpn_service_tokens)
            )

            print("Starting up NetBird agent ...", end="", flush=True)
            try:
                if self.zitadel.is_new:
                    cmd = [
                        f"netbird up",
                        f"--management-url {vpn_service_tokens['base_url']}",
                        f"--admin-url {vpn_service_tokens['base_url']}",
                        f"--setup-key {vpn_service_tokens['setup_key']}",
                        f"--hostname netbird-server",
                    ]
                    response = subprocess.run(
                        cmd, shell=True, check=True, capture_output=True
                    )
                else:
                    response = subprocess.run(
                        "netbird up", shell=True, check=True, capture_output=True
                    )

                if "Connected" not in response.stdout.decode():
                    raise RuntimeError("NetBird agent failed to connect")
            except:
                print("Failed to start NetBird agent")
            print(" done.")

            if self.zitadel.is_new:
                print("\nSetting up Zitadel admin user\n")
                self.zitadel.set_user_password(
                    zitadel_idp_details["human_user_id"],
                    self.env.zitadel_admin_password,
                    force_password_change=True,
                )
                print("\nDeleting Zitadel auto service user\n")
                self.zitadel.delete_auto_service_user()

        print(f"\nYou can access the NetBird dashboard at {self.env.base_url}")
        if self.zitadel.is_new:
            print("Login with the following credentials:")
            print(f"Username: {self.env.zitadel_admin_username}")
            print(f"Password: {self.env.zitadel_admin_password}")

    def get_auth_token(self, vpn_service_tokens_path: str) -> str:
        vpn_service_tokens = __class__.get_vpn_service_tokens(vpn_service_tokens_path)
        token = None
        if vpn_service_tokens:
            print("Using existing Netbird service token")
            token = vpn_service_tokens["service_user_pat"]

        if not token:
            print("Logging into Netbird with admin credentials...")
            auth = AuthHandler(
                base_url=f"{self.env.base_url}",
                client_id=self.env.client_id_dashboard,
                redirect_uri=self.env.redirect_urls_dashboard[0],
                scope=self.env.scopes_dashboard,
            )
            token = auth.get_access_token(
                self.env.zitadel_admin_username, self.env.zitadel_admin_password
            )
        if not token:
            raise RuntimeError("Failed to obtain access token")
        print("Netbird token acquired!")
        return token

    @staticmethod
    def get_vpn_service_tokens(vpn_service_tokens_path) -> Optional[VpnServiceTokens]:
        if os.path.exists(vpn_service_tokens_path):
            f = open(vpn_service_tokens_path, "r")
            peer_config: VpnServiceTokens = json.load(f)
            f.close()
            return peer_config

    def init_crdb(self):
        if self.env.zitadel_db_engine == DbEngine.COCKROACH:
            print("\nInitializing Zitadel's CockroachDB\n")
            self.docker.start_crdb()
            print("\nWaiting CockroachDB to become ready", end="", flush=True)
            self.wait_crdb()

            if not self.crdb_certs_created():
                raise RuntimeError("\ninit_crdb: Failed to create certs\n")

    def wait_crdb(self):
        while self.docker.crdb_is_ready():
            print(".", end="", flush=True)
            time.sleep(5)
        print(" done")

    def crdb_certs_created(self) -> bool:
        response = self.docker.exec(
            "zdb",
            "/bin/bash",
            "-c",
            '"cp /cockroach/certs/* /zitadel-certs/ && cockroach cert create-client --overwrite --certs-dir /zitadel-certs/ --ca-key /zitadel-certs/ca.key zitadel_user && chown -R 1000:1000 /zitadel-certs/"',
        )
        return response.returncode == 0


if __name__ == "__main__":
    drive, _ = os.path.splitdrive(os.getcwd())
    config_path = os.path.join(drive or "/", "opt", "vpn")

    netbird = VpnDeployer(config_path)
    netbird.deploy(server_as_peer=True)
