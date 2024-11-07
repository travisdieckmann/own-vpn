import os
import json
import yaml
from typing import Union
from yaml import SafeDumper

from vpn_types import DbEngine
from vpn_environment import VpnEnvironment


class ConfigFileRenderer:
    def __init__(self, env: VpnEnvironment):
        self.env = env

    @staticmethod
    def file_writelines(filename, content: list[str]):
        with open(filename, "w+") as fw:
            fw.writelines(line + "\n" for line in content)

    @staticmethod
    def file_write(filename: str, content: Union[str, dict, list]):
        if isinstance(content, dict) or isinstance(content, list):
            content = json.dumps(content, indent=4, sort_keys=True)
        with open(filename, "w+") as fw:
            fw.write(content)

    def docker_compose(self):
        self.docker_services = {
            "caddy": {
                "image": "caddy",
                "restart": "unless-stopped",
                "networks": ["netbird"],
                "ports": ["443:443", "80:80", "8080:8080"],
                "volumes": [
                    "netbird_caddy_data:/data",
                    "./Caddyfile:/etc/caddy/Caddyfile",
                ],
            },
            "dashboard": {
                "image": "netbirdio/dashboard:latest",
                "restart": "unless-stopped",
                "networks": ["netbird"],
                "env_file": ["./dashboard.env"],
                "logging": {
                    "driver": "json-file",
                    "options": {"max-size": "500m", "max-file": "2"},
                },
            },
            "signal": {
                "image": "netbirdio/signal:latest",
                "restart": "unless-stopped",
                "networks": ["netbird"],
                "logging": {
                    "driver": "json-file",
                    "options": {"max-size": "500m", "max-file": "2"},
                },
            },
            "management": {
                "image": "netbirdio/management:latest",
                "restart": "unless-stopped",
                "networks": ["netbird"],
                "volumes": [
                    "netbird_management:/var/lib/netbird",
                    "./management.json:/etc/netbird/management.json",
                ],
                "command": [
                    "--port",
                    "80",
                    "--log-file",
                    "console",
                    "--log-level",
                    "info",
                    "--disable-anonymous-metrics=false",
                    f"--single-account-mode-domain={self.env.local_domain}",
                    f"--dns-domain={self.env.local_domain}",
                    "--idp-sign-key-refresh-enabled",
                ],
                "logging": {
                    "driver": "json-file",
                    "options": {"max-size": "500m", "max-file": "2"},
                },
            },
            "coturn": {
                "image": "coturn/coturn",
                "restart": "unless-stopped",
                "volumes": ["./turnserver.conf:/etc/turnserver.conf:ro"],
                "network_mode": "host",
                "command": ["-c /etc/turnserver.conf"],
                "logging": {
                    "driver": "json-file",
                    "options": {"max-size": "500m", "max-file": "2"},
                },
            },
            "zitadel": {
                "restart": "always",
                "networks": ["netbird"],
                "image": "ghcr.io/zitadel/zitadel:v2.54.3",
                "command": f"start-from-init --masterkeyFromEnv --tlsMode {self.env.zitadel_tls_mode}",
                "env_file": ["./zitadel.env"],
                "depends_on": {"zdb": {"condition": "service_healthy"}},
                "volumes": [
                    "./machinekey:/machinekey",
                    "netbird_zitadel_certs:/zdb-certs:ro",
                ],
                "logging": {
                    "driver": "json-file",
                    "options": {"max-size": "500m", "max-file": "2"},
                },
            },
        }
        self.docker_volumes = {
            "netbird_zdb_data": {
                "driver": "local",
                "driver_opts": {
                    "type": "none",
                    "device": "./data/netbird_zdb_data",
                    "o": "bind",
                },
            },
            "netbird_management": {
                "driver": "local",
                "driver_opts": {
                    "type": "none",
                    "device": "./data/netbird_management",
                    "o": "bind",
                },
            },
            "netbird_caddy_data": {
                "driver": "local",
                "driver_opts": {
                    "type": "none",
                    "device": "./data/netbird_caddy_data",
                    "o": "bind",
                },
            },
            "netbird_zitadel_certs": {
                "driver": "local",
                "driver_opts": {
                    "type": "none",
                    "device": "./data/netbird_zitadel_certs",
                    "o": "bind",
                },
            },
        }
        self.docker_networks = {"netbird": None}

        if self.env.zitadel_db_engine == DbEngine.COCKROACH:
            print("Use CockroachDB as Zitadel database.")
            self.docker_services.update(
                {
                    "zdb": {
                        "restart": "always",
                        "networks": ["netbird"],
                        "image": "cockroachdb/cockroach:latest-v23.2",
                        "command": "start-single-node --advertise-addr zdb",
                        "volumes": [
                            "netbird_zdb_data:/cockroach/cockroach-data",
                            "netbird_zdb_certs:/cockroach/certs",
                            "netbird_zitadel_certs:/zitadel-certs",
                        ],
                        "healthcheck": {
                            "test": [
                                "CMD",
                                "curl",
                                "-f",
                                "http://localhost:8080/health?ready=1",
                            ],
                            "interval": "10s",
                            "timeout": "30s",
                            "retries": 5,
                            "start_period": "20s",
                        },
                        "logging": {
                            "driver": "json-file",
                            "options": {"max-size": "500m", "max-file": "2"},
                        },
                    }
                }
            )

            self.docker_volumes.update(
                {
                    "netbird_zdb_certs": {
                        "driver": "local",
                        "driver_opts": {
                            "type": "none",
                            "device": "./data/netbird_zdb_certs",
                            "o": "bind",
                        },
                    }
                }
            )
        else:
            print("Use Postgres as default Zitadel database.")
            print(
                "For using CockroachDB please the environment variable 'export ZITADEL_DATABASE=cockroach'."
            )
            self.docker_services.update(
                {
                    "zdb": {
                        "restart": "always",
                        "networks": ["netbird"],
                        "image": "postgres:16-alpine",
                        "env_file": ["./zdb.env"],
                        "volumes": ["netbird_zdb_data:/var/lib/postgresql/data:rw"],
                        "healthcheck": {
                            "test": ["CMD-SHELL", "pg_isready", "-d", "db_prod"],
                            "interval": "5s",
                            "timeout": "60s",
                            "retries": 10,
                            "start_period": "5s",
                        },
                        "logging": {
                            "driver": "json-file",
                            "options": {"max-size": "500m", "max-file": "2"},
                        },
                    }
                }
            )

        docker_compose_file_path = os.path.join(
            self.env.config_path, "docker-compose.yml"
        )
        docker_compose = {
            "services": self.docker_services,
            "volumes": self.docker_volumes,
            "networks": self.docker_networks,
        }

        SafeDumper.add_representer(
            type(None),
            lambda dumper, value: dumper.represent_scalar("tag:yaml.org,2002:null", ""),
        )

        with open(docker_compose_file_path, "w+") as file:
            yaml.safe_dump(docker_compose, file)

    def zitadel_config(self):
        zitadel_config = [
            "ZITADEL_LOG_LEVEL=debug",
            f"ZITADEL_MASTERKEY={self.env.zitadel_masterkey}",
            f"ZITADEL_EXTERNALSECURE={str(self.env.zitadel_externalsecure).lower()}",
            'ZITADEL_TLS_ENABLED="false"',
            f"ZITADEL_EXTERNALPORT={self.env.port}",
            f"ZITADEL_EXTERNALDOMAIN={self.env.domain}",
            "ZITADEL_FIRSTINSTANCE_PATPATH=/machinekey/zitadel-admin-sa.token",
            "ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_USERNAME=zitadel-admin-sa",
            "ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_NAME=Admin",
            "ZITADEL_FIRSTINSTANCE_ORG_MACHINE_PAT_SCOPES=openid",
            f"ZITADEL_FIRSTINSTANCE_ORG_MACHINE_PAT_EXPIRATIONDATE={self.env.get_zitadel_token_expiration_date()}",
        ]

        if self.env.zitadel_db_engine == DbEngine.COCKROACH:
            zitadel_config.extend(
                [
                    "ZITADEL_DATABASE_COCKROACH_HOST=zdb",
                    "ZITADEL_DATABASE_COCKROACH_USER_USERNAME=zitadel_user",
                    "ZITADEL_DATABASE_COCKROACH_USER_SSL_MODE=verify-full",
                    'ZITADEL_DATABASE_COCKROACH_USER_SSL_ROOTCERT="/zdb-certs/ca.crt"',
                    'ZITADEL_DATABASE_COCKROACH_USER_SSL_CERT="/zdb-certs/client.zitadel_user.crt"',
                    'ZITADEL_DATABASE_COCKROACH_USER_SSL_KEY="/zdb-certs/client.zitadel_user.key"',
                    "ZITADEL_DATABASE_COCKROACH_ADMIN_SSL_MODE=verify-full",
                    'ZITADEL_DATABASE_COCKROACH_ADMIN_SSL_ROOTCERT="/zdb-certs/ca.crt"',
                    'ZITADEL_DATABASE_COCKROACH_ADMIN_SSL_CERT="/zdb-certs/client.root.crt"',
                    'ZITADEL_DATABASE_COCKROACH_ADMIN_SSL_KEY="/zdb-certs/client.root.key"',
                ]
            )
        else:
            zitadel_config.extend(
                [
                    "ZITADEL_DATABASE_POSTGRES_HOST=zdb",
                    "ZITADEL_DATABASE_POSTGRES_PORT=5432",
                    "ZITADEL_DATABASE_POSTGRES_DATABASE=zitadel",
                    "ZITADEL_DATABASE_POSTGRES_USER_USERNAME=zitadel",
                    f"ZITADEL_DATABASE_POSTGRES_USER_PASSWORD={self.env.postgres_zitadel_password}",
                    "ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE=disable",
                    "ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME=root",
                    f"ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD={self.env.postgres_root_password}",
                    "ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE=disable",
                ]
            )

            file_path = os.path.join(self.env.config_path, "zdb.env")
            postgres_config = [
                "POSTGRES_USER=root",
                f"POSTGRES_PASSWORD={self.env.postgres_root_password}",
            ]
            __class__.file_writelines(file_path, postgres_config)

        file_path = os.path.join(self.env.config_path, "zitadel.env")
        __class__.file_writelines(file_path, zitadel_config)

    def turn_server_conf(self):
        config = [
            "listening-port=3478",
            f"{self.env.turn_external_ip}",
            "tls-listening-port=5349",
            f"min-port={self.env.turn_min_port}",
            f"max-port={self.env.turn_max_port}",
            "fingerprint",
            "lt-cred-mech",
            f"user={self.env.turn_user}:{self.env.turn_password}",
            "realm=wiretrustee.com",
            "cert=/etc/coturn/certs/cert.pem",
            "pkey=/etc/coturn/private/privkey.pem",
            "log-file=stdout",
            "no-software-attribute",
            'pidfile="/var/tmp/turnserver.pid"',
            "no-cli",
        ]

        file_path = os.path.join(self.env.config_path, "turnserver.conf")
        __class__.file_writelines(file_path, config)

    def management_json(self):
        management_json_path = os.path.join(self.env.config_path, "management.json")
        config = {
            "Stuns": [{"Proto": "udp", "URI": f"stun:{self.env.domain}:3478"}],
            "TURNConfig": {
                "Turns": [
                    {
                        "Proto": "udp",
                        "URI": f"turn:{self.env.domain}:3478",
                        "Username": self.env.turn_user,
                        "Password": self.env.turn_password,
                    }
                ],
                "TimeBasedCredentials": False,
            },
            "Signal": {
                "Proto": self.env.http_schema,
                "URI": f"{self.env.domain}:{self.env.port}",
            },
            "HttpConfig": {
                "AuthIssuer": f"{self.env.base_url}",
                "AuthAudience": self.env.client_id_dashboard,
                "OIDCConfigEndpoint": f"{self.env.base_url}/.well-known/openid-configuration",
            },
            "IdpManagerConfig": {
                "ManagerType": "zitadel",
                "ClientConfig": {
                    "Issuer": f"{self.env.base_url}",
                    "TokenEndpoint": f"{self.env.base_url}/oauth/v2/token",
                    "ClientID": self.env.idp_mgmt_client_id,
                    "ClientSecret": self.env.idp_mgmt_client_secret,
                    "GrantType": "client_credentials",
                },
                "ExtraConfig": {
                    "ManagementEndpoint": f"{self.env.base_url}/management/v1"
                },
            },
            "DeviceAuthorizationFlow": {
                "Provider": "hosted",
                "ProviderConfig": {
                    "Audience": self.env.client_id_cli,
                    "ClientID": self.env.client_id_cli,
                    "Scope": self.env.scopes_cli,
                },
            },
            "PKCEAuthorizationFlow": {
                "ProviderConfig": {
                    "Audience": self.env.client_id_cli,
                    "ClientID": self.env.client_id_cli,
                    "Scope": self.env.scopes_dashboard,
                    "RedirectURLs": self.env.redirect_urls_cli,
                }
            },
        }

        with open(management_json_path, "w+") as file:
            json.dump(config, file, indent=4)

    def dashboard_env(self):
        config = [
            "# Endpoints",
            f"NETBIRD_MGMT_API_ENDPOINT={self.env.base_url}",
            f"NETBIRD_MGMT_GRPC_API_ENDPOINT={self.env.base_url}",
            "# OIDC",
            f"AUTH_AUDIENCE={self.env.client_id_dashboard}",
            f"AUTH_CLIENT_ID={self.env.client_id_dashboard}",
            f"AUTH_AUTHORITY={self.env.base_url}",
            "USE_AUTH0=false",
            'AUTH_SUPPORTED_SCOPES="openid profile email offline_access"',
            "AUTH_REDIRECT_URI=/nb-auth",
            "AUTH_SILENT_REDIRECT_URI=/nb-silent-auth",
            "# SSL",
            "NGINX_SSL_PORT=443",
            "# Letsencrypt",
            "LETSENCRYPT_DOMAIN=none",
        ]

        file_path = os.path.join(self.env.config_path, "dashboard.env")
        __class__.file_writelines(file_path, config)

    def caddy_file(self):
        config = """{
  debug
	servers :80,:443 {
    protocols h1 h2c
  }
}

(security_headers) {
    header * {
        # enable HSTS
        # https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#strict-transport-security-hsts
        # NOTE: Read carefully how this header works before using it.
        # If the HSTS header is misconfigured or if there is a problem with
        # the SSL/TLS certificate being used, legitimate users might be unable
        # to access the website. For example, if the HSTS header is set to a
        # very long duration and the SSL/TLS certificate expires or is revoked,
        # legitimate users might be unable to access the website until
        # the HSTS header duration has expired.
        # The recommended value for the max-age is 2 year (63072000 seconds).
        # But we are using 1 hour (3600 seconds) for testing purposes
        # and ensure that the website is working properly before setting
        # to two years.

        Strict-Transport-Security "max-age=3600; includeSubDomains; preload"

        # disable clients from sniffing the media type
        # https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-content-type-options
        X-Content-Type-Options "nosniff"

        # clickjacking protection
        # https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-frame-options
        X-Frame-Options "DENY"

        # xss protection
        # https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-xss-protection
        X-XSS-Protection "1; mode=block"

        # Remove -Server header, which is an information leak
        # Remove Caddy from Headers
        -Server

        # keep referrer data off of HTTP connections
        # https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#referrer-policy
        Referrer-Policy strict-origin-when-cross-origin
    }
}

"""
        config += f":80, {self.env.domain}:{self.env.port}"
        config += """ {
    import security_headers
    # Signal
    reverse_proxy /signalexchange.SignalExchange/* h2c://signal:10000
    # Management
    reverse_proxy /api/* management:80
    reverse_proxy /management.ManagementService/* h2c://management:80
    # Zitadel
    reverse_proxy /zitadel.admin.v1.AdminService/* h2c://zitadel:8080
    reverse_proxy /admin/v1/* h2c://zitadel:8080
    reverse_proxy /zitadel.auth.v1.AuthService/* h2c://zitadel:8080
    reverse_proxy /auth/v1/* h2c://zitadel:8080
    reverse_proxy /zitadel.management.v1.ManagementService/* h2c://zitadel:8080
    reverse_proxy /management/v1/* h2c://zitadel:8080
    reverse_proxy /zitadel.system.v1.SystemService/* h2c://zitadel:8080
    reverse_proxy /system/v1/* h2c://zitadel:8080
    reverse_proxy /assets/v1/* h2c://zitadel:8080
    reverse_proxy /ui/* h2c://zitadel:8080
    reverse_proxy /oidc/v1/* h2c://zitadel:8080
    reverse_proxy /saml/v2/* h2c://zitadel:8080
    reverse_proxy /oauth/v2/* h2c://zitadel:8080
    reverse_proxy /.well-known/openid-configuration h2c://zitadel:8080
    reverse_proxy /openapi/* h2c://zitadel:8080
    reverse_proxy /debug/* h2c://zitadel:8080
    reverse_proxy /device/* h2c://zitadel:8080
    reverse_proxy /device h2c://zitadel:8080
    # Dashboard
    reverse_proxy /* dashboard:80
}
"""

        file_path = os.path.join(self.env.config_path, "Caddyfile")
        __class__.file_write(file_path, config)
