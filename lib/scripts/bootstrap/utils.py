import os
import json
import boto3
import secrets
import string
import subprocess
from typing import Optional, Any
from datetime import datetime


def timestamp_to_datetime(timestamp: str) -> datetime:
    return datetime.fromisoformat(f'{timestamp.split(".")[0]}+00:00')


class Metadata:
    file_path = "/run/cloud-init/instance-data.json"
    metadata: dict[str, Any] = {}

    def __init__(self):
        if not Metadata.metadata:
            Metadata.metadata = self.__load_metadata()

    def __load_metadata(self) -> dict[str, Any]:
        if not os.path.exists(self.file_path):
            raise RuntimeError(f"File not found: {self.file_path}")
        instance_data = {}
        with open(self.file_path, "r") as f:
            instance_data = json.load(f)

        if not instance_data:
            raise RuntimeError("No instance data found")

        return instance_data.get("ds", {}).get("meta-data", {})

    def local_ipv4(self) -> str:
        return Metadata.metadata.get("local-ipv4", "")

    def public_ipv4(self) -> str:
        return Metadata.metadata.get("public-ipv4", "")

    def ipv6(self) -> str:
        return Metadata.metadata.get("ipv6", "")


def generate_random_string(
    length,
    use_punctuation: bool = False,
    use_base64: bool = False,
    use_safe_symbols: bool = False,
):
    characters = string.ascii_letters + string.digits
    if use_punctuation:
        characters += string.punctuation
    if use_base64:
        characters += "+/"
    if use_safe_symbols:
        characters += "!@#$%^&*()-_=+|;:/?.>"
    characters = list(set(characters))
    return "".join(secrets.choice(characters) for _ in range(length))


# def get_host_ip():
#     import socket

#     try:
#         # Connect to an external server to retrieve local IP (no actual data is sent)
#         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         s.connect(("8.8.8.8", 80))  # Google's public DNS IP
#         ip_address = s.getsockname()[0]
#         s.close()
#         return ip_address
#     except Exception as e:
#         raise RuntimeError(f"Unable to get IP address: {e}")


def check_jq():
    if (
        subprocess.run(
            ["jq", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode
        != 0
    ):
        raise RuntimeError(
            "jq is not installed or not in PATH, please install with your package manager. e.g. sudo apt install jq"
        )


def store_credentials(
    secret_arn: Optional[str], credentials: dict[str, str]
) -> dict[str, Any]:
    if not secret_arn:
        print("No secret ARN provided, skipping storing credentials")
        return {}

    client = boto3.client("secretsmanager")
    response = client.update_secret(
        SecretId=secret_arn,
        SecretString=json.dumps(credentials),
    )
    return response


class DockerCompose:
    def __init__(self, working_dir: Optional[str] = None):
        self.working_dir = working_dir
        self.docker_compose_command = __class__.check_docker_compose()

    def up(self, *args):
        cmd = [self.docker_compose_command, "up", "-d", *args]
        print(f'Executing CMD: {" ".join(cmd)} | CWD: {self.working_dir}')
        subprocess.run(
            cmd,
            check=True,
            cwd=self.working_dir,
        )

    def start_zitadel(self):
        print("\nStarting Zitadel IDP for user management\n")
        self.up("caddy", "zitadel")

    def start_services(self):
        print("\nStarting NetBird services\n")
        self.up()
        print("\nDone!\n")

    def exec(self, service, *args):
        cmd = [self.docker_compose_command, "exec", service, *args]
        print(f'Executing CMD: {" ".join(cmd)} | CWD: {self.working_dir}')
        return subprocess.run(
            cmd,
            cwd=self.working_dir,
        )

    def crdb_is_ready(self) -> bool:
        result = self.exec(
            "zdb",
            "curl",
            "-sf",
            "-o",
            "/dev/null",
            "'http://localhost:8080/health?ready=1'",
        )
        if result.returncode == 0:
            return True
        return False

    def start_crdb(self):
        self.up("zdb")

    @staticmethod
    def check_docker_compose():
        if (
            subprocess.run(
                ["/usr/local/bin/docker-compose", "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        ):
            return "/usr/local/bin/docker-compose"
        elif (
            subprocess.run(
                ["/usr/bin/docker", "compose", "--help"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        ):
            return "/usr/bin/docker compose"
        else:
            raise RuntimeError(
                "docker-compose is not installed or not in PATH. Please follow the steps from the official guide: https://docs.docker.com/engine/install/"
            )


if __name__ == "__main__":
    docker = DockerCompose("/opt/vpn")
    docker.up("caddy", "zitadel")
