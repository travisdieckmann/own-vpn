import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import {
  InitConfig,
  InitCommand,
  SecurityGroup,
  Peer,
  Port,
  InitFile,
} from "aws-cdk-lib/aws-ec2";
import { Secret } from "aws-cdk-lib/aws-secretsmanager";

export interface NetBirdProps {
  securityGroup: SecurityGroup;
  domain: string;
  credentialsSecret: Secret;
  appPath: string;
}

export class NetBird extends Construct {
  public readonly initConfig: InitConfig;

  constructor(scope: Construct, id: string, props: NetBirdProps) {
    super(scope, id);

    props.securityGroup.addIngressRule(Peer.anyIpv4(), Port.allIcmp());
    props.securityGroup.addIngressRule(Peer.anyIpv4(), Port.HTTP);
    props.securityGroup.addIngressRule(Peer.anyIpv4(), Port.HTTPS);
    props.securityGroup.addIngressRule(Peer.anyIpv4(), Port.tcp(33073));
    props.securityGroup.addIngressRule(Peer.anyIpv4(), Port.tcp(10000));
    props.securityGroup.addIngressRule(Peer.anyIpv4(), Port.udp(3478));
    props.securityGroup.addIngressRule(
      Peer.anyIpv4(),
      Port.udpRange(49152, 65535)
    );
    props.securityGroup.addIngressRule(Peer.anyIpv6(), Port.allIcmpV6());
    props.securityGroup.addIngressRule(Peer.anyIpv6(), Port.HTTP);
    props.securityGroup.addIngressRule(Peer.anyIpv6(), Port.HTTPS);
    props.securityGroup.addIngressRule(Peer.anyIpv6(), Port.tcp(33073));
    props.securityGroup.addIngressRule(Peer.anyIpv6(), Port.tcp(10000));
    props.securityGroup.addIngressRule(Peer.anyIpv6(), Port.udp(3478));
    props.securityGroup.addIngressRule(
      Peer.anyIpv6(),
      Port.udpRange(49152, 65535)
    );

    this.initConfig = new InitConfig([
      InitCommand.shellCommand("echo Installing NetBird Application..."),
      InitCommand.shellCommand(
        "curl -fsSL https://pkgs.netbird.io/install.sh | sh"
      ),
      InitCommand.shellCommand(
        `mkdir -p ${props.appPath}/data/netbird_zdb_certs`
      ),
      InitCommand.shellCommand(
        `mkdir -p ${props.appPath}/data/netbird_zdb_data`
      ),
      InitCommand.shellCommand(
        `mkdir -p ${props.appPath}/data/netbird_management`
      ),
      InitCommand.shellCommand(
        `mkdir -p ${props.appPath}/data/netbird_caddy_data`
      ),
      InitCommand.shellCommand(
        `mkdir -p ${props.appPath}/data/netbird_zitadel_certs`
      ),
      InitCommand.shellCommand(`mkdir -p ${props.appPath}/data/netbird_agent`),
      InitCommand.shellCommand(
        `netbird down && rm -rf /etc/netbird && ln -s ${props.appPath}/data/netbird_agent /etc/netbird`
      ),
      InitFile.fromAsset(`/root/bootstrap.zip`, "./lib/scripts/bootstrap", {
        mode: "644",
      }),
      InitCommand.shellCommand("mkdir -p /opt/vpn/bootstrap"),
      InitCommand.shellCommand("rm -rf /opt/vpn/bootstrap/*"),
      InitCommand.shellCommand(
        `unzip -o /root/bootstrap.zip -d /opt/vpn/bootstrap`
      ),
      InitCommand.shellCommand(
        `sudo pip3 install -r /opt/vpn/bootstrap/requirements.txt`
      ),
      InitCommand.shellCommand(`python3 /opt/vpn/bootstrap/vpn_deployer.py`, {
        env: {
          NETBIRD_DOMAIN: props.domain,
          SECRET_ARN: props.credentialsSecret.secretArn,
          AWS_DEFAULT_REGION: cdk.Stack.of(this).region,
        },
      }),
    ]);
  }
}
