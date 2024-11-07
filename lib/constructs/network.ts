import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import {
  IpProtocol,
  SubnetType,
  Vpc,
  SecurityGroup,
  GatewayVpcEndpointAwsService,
  CfnSubnet,
  Peer,
  Port,
} from "aws-cdk-lib/aws-ec2";

export interface NetworkProps {
  enablePublicIPv4?: boolean;
  enableIPv6Only?: boolean;
  sshAllowedFromCidrIpv4?: string;
  sshAllowedFromCidrIpv6?: string;
}

export class Network extends Construct {
  public vpc: Vpc;
  public securityGroup: SecurityGroup;

  constructor(scope: Construct, id: string, props?: NetworkProps) {
    super(scope, id);

    const stack = cdk.Stack.of(this);

    this.vpc = new Vpc(this, "VpnVpc", {
      ipProtocol: IpProtocol.DUAL_STACK,
      maxAzs: 1,
      subnetConfiguration: [
        {
          name: "Public",
          subnetType: SubnetType.PUBLIC,
        },
      ],
      gatewayEndpoints: {
        S3: { service: GatewayVpcEndpointAwsService.S3 },
        DynamoDB: { service: GatewayVpcEndpointAwsService.DYNAMODB },
      },
    });
    this.vpc.node.tryRemoveChild("EIGW6");
    // Configure subnet for IPv6 since CDK L2 doesn't support all options
    this.vpc.publicSubnets.forEach((subnet) => {
      const pubSubnet = subnet.node.defaultChild as CfnSubnet;
      pubSubnet.addPropertyOverride("PrivateDnsNameOptionsOnLaunch", {
        EnableResourceNameDnsARecord: !props?.enableIPv6Only,
        EnableResourceNameDnsAAAARecord: true,
        HostnameType: "resource-name",
      });

      // Configure subnet for IPv6 ONLY:
      if (props?.enableIPv6Only) {
        pubSubnet.addPropertyDeletionOverride("CidrBlock");
        pubSubnet.addPropertyOverride("Ipv6Native", true);
        pubSubnet.addPropertyOverride("EnableDns64", true);
      }
    });

    this.securityGroup = new SecurityGroup(this, "VpnSecurityGroup", {
      vpc: this.vpc,
      allowAllIpv6Outbound: true,
      allowAllOutbound: true,
    });
    if (props?.sshAllowedFromCidrIpv4)
      this.securityGroup.addIngressRule(
        Peer.ipv4(props.sshAllowedFromCidrIpv4),
        Port.SSH
      );
    if (props?.sshAllowedFromCidrIpv6)
      this.securityGroup.addIngressRule(
        Peer.ipv6(props.sshAllowedFromCidrIpv6),
        Port.SSH
      );
  }
}
