import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import { Dns } from "./constructs/dns";
import { Network } from "./constructs/network";
import { NetBird } from "./constructs/netbird";
import { Compute } from "./constructs/compute";
import { Secret } from "aws-cdk-lib/aws-secretsmanager";
import { InstanceType, KeyPair } from "aws-cdk-lib/aws-ec2";
import { PersistentStorage } from "./constructs/persistent-storage";
import { DynamicAvailability } from "./constructs/dynamic-availability";
import {
  ManagedPolicy,
  PolicyDocument,
  PolicyStatement,
  Role,
  ServicePrincipal,
} from "aws-cdk-lib/aws-iam";

export class OwnVpnDnsStack extends cdk.Stack {
  public readonly dns: Dns;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const contextZoneName: string = this.node.tryGetContext("ZoneName");
    if (!contextZoneName) throw new Error("ZoneName context must be provided!");
    const contextZoneId: string | undefined = this.node.tryGetContext("ZoneId");
    const contextHostName: string | undefined =
      this.node.tryGetContext("HostName");
    const enablePublicIPv4 =
      (this.node.tryGetContext("EnablePublicIPv4") || "TRUE").toUpperCase() ===
      "TRUE";
    const dynamicAvailability =
      (
        this.node.tryGetContext("DynamicAvailability") || "FALSE"
      ).toUpperCase() === "TRUE";

    this.dns = new Dns(this, "DNS", {
      zoneName: contextZoneName,
      zoneId: contextZoneId,
      hostName: contextHostName,
      enablePublicIPv4,
    });
  }
}

interface OwnVpnComputeStackProps extends cdk.StackProps {
  dns: Dns;
}

export class OwnVpnComputeStack extends cdk.Stack {
  constructor(
    scope: Construct,
    id: string,
    props: cdk.StackProps,
    computeProps: OwnVpnComputeStackProps
  ) {
    super(scope, id, props);

    const dns = computeProps.dns;

    const contextInstanceType: string =
      this.node.tryGetContext("InstanceType") || "t3.micro";
    const contextNotificationEmail: string | undefined =
      this.node.tryGetContext("NotificationEmail");
    const contextSshAllowedIpv4Cidr: string | undefined =
      this.node.tryGetContext("SshAllowedIpv4Cidr");
    const contextSshAllowedIpv6Cidr: string | undefined =
      this.node.tryGetContext("SshAllowedIpv6Cidr");
    const contextKeyPairName: string | undefined =
      this.node.tryGetContext("KeyPairName");
    const enablePublicIPv4 =
      (this.node.tryGetContext("EnablePublicIPv4") || "TRUE").toUpperCase() ===
      "TRUE";
    const enableIPv6Only =
      (this.node.tryGetContext("EnableIPv6Only") || "FALSE").toUpperCase() ===
      "TRUE";
    const dynamicAvailability =
      (
        this.node.tryGetContext("DynamicAvailability") || "FALSE"
      ).toUpperCase() === "TRUE";

    const keyPair = contextKeyPairName
      ? KeyPair.fromKeyPairName(this, "VpnTestingKeyPair", contextKeyPairName)
      : undefined;
    const volumeMountPath = "/opt/vpn";

    const role = new Role(this, "VpnInstanceRole", {
      roleName: cdk.PhysicalName.GENERATE_IF_NEEDED,
      assumedBy: new ServicePrincipal("ec2.amazonaws.com"),
      managedPolicies: [
        ManagedPolicy.fromAwsManagedPolicyName("AmazonSSMManagedInstanceCore"),
        ManagedPolicy.fromAwsManagedPolicyName("CloudWatchAgentServerPolicy"),
      ],
      inlinePolicies: {
        NetBirdDns: new PolicyDocument({
          statements: [
            new PolicyStatement({
              actions: ["route53:ListHostedZones", "route53:GetChange"],
              resources: ["*"],
            }),
            new PolicyStatement({
              actions: ["route53:ChangeResourceRecordSets"],
              resources: [dns.publicHostedZone.hostedZoneArn],
            }),
          ],
        }),
      },
    });

    const network = new Network(this, "Network", {
      enablePublicIPv4,
      enableIPv6Only,
      sshAllowedFromCidrIpv4: contextSshAllowedIpv4Cidr,
      sshAllowedFromCidrIpv6: contextSshAllowedIpv6Cidr,
    });

    const credentialsSecret = new Secret(this, "VpnCredentialsSecret", {
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          Username: `admin@${dns.fqdn}`,
        }),
        generateStringKey: "Password",
        passwordLength: 44,
      },
    });
    credentialsSecret.grantWrite(role);

    const storage = new PersistentStorage(this, "PersistentStorage", {
      availabilityZone: network.vpc.publicSubnets[0].availabilityZone,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      size: cdk.Size.gibibytes(1),
      devicePath: "/dev/xvdh",
      mountPath: volumeMountPath,
    });
    storage.ebsVolume.grantAttachVolume(role);
    storage.ebsVolume.grantDetachVolume(role);
    storage.grantAsgInstanceVolumeDescribe(role);

    const app = new NetBird(this, "NetBirdConfig", {
      securityGroup: network.securityGroup,
      domain: dns.fqdn,
      credentialsSecret,
      appPath: volumeMountPath,
    });

    const compute = new Compute(this, "Compute", {
      vpc: network.vpc,
      securityGroup: network.securityGroup,
      autoScale: dynamicAvailability,
      enablePublicIPv4: enablePublicIPv4,
      enableIPv6Only: enableIPv6Only,
      role: role,
      storageInitConfig: storage.initConfig,
      dnsInitConfig: dns.initConfig,
      appInitConfig: app.initConfig,
      keyPair: keyPair,
      instanceType: new InstanceType(contextInstanceType),
    });

    if (dynamicAvailability)
      if (this.region !== "us-east-1")
        throw new Error(
          "DynamicAvailability is currently only supported in us-east-1. Please change the stack context."
        );
    new DynamicAvailability(this, "DynamicAvailability", {
      zoneName: dns.zoneName,
      fqdn: dns.fqdn,
      notificationEmail: contextNotificationEmail,
      autoScalingGroup: compute.autoScalingGroup,
    });

    new cdk.CfnOutput(this, "PublicHostedZoneId", {
      value: dns.publicHostedZone.hostedZoneId,
    });
    new cdk.CfnOutput(this, "HostedZone", {
      value: `https://us-east-1.console.aws.amazon.com/route53/v2/hostedzones?region=${this.region}#ListRecordSets/${dns.publicHostedZone.hostedZoneId}`,
    });
    new cdk.CfnOutput(this, "ZoneName", { value: dns.zoneName });
    new cdk.CfnOutput(this, "HostName", { value: dns.zoneName });
    new cdk.CfnOutput(this, "Url", { value: `https://${dns.fqdn}` });
    new cdk.CfnOutput(this, "InitialCredentials", {
      value: `https://${this.region}.console.aws.amazon.com/secretsmanager/home?region=${this.region}#!/secret?name=${credentialsSecret.secretArn}`,
    });
  }
}
