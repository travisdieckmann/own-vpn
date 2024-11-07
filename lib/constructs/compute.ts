import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import { IRole } from "aws-cdk-lib/aws-iam";
import { AutoScalingGroup, Signals } from "aws-cdk-lib/aws-autoscaling";
import {
  SpotRequestType,
  InstanceClass,
  InstanceInitiatedShutdownBehavior,
  InstanceSize,
  InstanceType,
  LaunchTemplate,
  MachineImage,
  IVpc,
  CloudFormationInit,
  InitConfig,
  InitCommand,
  SecurityGroup,
  IKeyPair,
  CfnLaunchTemplate,
} from "aws-cdk-lib/aws-ec2";

export interface ComputeProps {
  vpc: IVpc;
  role: IRole;
  instanceType?: InstanceType;
  keyPair?: IKeyPair;
  securityGroup: SecurityGroup;
  autoScale: boolean;
  enablePublicIPv4: boolean;
  enableIPv6Only: boolean;
  storageInitConfig: InitConfig;
  dnsInitConfig: InitConfig;
  appInitConfig: InitConfig;
}

export class Compute extends Construct {
  public autoScalingGroup: AutoScalingGroup;

  constructor(scope: Construct, id: string, props: ComputeProps) {
    super(scope, id);
    const launchTemplate = new LaunchTemplate(this, "NetBirdLaunchTemplate", {
      role: props.role,
      keyPair: props.keyPair,
      securityGroup: props.securityGroup,
      associatePublicIpAddress: props.enablePublicIPv4,
      instanceType:
        props.instanceType ||
        InstanceType.of(InstanceClass.T3, InstanceSize.NANO),
      instanceInitiatedShutdownBehavior:
        InstanceInitiatedShutdownBehavior.TERMINATE,
      requireImdsv2: true,
      machineImage: MachineImage.latestAmazonLinux2023(),
      spotOptions: { requestType: SpotRequestType.ONE_TIME },
    });
    if (props.enableIPv6Only)
      (
        launchTemplate.node.defaultChild as CfnLaunchTemplate
      ).addPropertyOverride(
        "LaunchTemplateData.MetadataOptions.HttpProtocolIpv6",
        "enabled"
      );

    const init = CloudFormationInit.fromConfigSets({
      configSets: { default: ["dns", "storage", "docker", "app"] },
      configs: {
        docker: new InitConfig([
          InitCommand.shellCommand("echo Configure Docker..."),
          InitCommand.shellCommand(
            "sudo yum install htop python3-pip docker amazon-cloudwatch-agent -y"
          ),
          InitCommand.shellCommand("sudo service docker start"),
          InitCommand.shellCommand("sudo chkconfig docker on"),
          InitCommand.shellCommand(
            "sudo curl -L https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m) -o /usr/local/bin/docker-compose"
          ),
          InitCommand.shellCommand(
            "sudo chmod +x /usr/local/bin/docker-compose"
          ),
        ]),
        dns: props.dnsInitConfig,
        storage: props.storageInitConfig,
        app: props.appInitConfig,
      },
    });

    this.autoScalingGroup = new AutoScalingGroup(this, "compute", {
      vpc: props.vpc,
      launchTemplate,
      init,
      maxCapacity: 1,
      minCapacity: props.autoScale ? 0 : 1,
      signals: Signals.waitForAll({
        minSuccessPercentage: 0,
        timeout: cdk.Duration.minutes(1),
      }),
      cooldown: cdk.Duration.minutes(1),
    });
  }
}
