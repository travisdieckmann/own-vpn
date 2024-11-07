import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import { AutoScalingGroup, Signals } from "aws-cdk-lib/aws-autoscaling";
import {
  ManagedPolicy,
  PolicyDocument,
  PolicyStatement,
  Role,
  ServicePrincipal,
} from "aws-cdk-lib/aws-iam";
import {
  SpotRequestType,
  InstanceClass,
  InstanceInitiatedShutdownBehavior,
  InstanceSize,
  InstanceType,
  LaunchTemplate,
  IVpc,
  SecurityGroup,
  IKeyPair,
  UserData,
  NatInstanceProviderV2,
  NatInstanceImage,
} from "aws-cdk-lib/aws-ec2";

export interface VpnNatGatwayInstanceProps {
  vpc: IVpc;
  keyPair?: IKeyPair;
}

export class VpnNatGatwayInstance extends Construct {
  constructor(scope: Construct, id: string, props: VpnNatGatwayInstanceProps) {
    super(scope, id);

    const stack = cdk.Stack.of(this);

    const gwRole = new Role(this, "NatGatewayInstanceRole", {
      assumedBy: new ServicePrincipal("ec2.amazonaws.com"),
      managedPolicies: [
        ManagedPolicy.fromAwsManagedPolicyName("AmazonSSMManagedInstanceCore"),
      ],
      inlinePolicies: {
        RouteTablePermissions: new PolicyDocument({
          statements: [
            new PolicyStatement({
              actions: ["ec2:ReplaceRoute"],
              resources: [
                `arn:${stack.partition}:ec2:${stack.region}:${stack.account}:route-table/${props.vpc.publicSubnets[0].routeTable.routeTableId}`,
              ],
            }),
            new PolicyStatement({
              actions: ["ec2:DescribeInstances"],
              resources: ["*"],
            }),
          ],
        }),
      },
    });

    const natGatewaySg = new SecurityGroup(this, "NatGatewaySecurityGroup", {
      vpc: props.vpc,
    });
    const natGwInstanceAsg = new AutoScalingGroup(this, "NatGatewayInstance", {
      vpc: props.vpc,
      launchTemplate: new LaunchTemplate(this, "NatGatewayLaunchTemplate", {
        role: gwRole,
        keyPair: props.keyPair,
        securityGroup: natGatewaySg,
        instanceType: InstanceType.of(InstanceClass.T3, InstanceSize.NANO),
        instanceInitiatedShutdownBehavior:
          InstanceInitiatedShutdownBehavior.TERMINATE,
        requireImdsv2: true,
        machineImage: new NatInstanceImage(),
        userData: UserData.custom(
          [
            ...NatInstanceProviderV2.DEFAULT_USER_DATA_COMMANDS,
            "ENI_ID=$(aws ec2 describe-instances --instance-ids $(ec2-metadata --quiet -i) | jq -r '.Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId')",
            "aws ec2 replace-route --destination-cidr-block 0.0.0.0/0 --network-interface-id ${ENI_ID}",
          ].join(`\n`)
        ),
        spotOptions: { requestType: SpotRequestType.ONE_TIME },
      }),
      desiredCapacity: 1,
      minCapacity: 1,
      maxCapacity: 1,
      signals: Signals.waitForAll({
        minSuccessPercentage: 0,
        timeout: cdk.Duration.minutes(1),
      }),
      cooldown: cdk.Duration.minutes(1),
    });
  }
}
