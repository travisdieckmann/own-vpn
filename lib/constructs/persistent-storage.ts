import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import {
  InitCommand,
  InitConfig,
  InitFile,
  InitPackage,
  Volume,
} from "aws-cdk-lib/aws-ec2";
import { IRole, Policy, PolicyStatement } from "aws-cdk-lib/aws-iam";

export interface PersistentStorageProps {
  availabilityZone: string;
  removalPolicy: cdk.RemovalPolicy;
  size: cdk.Size;
  devicePath: string;
  mountPath: string;
}

export class PersistentStorage extends Construct {
  public readonly ebsVolume: Volume;
  public readonly initConfig: InitConfig;

  constructor(scope: Construct, id: string, props: PersistentStorageProps) {
    super(scope, id);

    const stack = cdk.Stack.of(this);

    this.ebsVolume = new Volume(this, "PersistentStorageEbsVolume", {
      availabilityZone: props.availabilityZone,
      removalPolicy: props.removalPolicy,
      size: props.size,
    });

    this.initConfig = new InitConfig([
      InitPackage.yum("nvme-cli"),
      InitCommand.shellCommand(`mkdir -p ${props.mountPath}`),
      InitFile.fromAsset(
        "/root/disk_attach.sh",
        "./lib/scripts/disk_attach.sh",
        { mode: "755" }
      ),
      InitFile.fromAsset("/root/disk_mount.sh", "./lib/scripts/disk_mount.sh", {
        mode: "755",
      }),
      InitCommand.shellCommand(
        `/root/disk_attach.sh ${stack.region} ${this.ebsVolume.volumeId} ${props.devicePath}`
      ),
      InitCommand.shellCommand(
        `/root/disk_mount.sh ${props.devicePath} ${props.mountPath}`
      ),
    ]);
  }

  grantAsgInstanceVolumeDescribe(role: IRole): void {
    role.attachInlinePolicy(
      new Policy(this, "Ec2InstanceVolumeDescribe", {
        statements: [
          new PolicyStatement({
            actions: [
              "autoscaling:DescribeAutoScalingInstances",
              "ec2:DescribeInstances",
              "ec2:DescribeVolumes",
              "ec2:DescribeVolumeStatus",
            ],
            resources: ["*"],
          }),
        ],
      })
    );
  }
}
