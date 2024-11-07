import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import { Topic } from "aws-cdk-lib/aws-sns";
import { Metric } from "aws-cdk-lib/aws-cloudwatch";
import { TopicHook } from "aws-cdk-lib/aws-autoscaling-hooktargets";
import { EmailSubscription } from "aws-cdk-lib/aws-sns-subscriptions";
import { MetricAggregationType } from "aws-cdk-lib/aws-applicationautoscaling";
import {
  AutoScalingGroup,
  DefaultResult,
  LifecycleTransition,
} from "aws-cdk-lib/aws-autoscaling";

export interface DynamicAvailabilityProps {
  zoneName: string;
  fqdn: string;
  autoScalingGroup: AutoScalingGroup;
  notificationEmail?: string;
  dnsRequestsThreshold?: number;
  bytesOutThreshold?: number;
  bytesEvalPeriods?: number;
}

export class DynamicAvailability extends Construct {
  public readonly snsTopic?: Topic;

  constructor(scope: Construct, id: string, props: DynamicAvailabilityProps) {
    super(scope, id);

    const minDnsRequests = props.dnsRequestsThreshold || 2;
    const maxDnsRequests = minDnsRequests * 1.2;

    const maxBytesTransferred = props.bytesOutThreshold || 4000;
    const minBytesTransffered = maxBytesTransferred / 1.2;
    const bytesEvalPeriods = props.bytesEvalPeriods || 6;

    if (props.notificationEmail) {
      this.snsTopic = new Topic(this, "DnsQueryTopic");

      props.autoScalingGroup.addLifecycleHook("ScaleUpEventOccurred", {
        lifecycleTransition: LifecycleTransition.INSTANCE_LAUNCHING,
        notificationTarget: new TopicHook(this.snsTopic),
        defaultResult: DefaultResult.CONTINUE,
        heartbeatTimeout: cdk.Duration.seconds(30),
      });
      props.autoScalingGroup.addLifecycleHook("ScaleDownEventOccurred", {
        lifecycleTransition: LifecycleTransition.INSTANCE_TERMINATING,
        notificationTarget: new TopicHook(this.snsTopic),
        defaultResult: DefaultResult.CONTINUE,
        heartbeatTimeout: cdk.Duration.seconds(30),
      });

      this.snsTopic.addSubscription(
        new EmailSubscription(props.notificationEmail)
      );
    }

    props.autoScalingGroup.scaleOnMetric("DnsRequestScaleUpA", {
      metric: new Metric({
        namespace: "DNS",
        metricName: "Request",
        region: "us-east-1",
        dimensionsMap: {
          Domain: props.fqdn,
          RecordType: "A",
        },
      }),
      scalingSteps: [
        { lower: minDnsRequests, change: 1 },
        { lower: maxDnsRequests, change: 1 },
      ],
      cooldown: cdk.Duration.minutes(30),
      estimatedInstanceWarmup: cdk.Duration.seconds(30),
    });

    props.autoScalingGroup.scaleOnMetric("DnsRequestScaleUpAAAA", {
      metric: new Metric({
        namespace: "DNS",
        metricName: "Request",
        region: "us-east-1",
        dimensionsMap: {
          Domain: props.fqdn,
          RecordType: "AAAA",
        },
      }),
      scalingSteps: [
        { lower: minDnsRequests, change: 1 },
        { lower: maxDnsRequests, change: 1 },
      ],
      cooldown: cdk.Duration.minutes(30),
      estimatedInstanceWarmup: cdk.Duration.seconds(30),
    });

    props.autoScalingGroup.scaleOnMetric("BytesOutScaleDown", {
      metric: new Metric({
        namespace: "AWS/EC2",
        metricName: "NetworkOut",
        dimensionsMap: {
          AutoScalingGroupName: props.autoScalingGroup.autoScalingGroupName,
        },
      }),
      scalingSteps: [
        { upper: minBytesTransffered, change: -1 },
        { upper: maxBytesTransferred, change: -1 },
      ],
      evaluationPeriods: bytesEvalPeriods,
      metricAggregationType: MetricAggregationType.MAXIMUM,
      cooldown: cdk.Duration.minutes(15),
    });
  }
}
