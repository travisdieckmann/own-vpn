import { Construct } from "constructs";
import { RemovalPolicy } from "aws-cdk-lib";
import { InitCommand, InitConfig, InitFile } from "aws-cdk-lib/aws-ec2";
import {
  FilterPattern,
  ILogGroup,
  LogGroup,
  RetentionDays,
  MetricFilter,
} from "aws-cdk-lib/aws-logs";
import {
  IRole,
  Policy,
  PolicyDocument,
  PolicyStatement,
  ServicePrincipal,
} from "aws-cdk-lib/aws-iam";
import {
  PublicHostedZone,
  IPublicHostedZone,
  RecordSet,
  RecordTarget,
  RecordType,
} from "aws-cdk-lib/aws-route53";

export interface DnsProps {
  zoneName: string;
  zoneId?: string;
  hostName?: string;
  enablePublicIPv4?: boolean;
}

export class Dns extends Construct {
  public readonly zoneName: string;
  public readonly hostName?: string;
  public readonly fqdn: string;
  public publicHostedZone: IPublicHostedZone;
  public recordSetIPv4: RecordSet;
  public recordSetIPv6: RecordSet;
  public readonly logGroup: ILogGroup;
  public readonly initConfig: InitConfig;
  public readonly updatePolicyDocument: PolicyDocument;

  constructor(scope: Construct, id: string, props: DnsProps) {
    super(scope, id);

    this.zoneName = props.zoneName;
    this.hostName = props.hostName;
    this.fqdn = props.zoneName;
    if (props.hostName) this.fqdn = `${props.hostName}.${props.zoneName}`;

    const logGroupName = `/aws/route53/${this.zoneName}`;

    if (props.zoneId) {
      this.logGroup = LogGroup.fromLogGroupName(this, "LogGroup", logGroupName);

      this.publicHostedZone = PublicHostedZone.fromHostedZoneAttributes(
        this,
        "PublicHostedZone",
        { hostedZoneId: props.zoneId, zoneName: props.zoneName }
      );
    } else {
      this.logGroup = new LogGroup(this, "LogGroup", {
        logGroupName: logGroupName,
        retention: RetentionDays.ONE_DAY,
        removalPolicy: RemovalPolicy.DESTROY,
      });

      const resourcePolicy = this.logGroup.addToResourcePolicy(
        new PolicyStatement({
          principals: [new ServicePrincipal("route53.amazonaws.com")],
          actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
          resources: [this.logGroup.logGroupArn],
        })
      );

      this.publicHostedZone = new PublicHostedZone(this, "PublicHostedZone", {
        zoneName: props.zoneName,
        queryLogsLogGroupArn: this.logGroup.logGroupArn,
      });
      if (resourcePolicy.policyDependable)
        this.publicHostedZone.node.addDependency(
          resourcePolicy.policyDependable
        );

      new MetricFilter(this, "DnsRequestMetricFilter", {
        logGroup: this.logGroup,
        metricNamespace: "DNS",
        metricName: "Request",
        filterPattern: FilterPattern.literal(
          `[version, timestamp, zoneId, domain, recordType, status, protocol, datacenter, ip]`
        ),
        dimensions: {
          Domain: "$domain",
          RecordType: "$recordType",
        },
      });
    }

    this.recordSetIPv4 = new RecordSet(this, "RecordSetIPv4", {
      zone: this.publicHostedZone,
      recordName: this.fqdn,
      recordType: RecordType.A,
      target: RecordTarget.fromIpAddresses("127.0.0.1"),
    });

    this.recordSetIPv6 = new RecordSet(this, "RecordSetIPv6", {
      zone: this.publicHostedZone,
      recordName: this.fqdn,
      recordType: RecordType.AAAA,
      target: RecordTarget.fromIpAddresses("::1"),
    });

    const ipv4InitConfigElements = [
      InitCommand.shellCommand("echo Updating DNS record IPv4 address..."),
      InitFile.fromString(
        "/root/dns_update_ipv4.json",
        JSON.stringify({
          Comment: "Update record to reflect new IP address for a system ",
          Changes: [
            {
              Action: "UPSERT",
              ResourceRecordSet: {
                Name: this.fqdn,
                Type: "A",
                TTL: 30,
                ResourceRecords: [
                  {
                    Value: "%%IP%%",
                  },
                ],
              },
            },
          ],
        })
      ),
      InitCommand.shellCommand(
        'LOCALIP=`ec2-metadata --quiet -v` && sed -i "s/%%IP%%/${LOCALIP}/g" /root/dns_update_ipv4.json'
      ),
      InitCommand.shellCommand(
        [
          "aws route53 change-resource-record-sets ",
          `--hosted-zone-id ${this.publicHostedZone.hostedZoneId} `,
          "--change-batch file:///root/dns_update_ipv4.json",
        ].join("")
      ),
    ];

    this.initConfig = new InitConfig([
      ...(props.enablePublicIPv4 ? ipv4InitConfigElements : []),
      InitCommand.shellCommand("echo Updating DNS record IPv6 address..."),
      InitFile.fromString(
        "/root/dns_update_ipv6.json",
        JSON.stringify({
          Comment: "Update record to reflect new IP address for a system ",
          Changes: [
            {
              Action: "UPSERT",
              ResourceRecordSet: {
                Name: this.fqdn,
                Type: "AAAA",
                TTL: 30,
                ResourceRecords: [
                  {
                    Value: "%%IP%%",
                  },
                ],
              },
            },
          ],
        })
      ),
      InitCommand.shellCommand(
        [
          'TOKEN=`curl -sX PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` && ',
          'LOCALIP=`curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/ipv6` && ',
          'sed -i "s/%%IP%%/${LOCALIP}/g" /root/dns_update_ipv6.json',
        ].join("")
      ),
      InitCommand.shellCommand(
        [
          "aws route53 change-resource-record-sets ",
          `--hosted-zone-id ${this.publicHostedZone.hostedZoneId} `,
          "--change-batch file:///root/dns_update_ipv6.json",
        ].join("")
      ),
    ]);
  }

  grantRecordSetsWrite(role: IRole): void {
    role.attachInlinePolicy(
      new Policy(this, "Route53UpdateRecordSet", {
        statements: [
          new PolicyStatement({
            actions: ["route53:ListHostedZones", "route53:GetChange"],
            resources: ["*"],
          }),
          new PolicyStatement({
            actions: ["route53:ChangeResourceRecordSets"],
            resources: [this.publicHostedZone.hostedZoneArn],
          }),
        ],
      })
    );
  }
}
