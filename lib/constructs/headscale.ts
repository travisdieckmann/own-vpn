import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";

export interface HeadScaleProps {}

export class HeadScale extends Construct {
  constructor(scope: Construct, id: string, props?: HeadScaleProps) {
    super(scope, id);
  }
}
