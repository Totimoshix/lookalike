import { App } from "aws-cdk-lib";
import { CapstoneDomainGuardianStack } from "./capstone-stack.js";

const app = new App();
const stageName = process.env.APP_STAGE ?? "dev";
const appVersion = process.env.APP_VERSION ?? "1.0.0";
const deployRegion = process.env.APP_AWS_REGION ?? "ca-central-1";

new CapstoneDomainGuardianStack(app, `CapstoneDomainGuardianStack-${stageName}`, {
  stageName,
  appVersion,
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: deployRegion
  }
});
