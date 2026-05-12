import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  Duration,
  RemovalPolicy,
  Stack,
  type StackProps,
  CfnOutput,
  SecretValue
} from "aws-cdk-lib";
import {
  AccessLogFormat,
  LambdaIntegration,
  LogGroupLogDestination,
  MethodLoggingLevel,
  RestApi
} from "aws-cdk-lib/aws-apigateway";
import { Alarm, ComparisonOperator, TreatMissingData } from "aws-cdk-lib/aws-cloudwatch";
import { AttributeType, BillingMode, Table } from "aws-cdk-lib/aws-dynamodb";
import { Runtime } from "aws-cdk-lib/aws-lambda";
import { NodejsFunction, OutputFormat } from "aws-cdk-lib/aws-lambda-nodejs";
import { LogGroup, RetentionDays } from "aws-cdk-lib/aws-logs";
import { Secret } from "aws-cdk-lib/aws-secretsmanager";
import { Construct } from "constructs";

type CapstoneDomainGuardianStackProps = StackProps & {
  stageName: string;
  appVersion: string;
};

function retentionForStage(stageName: string): RetentionDays {
  return stageName === "prod" ? RetentionDays.THREE_MONTHS : RetentionDays.TWO_WEEKS;
}

export class CapstoneDomainGuardianStack extends Stack {
  constructor(scope: Construct, id: string, props: CapstoneDomainGuardianStackProps) {
    super(scope, id, props);
    const here = path.dirname(fileURLToPath(import.meta.url));
    const removalPolicy = props.stageName === "prod" ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY;
    const providerSecretName = `capstone/${props.stageName}/provider-config`;

    const cacheTable = new Table(this, "AnalysisCacheTable", {
      partitionKey: {
        name: "cache_key",
        type: AttributeType.STRING
      },
      timeToLiveAttribute: "expires_at",
      billingMode: BillingMode.PAY_PER_REQUEST,
      removalPolicy,
      pointInTimeRecovery: props.stageName === "prod"
    });

    const providerConfigSecret = new Secret(this, "ProviderConfigSecret", {
      secretName: providerSecretName,
      description: "Provider configuration for Capstone Domain Guardian 1.0.",
      secretStringValue: SecretValue.unsafePlainText(
        JSON.stringify({
          BEDROCK_MODEL_ID: process.env.BEDROCK_MODEL_ID ?? "",
          VT_API_KEY: process.env.VT_API_KEY ?? "",
          ABUSEIPDB_API_KEY: process.env.ABUSEIPDB_API_KEY ?? "",
          GOOGLE_SAFE_BROWSING_API_KEY: process.env.GOOGLE_SAFE_BROWSING_API_KEY ?? ""
        })
      )
    });

    const commonEnvironment = {
      APP_STAGE: props.stageName,
      APP_VERSION: props.appVersion,
      CACHE_TABLE_NAME: cacheTable.tableName,
      PROVIDER_CONFIG_SECRET_NAME: providerConfigSecret.secretName,
      BEDROCK_REGION: "ca-central-1",
      DNSTWISTER_API_BASE_URL: process.env.DNSTWISTER_API_BASE_URL ?? "https://dnstwister.report/api",
      DNSTWISTER_TIMEOUT_MS: process.env.DNSTWISTER_TIMEOUT_MS ?? "10000"
    };

    const analyzeFunction = new NodejsFunction(this, "AnalyzeFunction", {
      runtime: Runtime.NODEJS_22_X,
      entry: path.join(here, "..", "handlers", "analyze.ts"),
      bundling: {
        target: "node22",
        format: OutputFormat.ESM
      },
      environment: commonEnvironment,
      memorySize: 1024,
      timeout: Duration.seconds(30),
      logRetention: retentionForStage(props.stageName)
    });

    const generateFunction = new NodejsFunction(this, "GenerateLookalikesFunction", {
      runtime: Runtime.NODEJS_22_X,
      entry: path.join(here, "..", "handlers", "generateLookalikes.ts"),
      bundling: {
        target: "node22",
        format: OutputFormat.ESM
      },
      environment: commonEnvironment,
      memorySize: 512,
      timeout: Duration.seconds(15),
      logRetention: retentionForStage(props.stageName)
    });

    const healthFunction = new NodejsFunction(this, "HealthFunction", {
      runtime: Runtime.NODEJS_22_X,
      entry: path.join(here, "..", "handlers", "health.ts"),
      bundling: {
        target: "node22",
        format: OutputFormat.ESM
      },
      environment: commonEnvironment,
      memorySize: 256,
      timeout: Duration.seconds(10),
      logRetention: retentionForStage(props.stageName)
    });

    cacheTable.grantReadWriteData(analyzeFunction);
    cacheTable.grantReadWriteData(generateFunction);
    providerConfigSecret.grantRead(analyzeFunction);
    providerConfigSecret.grantRead(generateFunction);
    providerConfigSecret.grantRead(healthFunction);

    const apiAccessLogs = new LogGroup(this, "ApiAccessLogs", {
      retention: retentionForStage(props.stageName),
      removalPolicy
    });

    const api = new RestApi(this, "CapstoneApi", {
      defaultCorsPreflightOptions: {
        allowOrigins: ["*"],
        allowMethods: ["GET", "POST", "OPTIONS"],
        allowHeaders: ["content-type"]
      },
      deployOptions: {
        stageName: props.stageName,
        throttlingBurstLimit: props.stageName === "prod" ? 50 : 20,
        throttlingRateLimit: props.stageName === "prod" ? 25 : 10,
        metricsEnabled: true,
        loggingLevel: MethodLoggingLevel.INFO,
        dataTraceEnabled: false,
        accessLogDestination: new LogGroupLogDestination(apiAccessLogs),
        accessLogFormat: AccessLogFormat.jsonWithStandardFields({
          httpMethod: true,
          ip: true,
          protocol: true,
          requestTime: true,
          resourcePath: true,
          responseLength: true,
          status: true,
          caller: false,
          user: false
        })
      }
    });

    api.root.addResource("health").addMethod("GET", new LambdaIntegration(healthFunction));
    api.root.addResource("analyze").addMethod("POST", new LambdaIntegration(analyzeFunction));
    api.root.addResource("generate-lookalikes").addMethod("POST", new LambdaIntegration(generateFunction));

    new Alarm(this, "Api5xxAlarm", {
      metric: api.metricServerError({
        period: Duration.minutes(5),
        statistic: "sum"
      }),
      threshold: 3,
      evaluationPeriods: 1,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: TreatMissingData.NOT_BREACHING,
      alarmDescription: "API Gateway 5xx responses exceeded the threshold."
    });

    new Alarm(this, "AnalyzeLambdaErrorsAlarm", {
      metric: analyzeFunction.metricErrors({
        period: Duration.minutes(5),
        statistic: "sum"
      }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: TreatMissingData.NOT_BREACHING,
      alarmDescription: "Analyze Lambda reported one or more errors."
    });

    new CfnOutput(this, "ApiBaseUrl", {
      value: api.url
    });

    new CfnOutput(this, "ProviderConfigSecretName", {
      value: providerConfigSecret.secretName
    });
  }
}
