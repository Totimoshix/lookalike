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
import { Rule, RuleTargetInput, Schedule } from "aws-cdk-lib/aws-events";
import { LambdaFunction as LambdaFunctionTarget } from "aws-cdk-lib/aws-events-targets";
import { AttributeType, BillingMode, Table } from "aws-cdk-lib/aws-dynamodb";
import { Effect, PolicyStatement } from "aws-cdk-lib/aws-iam";
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
      // Bedrock region is decoupled from the stack region: Amazon Nova Lite is
      // not offered in ca-central-1, so the LLM step defaults to us-east-1 with
      // the cross-region inference profile (us.amazon.nova-lite-v1:0). Override
      // via the BEDROCK_REGION env var at deploy time. The bedrock:InvokeModel
      // grant uses a wildcard region, so it already covers this.
      BEDROCK_REGION: process.env.BEDROCK_REGION ?? "us-east-1",
      DNSTWISTER_API_BASE_URL: process.env.DNSTWISTER_API_BASE_URL ?? "https://dnstwister.report/api",
      DNSTWISTER_TIMEOUT_MS: process.env.DNSTWISTER_TIMEOUT_MS ?? "10000"
    };

    // ESM output (format: ESM) trips on transitive CommonJS deps that call
    // require() at load time (e.g. safer-buffer via iconv-lite, pulled in by
    // the HTML/encoding parsers) — esbuild emits "Dynamic require of X is not
    // supported". Re-create a real require() from import.meta.url so those
    // CJS modules resolve. Standard fix for CDK NodejsFunction + ESM.
    const esmBundling = {
      target: "node22",
      format: OutputFormat.ESM,
      banner: "import { createRequire as topLevelCreateRequire } from 'module'; const require = topLevelCreateRequire(import.meta.url);"
    };

    const analyzeFunction = new NodejsFunction(this, "AnalyzeFunction", {
      runtime: Runtime.NODEJS_22_X,
      entry: path.join(here, "..", "handlers", "analyze.ts"),
      bundling: esmBundling,
      environment: commonEnvironment,
      memorySize: 1024,
      timeout: Duration.seconds(30),
      logRetention: retentionForStage(props.stageName)
    });

    const analyzeFastFunction = new NodejsFunction(this, "AnalyzeFastFunction", {
      runtime: Runtime.NODEJS_22_X,
      entry: path.join(here, "..", "handlers", "analyzeFast.ts"),
      bundling: esmBundling,
      environment: commonEnvironment,
      memorySize: 512,
      timeout: Duration.seconds(5),
      logRetention: retentionForStage(props.stageName)
    });

    const generateFunction = new NodejsFunction(this, "GenerateLookalikesFunction", {
      runtime: Runtime.NODEJS_22_X,
      entry: path.join(here, "..", "handlers", "generateLookalikes.ts"),
      bundling: esmBundling,
      environment: commonEnvironment,
      memorySize: 512,
      timeout: Duration.seconds(15),
      logRetention: retentionForStage(props.stageName)
    });

    const healthFunction = new NodejsFunction(this, "HealthFunction", {
      runtime: Runtime.NODEJS_22_X,
      entry: path.join(here, "..", "handlers", "health.ts"),
      bundling: esmBundling,
      environment: commonEnvironment,
      memorySize: 256,
      timeout: Duration.seconds(10),
      logRetention: retentionForStage(props.stageName)
    });

    cacheTable.grantReadWriteData(analyzeFunction);
    cacheTable.grantReadWriteData(analyzeFastFunction);
    cacheTable.grantReadWriteData(generateFunction);
    providerConfigSecret.grantRead(analyzeFunction);
    providerConfigSecret.grantRead(analyzeFastFunction);
    providerConfigSecret.grantRead(generateFunction);
    providerConfigSecret.grantRead(healthFunction);

    // Allow the analyze Lambda to invoke Bedrock for the analyst explanation,
    // brand-inference LLM fallback, and reporting-contact notes. The Converse
    // API maps to bedrock:InvokeModel. Scoped to inference profiles in this
    // account (any region, to support cross-region/global profiles) and the
    // account-less foundation-model ARNs those profiles fan out to. Only the
    // analyze path calls Bedrock — fast/generate/health do not.
    analyzeFunction.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
        resources: [
          `arn:aws:bedrock:*:${this.account}:inference-profile/*`,
          "arn:aws:bedrock:*::foundation-model/*"
        ]
      })
    );

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
    const analyzeResource = api.root.addResource("analyze");
    analyzeResource.addMethod("POST", new LambdaIntegration(analyzeFunction));
    analyzeResource.addResource("fast").addMethod("POST", new LambdaIntegration(analyzeFastFunction));
    api.root.addResource("generate-lookalikes").addMethod("POST", new LambdaIntegration(generateFunction));

    // Keep the two analysis Lambdas warm so demo/first-hit latency stays low.
    // Invokes them every 5 minutes with a { warmup: true } event that the
    // handlers short-circuit before doing any work.
    const warmer = new Rule(this, "LambdaWarmer", {
      schedule: Schedule.rate(Duration.minutes(5))
    });
    const warmupEvent = RuleTargetInput.fromObject({ warmup: true });
    warmer.addTarget(new LambdaFunctionTarget(analyzeFunction, { event: warmupEvent }));
    warmer.addTarget(new LambdaFunctionTarget(analyzeFastFunction, { event: warmupEvent }));

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
