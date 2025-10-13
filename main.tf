terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
  }
}

provider "aws" {
  region = var.region
}

resource "aws_ecs_cluster" "this" {
  name = "sb-${var.environment}-tenant-${split("-", var.tenant_id)[0]}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Tenant = var.tenant_id
    Tier   = var.tier
  }
}

resource "aws_security_group" "alb" {
  name        = "sb-${var.environment}-tenant-${split("-", var.tenant_id)[0]}-alb-sg"
  description = "HTTP/S access to the load balancer"
  vpc_id      = var.egress_public_vpc_id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Tenant = var.tenant_id
  }
}

resource "aws_security_group" "ecs" {
  name        = "sb-${var.environment}-tenant-${split("-", var.tenant_id)[0]}-ecssg"
  description = "Access to containers"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Tenant = var.tenant_id
  }
}

resource "aws_vpc_security_group_ingress_rule" "ecs_intra" {
  security_group_id = aws_security_group.ecs.id
  cidr_ipv4         = var.cidr_prefix
  ip_protocol       = "-1"
}

resource "aws_security_group" "lambda" {
  name        = "sb-${var.environment}-tenant-${split("-", var.tenant_id)[0]}-lambda-sg"
  description = "Lambda SG for NLB discovery function"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Tenant = var.tenant_id
  }
}

resource "aws_lb" "app_alb" {
  name               = "sb-${var.environment}-tenant-${split("-", var.tenant_id)[0]}"
  internal           = true
  load_balancer_type = "application"

  subnets         = [var.egress_public_subnet_id1, var.egress_public_subnet_id2]
  security_groups = [aws_security_group.alb.id]

  idle_timeout = 30

  tags = {
    Tenant = var.tenant_id
    Tier   = var.tier
  }
}

data "archive_file" "nlb_fn_zip" {
  type             = "zip"
  output_path      = "${path.module}/build/nlb_function.zip"
  source_content   = <<-PY
    import boto3
    import os
    import urllib3
    import json

    nlb_loadbalancer_name = os.environ['NLB_LOADBALANCER_NAME']
    filter_value = f"*{nlb_loadbalancer_name}*"

    client = boto3.client('ec2')

    def lambda_handler(event, context):
        request_type = event.get('RequestType')
        response_data = {}
        if request_type in ['Create', 'Update']:
            try:
                response = client.describe_network_interfaces(
                    Filters=[{'Name': 'description', 'Values': [filter_value]}]
                )
                private_addresses = [iface['PrivateIpAddress'] for iface in response['NetworkInterfaces']]
                response_data['PrivateAddresses'] = private_addresses
                return { 'Status': 'SUCCESS', 'Data': response_data }
            except Exception as e:
                print(e)
                return { 'Status': 'FAILED', 'Data': response_data }
        elif request_type == 'Delete':
            http = urllib3.PoolManager()
            response_body = {
                "Status": "SUCCESS",
                "PhysicalResourceId": event.get("PhysicalResourceId"),
                "StackId": event.get('StackId'),
                "RequestId": event.get('RequestId'),
                "LogicalResourceId": event.get('LogicalResourceId')
            }
            url = event.get("ResponseURL")
            json_body = json.dumps(response_body)
            headers = { 'content-type': '', 'content-length': str(len(json_body)) }
            try:
                http.request('PUT', url, body=json_body.encode('utf-8'), headers=headers)
            except Exception as e:
                print(f"send(..) failed: {e}")
            return { 'Status': 'SUCCESS' }
  PY
  source_content_filename = "index.py"
}

resource "aws_iam_role" "lambda" {
  name = "sb-${var.environment}-tenant-${split("-", var.tenant_id)[0]}-nlb-function-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = { Service = "lambda.amazonaws.com" },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "nlb_eni_policy" {
  name        = "sb-${var.environment}-tenant-${split("-", var.tenant_id)[0]}-nlb-eni"
  description = "Allow describe and manage ENIs for NLB discovery"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:DescribeNetworkInterfaces",
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:DescribeInstances",
          "ec2:AttachNetworkInterface"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "nlb_eni_attach" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.nlb_eni_policy.arn
}

resource "aws_lb" "nlb" {
  count              = var.create_nlb ? 1 : 0
  name               = "sb-${var.environment}-tenant-${split("-", var.tenant_id)[0]}-nlb"
  internal           = true
  load_balancer_type = "network"
  subnets            = [var.private_subnet_a, var.private_subnet_b]
}

data "aws_lb" "existing_nlb" {
  count = var.create_nlb ? 0 : 1
  arn   = var.existing_nlb_arn
}

resource "aws_lambda_function" "nlb_function" {
  function_name = "sb-${var.environment}-tenant-${split("-", var.tenant_id)[0]}-nlb-function"
  role          = aws_iam_role.lambda.arn
  handler       = "index.lambda_handler"
  runtime       = "python3.12"
  timeout       = 300

  filename         = data.archive_file.nlb_fn_zip.output_path
  source_code_hash = data.archive_file.nlb_fn_zip.output_base64sha256

  vpc_config {
    security_group_ids = [aws_security_group.lambda.id]
    subnet_ids         = [var.private_subnet_a, var.private_subnet_b]
  }

  environment {
    variables = {
      NLB_LOADBALANCER_NAME = coalesce(try(aws_lb.nlb[0].name, null), try(data.aws_lb.existing_nlb[0].name, null))
    }
  }
}

# ===== Merged from alb_nlb.tf =====
# Default ALB Target Group
resource "aws_lb_target_group" "alb_default" {
  name        = "sb-${var.environment}-tenant-${split("-", var.tenant_id)[0]}"
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.egress_public_vpc_id

  health_check {
    protocol            = "HTTP"
    path                = "/"
    interval            = 15
    timeout             = 10
    healthy_threshold   = 2
    unhealthy_threshold = 5
    matcher             = "200-499"
  }

  stickiness {
    enabled = true
    type    = "lb_cookie"
    cookie_duration = 86400
  }

  deregistration_delay = 30

  tags = {
    Environment = var.environment
    Name        = "sb-${var.environment}-tenant-${split("-", var.tenant_id)[0]}"
    Tenant      = var.tenant_id
    Tier        = var.tier
  }
}

# HTTPS Listener for ALB
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app_alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
  certificate_arn   = var.ssl_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.alb_default.arn
  }
}

# HTTP listener redirect to HTTPS
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.app_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      protocol = "HTTPS"
      port     = "443"
      host     = "#{host}"
      path     = "/#{path}"
      query    = "#{query}"
      status_code = "HTTP_301"
    }
  }
}

# NLB Target Group
resource "aws_lb_target_group" "nlb_tg" {
  name        = "sb-${var.environment}-tenant-${split("-", var.tenant_id)[0]}-nlb-tg"
  port        = 80
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  health_check {
    enabled  = true
    protocol = "HTTP"
    port     = "traffic-port"
    path     = "/ingestion"
    interval = 10
    timeout  = 10
    healthy_threshold   = 3
  }

  tags = {
    Environment = var.environment
    Name        = "sb-${var.environment}-tenant-${split("-", var.tenant_id)[0]}-${var.service_resource_name}"
    Tenant      = var.tenant_id
    Tier        = var.tier
  }
}

# NLB Listener on port 80
resource "aws_lb_listener" "nlb_http" {
  load_balancer_arn = var.create_nlb ? aws_lb.nlb[0].arn : data.aws_lb.existing_nlb[0].arn
  port              = 80
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.nlb_tg.arn
  }
}

# ===== Merged from ecs.tf =====
# Log group for ECS
resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/sb-${var.environment}-tenant-${var.tenant_short_id}-${var.service_resource_name}"
  retention_in_days = 30
}

# Execution Role
resource "aws_iam_role" "ecs_exec" {
  name = "sb-${var.environment}-tenant-${var.tenant_short_id}-exec-${var.service_resource_name}${var.region}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ecs-tasks.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "ecs_exec_inline" {
  name = "sb-${var.environment}-tenant-${var.tenant_short_id}-exec-${var.service_resource_name}"
  role = aws_iam_role.ecs_exec.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      { Effect = "Allow", Action = ["logs:PutLogEvents"], Resource = ["arn:${var.partition}:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:*:log-stream:*"] },
      { Effect = "Allow", Action = ["logs:CreateLogStream"], Resource = ["arn:${var.partition}:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:*"] },
      { Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability","ecr:GetDownloadUrlForLayer","ecr:BatchGetImage"], Resource = ["*"] },
      { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = ["*"] },
      { Effect = "Allow", Action = ["ssm:GetParameters"], Resource = [
        "arn:${var.partition}:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/saas-platform/${var.environment}/${var.tenant_short_id}/*",
        "arn:${var.partition}:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/saas-platform/${var.environment}/METRICS_STREAM"
      ] },
      { Effect = "Allow", Action = [
        "secretsmanager:GetSecretValue","secretsmanager:GetResourcePolicy","secretsmanager:DescribeSecret","secretsmanager:ListSecretVersionIds"
      ], Resource = [
        "arn:${var.partition}:secretsmanager:${var.region}:${data.aws_caller_identity.current.account_id}:secret:/saas-platform/${var.environment}/${var.tenant_short_id}/RDS_CREDENTIALS"
      ] },
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = [
        "arn:${var.partition}:s3:::${aws_s3_bucket.resources.bucket}/tenants/${var.tenant_id}/ServiceDiscovery.env"
      ] },
      { Effect = "Allow", Action = ["s3:GetBucketLocation"], Resource = [
        "arn:${var.partition}:s3:::${aws_s3_bucket.resources.bucket}"
      ] },
      { Effect = "Allow", Action = ["fsx:DescribeFileSystems"], Resource = [
        "arn:${var.partition}:fsx:${var.region}:${data.aws_caller_identity.current.account_id}:file-system/*"
      ] },
      { Effect = "Allow", Action = [
        "s3:GetObject","s3:GetObjectVersion","s3:ListBucket","s3:ListBucketVersions","s3:GetBucket*","s3:GetAccelerateConfiguration","s3:GetAnalyticsConfiguration","s3:GetEncryptionConfiguration","s3:GetIntelligentTieringConfiguration","s3:GetInventoryConfiguration","s3:GetLifecycleConfiguration","s3:GetMetricsConfiguration","s3:PutObject*","s3:DeleteObject*","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"
      ], Resource = ["*"] }
    ]
  })
}

# Task Role
resource "aws_iam_role" "ecs_task" {
  name = "sb-${var.environment}-tenant-${var.tenant_short_id}-task-${var.service_resource_name}${var.region}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ecs-tasks.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

# Task Role policies (condensed to match YAML intents)
resource "aws_iam_role_policy" "ecs_task_policies" {
  name = "sb-${var.environment}-tenant-${var.tenant_short_id}-task-${var.service_resource_name}"
  role = aws_iam_role.ecs_task.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      { Effect = "Allow", Action = [
        "s3:GetObject","s3:GetObjectVersion","s3:ListBucket","s3:ListBucketVersions","s3:GetBucket*","s3:GetAccelerateConfiguration","s3:GetAnalyticsConfiguration","s3:GetEncryptionConfiguration","s3:GetIntelligentTieringConfiguration","s3:GetInventoryConfiguration","s3:GetLifecycleConfiguration","s3:GetMetricsConfiguration","s3:PutObject*","s3:DeleteObject*","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"
      ], Resource = ["*"] },
      { Effect = "Allow", Action = [
        "cognito-idp:*"
      ], Resource = ["*"] },
      { Effect = "Allow", Action = [
        "dynamodb:*"
      ], Resource = ["*"] },
      { Effect = "Allow", Action = [
        "states:DescribeExecution","states:GetExecutionHistory","states:StartExecution"
      ], Resource = ["*"] },
      { Effect = "Allow", Action = [
        "firehose:PutRecord","firehose:PutRecordBatch"
      ], Resource = ["arn:${var.partition}:firehose:${var.region}:${data.aws_caller_identity.current.account_id}:deliverystream/sb-${var.environment}-metrics-stream"] },
      { Effect = "Allow", Action = [
        "quicksight:DescribeUser","quicksight:GenerateEmbedUrlForRegisteredUser"
      ], Resource = ["*"] },
      { Effect = "Allow", Action = [
        "events:DescribeEventBus","events:PutEvents"
      ], Resource = ["arn:${var.partition}:events:${var.region}:${data.aws_caller_identity.current.account_id}:event-bus/${var.event_bus_name}"] }
    ]
  })
}

data "aws_caller_identity" "current" {}

# Ingestion Task Definition
resource "aws_ecs_task_definition" "ingestion" {
  family                   = "sb-${var.environment}-tenant-ingestion-${var.tenant_short_id}-${var.service_resource_name}"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "2048"
  memory                   = "4096"
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_exec.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "sb-${var.environment}-tenant-${var.tenant_short_id}-${var.service_resource_name}"
      image     = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.region}.${var.url_suffix}/${var.container_repository}:${var.image_tag}"
      cpu       = 2048
      memory    = 4096
      portMappings = [{ containerPort = var.container_port }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.ecs.name
          awslogs-region        = var.region
          awslogs-stream-prefix = "ecs"
        }
      }
      environment = [
        { name = "AWS_REGION", value = var.region },
        { name = "SAAS_PLATFORM_ENV", value = var.environment },
        { name = "TENANT_ID", value = var.tenant_id },
        { name = "SAAS_PLATFORM_RESOURCES_BUCKET", value = aws_s3_bucket.resources.bucket },
        { name = "SAAS_PLATFORM_EVENT_BUS", value = var.event_bus_name },
        { name = "METRICS_STREAM", value = var.metrics_stream },
        { name = "FILESYSTEM_MONITORING", value = "false" },
        { name = "DYNAMO_TABLE1", value = aws_dynamodb_table.dynamo1.name },
        { name = "DYNAMO_TABLE2", value = aws_dynamodb_table.dynamo2.name },
        { name = "DYNAMO_TABLE3", value = "" },
        { name = "DYNAMO_TABLE4", value = aws_dynamodb_table.dynamo4.name },
        { name = "DYNAMO_TABLE5", value = "" },
        { name = "DYNAMO_TABLE6", value = aws_dynamodb_table.dynamo6.name },
        { name = "DYNAMO_TABLE7", value = aws_dynamodb_table.dynamo7.name },
        { name = "DYNAMO_TABLE8", value = aws_dynamodb_table.dynamo8.name }
      ]
      environmentFiles = [{
        type  = "s3",
        value = "arn:${var.partition}:s3:::${aws_s3_bucket.resources.bucket}/tenants/${var.tenant_id}/ServiceDiscovery.env"
      }]
    }
  ])

  tags = {
    Tenant = var.tenant_id
    Tier   = var.tier
  }
}

# ECS Service Ingestion
resource "aws_ecs_service" "ingestion" {
  name            = var.service_resource_name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.ingestion.arn
  launch_type     = "FARGATE"
  desired_count   = 0

  network_configuration {
    subnets         = [var.private_subnet_a, var.private_subnet_b]
    security_groups = [aws_security_group.ecs.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.nlb_tg.arn
    container_name   = "sb-${var.environment}-tenant-${var.tenant_short_id}-${var.service_resource_name}"
    container_port   = var.container_port
  }

  propagate_tags = "TASK_DEFINITION"
}

# ===== Merged from autoscaling.tf =====
resource "aws_appautoscaling_target" "ecs_service" {
  max_capacity       = var.max_task_count
  min_capacity       = var.min_task_count
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.ingestion.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "sb-${var.environment}-tenant-${split("-", var.tenant_id)[0]}-autoscaling-policy-cpu-${var.service_resource_name}${var.region}"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs_service.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_service.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_service.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 65
    scale_in_cooldown  = 120
    scale_out_cooldown = 60
  }
}

resource "aws_appautoscaling_policy" "mem" {
  name               = "sb-${var.environment}-tenant-${split("-", var.tenant_id)[0]}-autoscaling-policy-mem-${var.service_resource_name}${var.region}"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs_service.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_service.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_service.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    target_value       = 85
    scale_in_cooldown  = 120
    scale_out_cooldown = 60
  }
}

# ===== Merged from s3_kms.tf =====
resource "aws_kms_key" "tenant" {
  description         = "Primary KMS Key"
  enable_key_rotation = true
  multi_region        = true

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid: "Enable IAM User Permissions",
        Effect: "Allow",
        Principal: { AWS: "arn:${var.partition}:iam::${data.aws_caller_identity.current.account_id}:root" },
        Action: [
          "kms:GenerateRandom","kms:Describe*","kms:List*","kms:Get*","kms:Create*","kms:Put*","kms:Enable*","kms:TagResource","kms:UntagResource","kms:Update*","kms:Encrypt","kms:Decrypt","kms:ReEncrypt*","kms:GenerateDataKey*","kms:DeleteAlias","kms:Revoke*","kms:Disable*","kms:Delete*","kms:ScheduleKeyDeletion","kms:CancelKeyDeletion","kms:ReplicateKey"
        ],
        Resource: "*"
      },
      {
        Sid: "Allow VPC Flow Logs to use the key as well",
        Effect: "Allow",
        Principal: { Service: "delivery.logs.amazonaws.com" },
        Action: ["kms:GenerateDataKey*"],
        Resource: "*"
      },
      {
        Sid: "Allow Logs to use the key as well",
        Effect: "Allow",
        Principal: { Service: "logs.${var.region}.amazonaws.com" },
        Action: ["kms:Encrypt*","kms:Decrypt*","kms:ReEncrypt*","kms:GenerateDataKey*","kms:Describe*"],
        Resource: "*"
      },
      {
        Sid: "Allow sms-voice to use the key as well",
        Effect: "Allow",
        Principal: { Service: "sms-voice.amazonaws.com" },
        Action: ["kms:Decrypt*","kms:GenerateDataKey*"],
        Resource: "*"
      },
      {
        Effect: "Allow",
        Principal: { AWS: "*" },
        Action: ["kms:Encrypt","kms:Decrypt","kms:ReEncrypt*","kms:GenerateDataKey*","kms:CreateGrant","kms:ListGrants","kms:DescribeKey"],
        Resource: "*",
        Condition: { StringEquals: { "kms:CallerAccount": data.aws_caller_identity.current.account_id, "kms:ViaService": "rds.${var.region}.amazonaws.com" } }
      },
      {
        Effect: "Allow",
        Principal: { AWS: "*" },
        Action: ["kms:Encrypt","kms:Decrypt","kms:ReEncrypt*","kms:GenerateDataKey*","kms:CreateGrant","kms:ListGrants","kms:DescribeKey"],
        Resource: "*"
      }
    ]
  })
}

resource "aws_kms_alias" "tenant" {
  name          = "alias/kms/${var.tenant_short_id}"
  target_key_id = aws_kms_key.tenant.id
}

# Access Logs Bucket
resource "aws_s3_bucket" "access_logs" {
  bucket = "sb-${var.environment}-access-logs-${var.tenant_short_id}"
}

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid: "ELBAccessLogs",
        Effect: "Allow",
        Principal: { AWS: "arn:aws:iam::127311923021:root" },
        Action: "s3:PutObject",
        Resource: "arn:${var.partition}:s3:::${aws_s3_bucket.access_logs.bucket}/access-logs/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
      },
      {
        Sid: "AWSLogDeliveryWrite",
        Effect: "Allow",
        Principal: { Service: "delivery.logs.amazonaws.com" },
        Action: "s3:PutObject",
        Resource: "arn:${var.partition}:s3:::${aws_s3_bucket.access_logs.bucket}/access-logs/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition: { StringEquals: { "s3:x-amz-acl": "bucket-owner-full-control" } }
      },
      {
        Sid: "AWSLogDeliveryAclCheck",
        Effect: "Allow",
        Principal: { Service: "delivery.logs.amazonaws.com" },
        Action: "s3:GetBucketAcl",
        Resource: "arn:${var.partition}:s3:::${aws_s3_bucket.access_logs.bucket}"
      },
      {
        Sid: "DenyNonHttps",
        Effect: "Deny",
        Principal: "*",
        Action: "s3:*",
        Resource: [
          "arn:${var.partition}:s3:::${aws_s3_bucket.access_logs.bucket}/*",
          "arn:${var.partition}:s3:::${aws_s3_bucket.access_logs.bucket}"
        ],
        Condition: { Bool: { "aws:SecureTransport": false } }
      }
    ]
  })
}

# Tenant bucket with KMS
resource "aws_s3_bucket" "tenant" {
  bucket = "sb-uat12-artifacts-ez39knks2qtxtt"
}

resource "aws_s3_bucket_versioning" "tenant" {
  bucket = aws_s3_bucket.tenant.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_logging" "tenant" {
  bucket        = aws_s3_bucket.tenant.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = var.tenant_short_id
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tenant" {
  bucket = aws_s3_bucket.tenant.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_alias.tenant.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_policy" "tenant_https_only" {
  bucket = aws_s3_bucket.tenant.id
  policy = jsonencode({
    Statement = [{
      Effect: "Deny",
      Action: "s3:*",
      Principal: "*",
      Resource: [
        "arn:${var.partition}:s3:::${aws_s3_bucket.tenant.bucket}/*",
        "arn:${var.partition}:s3:::${aws_s3_bucket.tenant.bucket}"
      ],
      Condition: { Bool: { "aws:SecureTransport": false } }
    }]
  })
}

# CodePipeline and Resources buckets
resource "aws_s3_bucket" "codepipeline" {
  bucket = "sb-${var.environment}-pipelines-${var.tenant_short_id}"
}

resource "aws_s3_bucket" "resources" {
  bucket = "sb-${var.environment}-resources-${var.tenant_short_id}"
}

resource "aws_s3_bucket_policy" "codepipeline_https_only" {
  bucket = aws_s3_bucket.codepipeline.id
  policy = jsonencode({
    Version = "2008-10-17",
    Statement = [
      {
        Effect: "Deny",
        Principal: "*",
        Action: "s3:*",
        Resource: [
          "arn:${var.partition}:s3:::${aws_s3_bucket.codepipeline.bucket}/*",
          "arn:${var.partition}:s3:::${aws_s3_bucket.codepipeline.bucket}"
        ],
        Condition: { Bool: { "aws:SecureTransport": false } }
      },
      {
        Effect: "Allow",
        Principal: { AWS: "arn:aws:iam::829936139864:root" },
        Action: "*",
        Resource: [
          "arn:${var.partition}:s3:::${aws_s3_bucket.codepipeline.bucket}/*",
          "arn:${var.partition}:s3:::${aws_s3_bucket.codepipeline.bucket}"
        ]
      }
    ]
  })
}

resource "aws_cloudfront_origin_access_identity" "web_oai" {}

resource "aws_s3_bucket_policy" "resources_policy" {
  bucket = aws_s3_bucket.resources.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect: "Allow",
        Principal: { CanonicalUser: aws_cloudfront_origin_access_identity.web_oai.s3_canonical_user_id },
        Action: "s3:GetObject",
        Resource: "arn:${var.partition}:s3:::${aws_s3_bucket.resources.bucket}/*"
      },
      {
        Effect: "Deny",
        Principal: "*",
        Action: "s3:*",
        Resource: [
          "arn:${var.partition}:s3:::${aws_s3_bucket.resources.bucket}/*",
          "arn:${var.partition}:s3:::${aws_s3_bucket.resources.bucket}"
        ],
        Condition: { Bool: { "aws:SecureTransport": false } }
      }
    ]
  })
}

# ===== Merged from dynamodb.tf =====
locals {
  table_prefix   = "sb-${var.environment}-${var.tenant_short_id}"
  table_prefix_s = "sb-${var.environment}-${var.tenant_short_id}-${var.service_name}"
}

resource "aws_dynamodb_table" "dynamo1" {
  name         = "${local.table_prefix_s}-${var.table_name1}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute { name = "id" type = "S" }

  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  replica { region_name = var.region }

  point_in_time_recovery { enabled = true }

  tags = { Tenant = var.tenant_id }
}

resource "aws_dynamodb_table" "dynamo2" {
  name         = "${local.table_prefix_s}-${var.table_name2}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute { name = "id" type = "S" }
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  replica { region_name = var.region }
  point_in_time_recovery { enabled = true }
  tags = { Tenant = var.tenant_id }
}

resource "aws_dynamodb_table" "dynamo4" {
  name         = "${local.table_prefix}-common-${var.table_name4}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute { name = "id" type = "S" }
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  replica { region_name = var.region }
  point_in_time_recovery { enabled = true }
  tags = { Tenant = var.tenant_id }
}

resource "aws_dynamodb_table" "dynamo6" {
  name         = "${local.table_prefix}-common-${var.table_name6}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute { name = "id" type = "S" }
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  replica { region_name = var.region }
  point_in_time_recovery { enabled = true }
  tags = { Tenant = var.tenant_id }
}

resource "aws_dynamodb_table" "dynamo7" {
  name         = "${local.table_prefix}-common-${var.table_name7}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute { name = "id" type = "S" }
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  replica { region_name = var.region }
  point_in_time_recovery { enabled = true }
  tags = { Tenant = var.tenant_id }
}

resource "aws_dynamodb_table" "dynamo8" {
  name         = "${local.table_prefix}-common-${var.table_name8}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute { name = "id" type = "S" }
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  replica { region_name = var.region }
  point_in_time_recovery { enabled = true }
  tags = { Tenant = var.tenant_id }
}

resource "aws_dynamodb_table" "semaphore" {
  name         = "sb-${var.environment}-${var.tenant_short_id}-cc-locktable"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockName"
  attribute { name = "LockName" type = "S" }
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  replica { region_name = var.region }
  point_in_time_recovery { enabled = true }
  tags = { Tenant = var.tenant_id }
}

# ===== Merged from servicediscovery.tf =====
resource "aws_service_discovery_private_dns_namespace" "ns" {
  name = "sb-${var.environment}-local-${var.tenant_short_id}"
  vpc  = var.vpc_id
}

resource "aws_service_discovery_service" "svc" {
  name = var.service_resource_name

  dns_config {
    routing_policy = "MULTIVALUE"
    dns_records {
      type = "A"
      ttl  = 60
    }
    dns_records {
      type = "SRV"
      ttl  = 60
    }
  }

  health_check_custom_config { failure_threshold = 1 }
  namespace_id = aws_service_discovery_private_dns_namespace.ns.id
}

# ===== Cognito resources =====
resource "aws_cognito_user_pool" "idp" {
  name = "sb-${var.environment}-${var.tenant_short_id}-users"

  mfa_configuration = "OPTIONAL"
  software_token_mfa_configuration { enabled = true }

  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_numbers   = true
    require_symbols   = false
    require_uppercase = true
    temporary_password_validity_days = 7
  }

  admin_create_user_config {
    allow_admin_create_user_only = true
    invite_message_template {
      email_subject = "Xtrakto password"
      email_message = <<EOM
<b>Welcome to Xtrakto!</b> <br>
<br>
You can login to your Xtrakto at our default site
<br>
Your username is:  <b>{username}</b>
<br>
Your temporary password is:  <b>{####}</b>
<br>
EOM
    }
  }
}

resource "aws_cognito_resource_server" "idp" {
  identifier = "saas-platform/${var.environment}"
  name       = "sb-${var.environment}-${var.tenant_short_id}-api"
  user_pool_id = aws_cognito_user_pool.idp.id
  scope {
    scope_name        = "read"
    scope_description = "Read Public API Access"
  }
  scope {
    scope_name        = "write"
    scope_description = "Write Public API Access"
  }
  scope {
    scope_name        = "private"
    scope_description = "Read/Write Private API Access"
  }
}

resource "aws_cognito_user_pool_client" "admin_web" {
  name         = "sb-${var.environment}-${var.tenant_short_id}-webapp-client"
  user_pool_id = aws_cognito_user_pool.idp.id

  supported_identity_providers = ["COGNITO"]
  explicit_auth_flows = [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH"
  ]
  generate_secret = false

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows  = ["code"]
  allowed_oauth_scopes = ["openid","email","profile"]

  callback_urls = compact([var.web_url, "http://localhost:3000", "http://localhost:4200"])
  logout_urls   = compact([var.web_url, "http://localhost:3000", "http://localhost:4200"])
}

resource "aws_cognito_user_pool_client" "api_private" {
  name         = "sb-${var.environment}-${var.tenant_short_id}-private-api-client"
  user_pool_id = aws_cognito_user_pool.idp.id

  supported_identity_providers = ["COGNITO"]
  generate_secret              = true
  access_token_validity        = 5
  token_validity_units { access_token = "minutes" }
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows  = ["client_credentials"]
  allowed_oauth_scopes = [
    aws_cognito_resource_server.idp.scope_identifiers["read"],
    aws_cognito_resource_server.idp.scope_identifiers["write"]
  ]
}

resource "aws_cognito_user_pool_client" "private_api" {
  name         = "sb-${var.environment}-${var.tenant_short_id}-private-api-client2"
  user_pool_id = aws_cognito_user_pool.idp.id

  supported_identity_providers = ["COGNITO"]
  generate_secret              = true
  access_token_validity        = 5
  token_validity_units { access_token = "minutes" }
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows  = ["client_credentials"]
  allowed_oauth_scopes = [
    aws_cognito_resource_server.idp.scope_identifiers["read"],
    aws_cognito_resource_server.idp.scope_identifiers["write"],
    aws_cognito_resource_server.idp.scope_identifiers["private"]
  ]
}

resource "aws_cognito_user_pool_domain" "idp" {
  domain       = "sb-${var.environment}-${var.tenant_short_id}-userpool-domain"
  user_pool_id = aws_cognito_user_pool.idp.id
}

resource "aws_cognito_user" "admin" {
  user_pool_id = aws_cognito_user_pool.idp.id
  username     = var.admin_username
  attributes = {
    email          = var.admin_email_address
    email_verified = "true"
  }
  desired_delivery_mediums = ["EMAIL"]
}

resource "aws_cognito_user_group" "admin" { name = var.admin_groupname, user_pool_id = aws_cognito_user_pool.idp.id, description = "Tenant admin group" }
resource "aws_cognito_user_group" "builder" { name = var.builder_groupname, user_pool_id = aws_cognito_user_pool.idp.id, description = "Tenant builder group" }
resource "aws_cognito_user_group" "validator" { name = var.validator_groupname, user_pool_id = aws_cognito_user_pool.idp.id, description = "Tenant validator group" }
resource "aws_cognito_user_group" "manager" { name = var.manager_groupname, user_pool_id = aws_cognito_user_pool.idp.id, description = "Tenant manager group" }

# ===== ECS Module service (task + service) =====
resource "aws_ecs_task_definition" "module" {
  family                   = "sb-${var.environment}-tenant-${var.tenant_short_id}-${var.service_resource_name_module}"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "2048"
  memory                   = "4096"
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_exec.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "sb-${var.environment}-tenant-${var.tenant_short_id}-${var.service_resource_name_module}"
      image     = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.region}.${var.url_suffix}/${var.container_repository_module}:${var.image_tag}"
      cpu       = 2048
      memory    = 4096
      portMappings = [{ containerPort = var.container_port }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.ecs.name
          awslogs-region        = var.region
          awslogs-stream-prefix = "ecs-module"
        }
      }
      environment = [
        { name = "AWS_REGION", value = var.region },
        { name = "SAAS_PLATFORM_ENV", value = var.environment },
        { name = "TENANT_ID", value = var.tenant_id },
        { name = "SAAS_PLATFORM_RESOURCES_BUCKET", value = aws_s3_bucket.resources.bucket },
        { name = "SAAS_PLATFORM_EVENT_BUS", value = var.event_bus_name },
        { name = "METRICS_STREAM", value = var.metrics_stream },
        { name = "FILESYSTEM_MONITORING", value = "false" },
        { name = "DYNAMO_TABLE1", value = aws_dynamodb_table.dynamo1.name },
        { name = "DYNAMO_TABLE2", value = aws_dynamodb_table.dynamo2.name },
        { name = "DYNAMO_TABLE3", value = "" },
        { name = "DYNAMO_TABLE4", value = aws_dynamodb_table.dynamo4.name },
        { name = "DYNAMO_TABLE5", value = "" },
        { name = "DYNAMO_TABLE6", value = aws_dynamodb_table.dynamo6.name },
        { name = "DYNAMO_TABLE7", value = aws_dynamodb_table.dynamo7.name },
        { name = "DYNAMO_TABLE8", value = aws_dynamodb_table.dynamo8.name }
      ]
      environmentFiles = [{
        type  = "s3",
        value = "arn:${var.partition}:s3:::${aws_s3_bucket.resources.bucket}/tenants/${var.tenant_id}/ServiceDiscovery.env"
      }]
    }
  ])

  tags = {
    Tenant = var.tenant_id
    Tier   = var.tier
  }
}

resource "aws_ecs_service" "module" {
  name            = var.service_resource_name_module
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.module.arn
  launch_type     = "FARGATE"
  desired_count   = 0

  network_configuration {
    subnets         = [var.private_subnet_a, var.private_subnet_b]
    security_groups = [aws_security_group.ecs.id]
  }

  propagate_tags = "TASK_DEFINITION"
}

# ===== Onboarding Concurrency Lambda role and log =====
resource "aws_iam_role" "concurrency_exec" {
  name = "sb-${var.environment}-${var.tenant_short_id}-concur-exec-role-medicalidp-${var.region}"
  path = "/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "concurrency_policy" {
  name = "sb-${var.environment}-${var.tenant_short_id}-concur-policy-medicalidp-${var.region}"
  role = aws_iam_role.concurrency_exec.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      { Effect = "Allow", Action = ["logs:PutLogEvents"], Resource = ["arn:${var.partition}:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:*:log-stream:*"] },
      { Effect = "Allow", Action = ["logs:CreateLogStream","logs:DescribeLogStreams"], Resource = ["arn:${var.partition}:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:*"] },
      { Effect = "Allow", Action = ["ec2:DescribeNetworkInterfaces","ec2:CreateNetworkInterface","ec2:DeleteNetworkInterface","ec2:DescribeInstances","ec2:AttachNetworkInterface"], Resource = ["*"] },
      { Effect = "Allow", Action = ["dynamodb:UpdateItem"], Resource = ["arn:aws:dynamodb:${var.region}:${data.aws_caller_identity.current.account_id}:table/*"] }
    ]
  })
}

resource "aws_cloudwatch_log_group" "onboarding_concurrency" {
  name              = "/aws/lambda/sb-${var.environment}-StatusHandler-${var.tenant_short_id}"
  retention_in_days = 30
}

resource "aws_lambda_function" "onboarding_stack" {
  function_name = "sb-${var.environment}-${var.tenant_short_id}-StatusHandler"
  role          = aws_iam_role.concurrency_exec.arn
  runtime       = "python3.9"
  timeout       = 600
  memory_size   = 512
  handler       = "lambda_function.lambda_handler"
  s3_bucket     = var.concurrency_bucket
  s3_key        = "${var.lambda_source_folder}/onboarding-concurrency-handler-lambda.zip"

  environment { variables = { JOB_EXECUTION_STATUS_TABLE = "sb-${var.environment}-${var.tenant_short_id}-ingestion-jobs" } }

  vpc_config {
    security_group_ids = [aws_security_group.lambda.id]
    subnet_ids         = [var.private_subnet_a, var.private_subnet_b]
  }

  depends_on = [aws_cloudwatch_log_group.onboarding_concurrency]
  tags = { PlatformService = "OnboardingConcurrency" }
}

# ===== State Machines logs =====
resource "aws_cloudwatch_log_group" "state_machines" {
  name              = "/aws/vendedlogs/states/sb-${var.environment}-${var.tenant_short_id}-cc-StateMachineLogs"
  retention_in_days = 30
}

# ===== IAM Role for State Machines =====
resource "aws_iam_role" "application_sfn" {
  name = "sb-${var.environment}-${var.tenant_short_id}-app-concur-role-${var.region}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = ["states.amazonaws.com","events.amazonaws.com"] },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "application_sfn" {
  name = "sb-${var.environment}-${var.tenant_short_id}-app-policy"
  role = aws_iam_role.application_sfn.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      { Effect = "Allow", Action = ["events:PutTargets","events:PutRule","events:DescribeRule","states:StartExecution","xray:PutTraceSegments","xray:PutTelemetryRecords","xray:GetSamplingRules","xray:GetSamplingTargets","logs:CreateLogDelivery","logs:GetLogDelivery","logs:UpdateLogDelivery","logs:DeleteLogDelivery","logs:ListLogDeliveries","logs:PutResourcePolicy","logs:DescribeResourcePolicies","logs:DescribeLogGroups","cloudwatch:PutMetricData"], Resource = ["*"] },
      { Effect = "Allow", Action = [
        "dynamodb:PutItem","dynamodb:GetItem","dynamodb:Query","dynamodb:UpdateItem","dynamodb:DeleteItem","dynamodb:Scan","dynamodb:BatchGetItem","dynamodb:BatchWriteItem","dynamodb:ConditionCheckItem","dynamodb:PartiQL*","dynamodb:DescribeTable","dynamodb:UpdateTable"
      ], Resource = ["arn:aws:dynamodb:${var.region}:${data.aws_caller_identity.current.account_id}:table/*"] },
      { Effect = "Allow", Action = ["lambda:InvokeFunction"], Resource = [aws_lambda_function.onboarding_stack.arn] },
      { Effect = "Allow", Action = ["events:PutRule","events:PutTargets","events:DescribeRule","events:DeleteRule","events:RemoveTargets"], Resource = ["*"] }
    ]
  })
}

# ===== Step Functions Definitions =====
resource "aws_sfn_state_machine" "semaphore" {
  name     = "sb-${var.environment}-${var.tenant_short_id}-cc-ConcurrencyControlledStateMachine"
  role_arn = aws_iam_role.application_sfn.arn
  logging_configuration {
    include_execution_data = true
    level                  = "ALL"
    log_destination        = "${aws_cloudwatch_log_group.state_machines.arn}:*"
  }
  tracing_configuration { enabled = true }
  definition = jsonencode({
    Comment = "Control concurrency through DynamoDB",
    StartAt = "Acquire Lock",
    States = {
      "Acquire Lock" = {
        Type = "Task",
        Resource = "arn:aws:states:::dynamodb:updateItem",
        Parameters = {
          TableName = aws_dynamodb_table.semaphore.name,
          Key = { LockName = { S = var.parameter_lock_name } },
          ConditionExpression = "LockCount < :limit",
          UpdateExpression    = "SET LockCount = LockCount + :increase",
          ExpressionAttributeValues = {
            ":increase" = { N = "1" },
            ":limit"    = { N = var.concurrent_access_limit }
          },
          ReturnValues = "NONE"
        },
        Retry = [
          { ErrorEquals = ["DynamoDB.AmazonDynamoDBException"], IntervalSeconds = 2, MaxAttempts = 50, BackoffRate = 1 },
          { ErrorEquals = ["DynamoDB.ConditionalCheckFailedException"], IntervalSeconds = 60, MaxAttempts = 50, BackoffRate = 1.01 }
        ],
        Catch = [{ ErrorEquals = ["States.ALL"], Next = "Failed to Acquire Lock", ResultPath = "$.ErrorInfo" }],
        Next = "SFN Concurrency Manager",
        ResultPath = null
      },
      "Failed to Acquire Lock" = { Type = "Fail", ErrorPath = "$.ErrorInfo.Error", Cause = "ACQUIRE_LOCK_FAILURE" },
      "SFN Concurrency Manager" = {
        Type = "Map",
        MaxConcurrency = 1,
        ItemsPath = "$.MapList",
        OutputPath = "$",
        ResultPath = "$.StateResponse.SFNConcurrencyManager",
        Catch = [{ ErrorEquals = ["States.ALL"], Next = "Failed at Concurrency Manager", ResultPath = "$.ErrorInfo" }],
        ItemProcessor = {
          ProcessorConfig = { Mode = "INLINE" },
          StartAt = "Invoke Resource",
          States = {
            "Invoke Resource" = {
              Type = "Task",
              Resource = "arn:aws:states:::states:startExecution.sync:2",
              Parameters = { "Input.$" = "$.Input", "Name.$" = "$.Input.FileId", "StateMachineArn.$" = "$.ResourceArn" },
              ResultSelector = { "ExecutionArn.$" = "$.ExecutionArn", "Output.$" = "$.Output" },
              End = true,
              InputPath = "$",
              OutputPath = "$",
              ResultPath = "$"
            }
          }
        },
        Next = "Update Job Status"
      },
      "Failed at Concurrency Manager" = { Type = "Fail", ErrorPath = "$.ErrorInfo.Error", Cause = "CONCURRENCY_MANAGER_FAILURE" },
      "Update Job Status" = {
        Type = "Task",
        Resource = aws_lambda_function.onboarding_stack.arn,
        InputPath = "$",
        OutputPath = "$",
        ResultPath = "$.StateResponse.ExecutionStatus",
        Retry = [
          { ErrorEquals = ["Lambda.AWSLambdaException"], IntervalSeconds = 20, MaxAttempts = 5, BackoffRate = 1.5 },
          { ErrorEquals = ["States.ALL"], IntervalSeconds = 5, MaxAttempts = 30, BackoffRate = 1.125 }
        ],
        Catch = [{ ErrorEquals = ["States.ALL"], Next = "Failed to Update Job Status", ResultPath = "$.ErrorInfo" }],
        Next = "Release Lock"
      },
      "Failed to Update Job Status" = { Type = "Fail", ErrorPath = "$.ErrorInfo.Error", Cause = "UPDATE_JOB_STATUS_FAILURE" },
      "Release Lock" = {
        Type = "Task",
        Resource = "arn:aws:states:::dynamodb:updateItem",
        Parameters = {
          TableName = aws_dynamodb_table.semaphore.name,
          Key = { LockName = { S = var.parameter_lock_name } },
          UpdateExpression = "SET LockCount = LockCount - :decrease",
          ExpressionAttributeValues = { ":decrease" = { N = "1" } },
          ReturnValues = "NONE"
        },
        Retry = [
          { ErrorEquals = ["DynamoDB.ConditionalCheckFailedException"], MaxAttempts = 0 },
          { ErrorEquals = ["DynamoDB.AmazonDynamoDBException"], IntervalSeconds = 5, MaxAttempts = 10, BackoffRate = 1 }
        ],
        Catch = [{ ErrorEquals = ["States.ALL"], Next = "Failed to Release Lock", ResultPath = "$.ErrorInfo" }],
        End = true,
        ResultPath = null
      },
      "Failed to Release Lock" = { Type = "Fail", ErrorPath = "$.ErrorInfo.Error", Cause = "RELEASE_LOCK_FAILURE" }
    }
  })
}

resource "aws_sfn_state_machine" "semaphore_cleanup" {
  name     = "sb-${var.environment}-${var.tenant_short_id}-cc-CleanFromIncomplete"
  role_arn = aws_iam_role.application_sfn.arn
  logging_configuration {
    include_execution_data = true
    level                  = "ALL"
    log_destination        = "${aws_cloudwatch_log_group.state_machines.arn}:*"
  }
  tracing_configuration { enabled = true }
  definition = jsonencode({
    Comment = "Clean up orphaned locks",
    StartAt = "Check Cause to Update Job Status",
    States = {
      "Check Cause to Update Job Status" = {
        Type = "Choice",
        Choices = [{ Or = [
          { Variable = "$.detail.cause", StringEquals = "ACQUIRE_LOCK_FAILURE" },
          { Variable = "$.detail.cause", StringEquals = "CONCURRENCY_MANAGER_FAILURE" },
          { Variable = "$.detail.cause", StringEquals = "UPDATE_JOB_STATUS_FAILURE" }
        ], Next = "Update Job Status" }],
        Default = "Release Lock"
      },
      "Update Job Status" = {
        Type = "Task",
        Resource = "arn:aws:states:::dynamodb:updateItem",
        Parameters = {
          TableName = "sb-${var.environment}-${var.tenant_short_id}-ingestion-jobs",
          Key       = { id = { "S.$" = "$.detail.name" } },
          UpdateExpression = "set exitCode=:exitCode, stopDate=:enteredTime",
          ExpressionAttributeValues = { ":exitCode" = { N = "1" }, ":enteredTime" = { "S.$" = "$$.State.EnteredTime" } },
          ReturnValues = "NONE"
        },
        Retry = [{ ErrorEquals = ["DynamoDB.AmazonDynamoDBException"], IntervalSeconds = 5, MaxAttempts = 10, BackoffRate = 1 }],
        Next = "Check Cause to Release Lock"
      },
      "Check Cause to Release Lock" = {
        Type = "Choice",
        Choices = [{ Or = [
          { Variable = "$.detail.cause", StringEquals = "CONCURRENCY_MANAGER_FAILURE" },
          { Variable = "$.detail.cause", StringEquals = "UPDATE_JOB_STATUS_FAILURE" }
        ], Next = "Release Lock" }],
        Default = "Lock Not Acquired"
      },
      "Release Lock" = {
        Type = "Task",
        Resource = "arn:aws:states:::dynamodb:updateItem",
        Parameters = {
          TableName = aws_dynamodb_table.semaphore.name,
          Key = { LockName = { S = var.parameter_lock_name } },
          ExpressionAttributeNames  = { "#LockCount" = "LockCount" },
          ExpressionAttributeValues = { ":decrease" = { N = "1" } },
          UpdateExpression = "SET #LockCount = #LockCount - :decrease",
          ReturnValues     = "NONE"
        },
        Retry = [{ ErrorEquals = ["DynamoDB.AmazonDynamoDBException"], IntervalSeconds = 5, MaxAttempts = 10, BackoffRate = 1 }],
        End = true
      },
      "Lock Not Acquired" = { Type = "Pass", End = true }
    }
  })
}

# EventBridge rule to trigger cleanup
resource "aws_cloudwatch_event_rule" "cleanup" {
  name  = "sb-${var.environment}-${var.tenant_short_id}-cleanup-rule"
  event_pattern = jsonencode({
    source = ["aws.states"],
    detail = {
      stateMachineArn = [aws_sfn_state_machine.semaphore.arn],
      status = ["FAILED","TIMED_OUT","ABORTED"]
    }
  })
}

resource "aws_cloudwatch_event_target" "cleanup_target" {
  rule      = aws_cloudwatch_event_rule.cleanup.name
  target_id = "Invoke-StateMachineSempaphoreCleanup"
  arn       = aws_sfn_state_machine.semaphore_cleanup.arn
}

# ===== CodeBuild Role =====
resource "aws_iam_role" "service_build" {
  name = "sb-${var.environment}-medical-idp-service-build-role"
  path = "/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{ Effect = "Allow", Principal = { Service = "codebuild.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "service_build" {
  name = "sb-${var.environment}-medical-idp-service-build-policy"
  role = aws_iam_role.service_build.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      { Effect = "Allow", Action = ["logs:PutLogEvents"], Resource = ["arn:${var.partition}:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:*:log-stream:*"] },
      { Effect = "Allow", Action = ["logs:CreateLogGroup","logs:CreateLogStream","logs:DescribeLogStreams"], Resource = ["arn:${var.partition}:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:*"] },
      { Effect = "Allow", Action = ["s3:DeleteObject","s3:PutObject","s3:PutObjectAcl","s3:GetObject","s3:GetObjectVersion","s3:ListBucket","s3:ListAllMyBuckets"], Resource = ["*"] },
      { Effect = "Allow", Action = ["codebuild:BatchGetBuilds","codebuild:StartBuild","codebuild:BatchGetBuildBatches","codebuild:StartBuildBatch","lambda:InvokeFunction","iam:PassRole","lambda:ListFunctions","ssm:GetParameters","ssm:GetParameter","cloudfront:CreateInvalidation"], Resource = ["*"] },
      { Effect = "Allow", Action = ["kms:Decrypt","kms:ReEncrypt*","kms:GenerateDataKey*","kms:Encrypt","kms:DescribeKey","kms:CreateGrant","kms:ListGrants","kms:RevokeGrant","ecr:GetAuthorizationToken","ecr:BatchCheckLayerAvailability","ecr:CompleteLayerUpload","ecr:UploadLayerPart","ecr:InitiateLayerUpload","ecr:PutImage","ecr:DescribeImages"], Resource = ["*"] }
    ]
  })
}

# ===== CodePipeline Role =====
resource "aws_iam_role" "codepipeline" {
  name = "sb-${var.environment}-medical-idp-service-pipeline-role"
  path = "/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{ Effect = "Allow", Principal = { Service = "codepipeline.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "codepipeline" {
  name = "inlinepolicy"
  role = aws_iam_role.codepipeline.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      { Sid = "CloudWatchLogsPolicy", Effect = "Allow", Action = ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"], Resource = ["*"] },
      { Sid = "S3GetObjectPolicy", Effect = "Allow", Action = ["s3:GetObject","s3:GetObjectVersion"], Resource = ["*"] },
      { Sid = "S3PutObjectPolicy", Effect = "Allow", Action = ["s3:PutObject"], Resource = ["*"] },
      { Sid = "S3BucketIdentity", Effect = "Allow", Action = ["s3:GetBucketAcl","s3:GetBucketLocation"], Resource = ["*"] },
      { Sid = "CodeBuildPolicy", Effect = "Allow", Action = ["codebuild:BatchGetBuilds","codebuild:StartBuild","codestar-connections:UseConnection","iam:PassRole"], Resource = ["*"] }
    ]
  })
}

# ===== CodeBuild Projects =====
resource "aws_codebuild_project" "service_ingestion" {
  name         = "sb-${var.environment}-medical-idp-Build-Ingestion"
  service_role = aws_iam_role.service_build.arn
  timeout      = 10
  source { type = "CODECOMMIT", location = "https://git-codecommit.${var.region}.amazonaws.com/v1/repos/${var.service_code_repo_ingestion}" }
  source_version = "refs/heads/${var.api_service_code_branch}"
  artifacts { type = "NO_ARTIFACTS" }
  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type         = "LINUX_CONTAINER"
    privileged_mode = true
    environment_variable = [
      { name = "ENVIRONMENT", value = var.environment },
      { name = "IMAGE_TAG",  value = var.image_tag },
      { name = "NODE_OPTIONS", value = "--max_old_space_size=4096" },
      { name = "AWS_DEFAULT_REGION", value = var.region },
      { name = "AWS_ACCOUNT_ID", value = data.aws_caller_identity.current.account_id },
      { name = "SSM_PARAMETER_STORE", value = var.ssm_parameter_ingestion }
    ]
  }
}

resource "aws_codebuild_project" "service_module" {
  name         = "sb-${var.environment}-medical-idp-Build-module"
  service_role = aws_iam_role.service_build.arn
  timeout      = 10
  source { type = "CODECOMMIT", location = "https://git-codecommit.${var.region}.amazonaws.com/v1/repos/${var.service_code_repo_module}" }
  source_version = "refs/heads/${var.api_service_code_branch}"
  artifacts { type = "NO_ARTIFACTS" }
  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type         = "LINUX_CONTAINER"
    privileged_mode = true
    environment_variable = [
      { name = "ENVIRONMENT", value = var.environment },
      { name = "IMAGE_TAG",  value = var.image_tag },
      { name = "NODE_OPTIONS", value = "--max_old_space_size=4096" },
      { name = "AWS_DEFAULT_REGION", value = var.region },
      { name = "AWS_ACCOUNT_ID", value = data.aws_caller_identity.current.account_id },
      { name = "SSM_PARAMETER_STORE", value = var.ssm_parameter_module }
    ]
  }
}

resource "aws_codebuild_project" "service_ui" {
  name         = "sb-${var.environment}-medical-idp-Build-UI"
  service_role = aws_iam_role.service_build.arn
  timeout      = 10
  source { type = "CODECOMMIT", location = "https://git-codecommit.${var.region}.amazonaws.com/v1/repos/${var.service_code_repo_ui}" }
  source_version = "refs/heads/${var.ui_service_code_branch}"
  artifacts { type = "NO_ARTIFACTS" }
  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type         = "LINUX_CONTAINER"
    privileged_mode = true
    environment_variable = [
      { name = "WEBSITE_BUCKET", value = aws_s3_bucket.resources.bucket },
      { name = "SaaSPlatformBucket", value = aws_s3_bucket.tenant.bucket },
      { name = "ENVIRONMENT", value = var.environment },
      { name = "TENANT_ID", value = var.tenant_id },
      { name = "REACT_APP_AWS_REGION", value = var.region },
      { name = "REACT_APP_AWS_ACCOUNT", value = data.aws_caller_identity.current.account_id },
      { name = "REACT_APP_CLIENT_ID", value = aws_cognito_user_pool_client.admin_web.id },
      { name = "REACT_APP_SCOPE", value = "openid profile email" },
      { name = "REACT_APP_ISSUER", value = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.idp.id}" },
      { name = "REACT_APP_IDP_DOMAIN", value = "https://${aws_cognito_user_pool_domain.idp.domain}.auth.${var.region}.amazoncognito.com" },
      { name = "REACT_APP_IDP", value = "COGNITO" },
      { name = "NODE_OPTIONS", value = "--max_old_space_size=4096" }
    ]
  }
}

# ===== Pipelines using CodeStarSourceConnection (GitHub Enterprise) =====
resource "aws_codepipeline" "pipeline_ingestion" {
  name     = "sb-${var.environment}-medical-idp-Pipeline-Ingestion"
  role_arn = aws_iam_role.codepipeline.arn
  artifact_store { location = aws_s3_bucket.codepipeline.id, type = "S3" }
  stage {
    name = "Source"
    action {
      name             = "GitHubEnterpriseSource"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeStarSourceConnection"
      version          = "1"
      output_artifacts = ["SourceOutput"]
      configuration = {
        ConnectionArn    = var.github_enterprise_connection_arn
        FullRepositoryId  = var.api_repository_name
        BranchName        = var.api_service_code_branch
      }
    }
  }
  stage {
    name = "Build"
    action {
      name            = "Build"
      category        = "Build"
      owner           = "AWS"
      provider        = "CodeBuild"
      version         = "1"
      input_artifacts = ["SourceOutput"]
      configuration = { ProjectName = aws_codebuild_project.service_ingestion.name }
    }
  }
}

resource "aws_codepipeline" "pipeline_module" {
  name     = "sb-${var.environment}-medical-idp-Pipeline-module"
  role_arn = aws_iam_role.codepipeline.arn
  artifact_store { location = aws_s3_bucket.codepipeline.id, type = "S3" }
  stage {
    name = "Source"
    action {
      name             = "GitHubEnterpriseSource"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeStarSourceConnection"
      version          = "1"
      output_artifacts = ["SourceOutput"]
      configuration = {
        ConnectionArn    = var.github_enterprise_connection_arn
        FullRepositoryId  = var.api_repository_name
        BranchName        = var.api_service_code_branch
      }
    }
  }
  stage {
    name = "Build"
    action {
      name            = "Build"
      category        = "Build"
      owner           = "AWS"
      provider        = "CodeBuild"
      version         = "1"
      input_artifacts = ["SourceOutput"]
      configuration = { ProjectName = aws_codebuild_project.service_module.name }
    }
  }
}

resource "aws_codepipeline" "pipeline_ui" {
  name     = "sb-${var.environment}-medical-idp-Pipeline-UI"
  role_arn = aws_iam_role.codepipeline.arn
  artifact_store { location = aws_s3_bucket.codepipeline.id, type = "S3" }
  stage {
    name = "Source"
    action {
      name             = "GitHubEnterpriseSource"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeStarSourceConnection"
      version          = "1"
      output_artifacts = ["SourceOutput"]
      configuration = {
        ConnectionArn    = var.github_enterprise_connection_arn
        FullRepositoryId  = var.ui_repository_name
        BranchName        = var.ui_service_code_branch
      }
    }
  }
  stage {
    name = "Build"
    action {
      name            = "Build"
      category        = "Build"
      owner           = "AWS"
      provider        = "CodeBuild"
      version         = "1"
      input_artifacts = ["SourceOutput"]
      configuration = { ProjectName = aws_codebuild_project.service_ui.name }
    }
  }
}
