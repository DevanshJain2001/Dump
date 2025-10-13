variable "region" {
  type        = string
  description = "AWS region"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Environment (test, uat, prod, etc.)"
  default     = "uat12"
}

variable "tenant_id" {
  type        = string
  description = "The GUID for the tenant"
  default     = "55b51eaa-96f2-44b4-a943-494bc0dbd15a"
}

variable "tier" {
  type        = string
  description = "The tier this tenant is onboarding into"
  default     = "default"
}

variable "cidr_prefix" {
  type        = string
  description = "CIDR used for ECS ingress allowance"
  default     = "10.95.64.0/23"
}

variable "egress_public_vpc_id" {
  type        = string
  description = "Public VPC ID for ALB"
}

variable "egress_public_subnet_id1" {
  type        = string
  description = "Public Subnet A for ALB"
}

variable "egress_public_subnet_id2" {
  type        = string
  description = "Public Subnet B for ALB"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID for ECS and Lambda SG"
}

variable "private_subnet_a" {
  type        = string
  description = "Private Subnet A for Lambda/NLB"
}

variable "private_subnet_b" {
  type        = string
  description = "Private Subnet B for Lambda/NLB"
}

variable "ssl_certificate_arn" {
  type        = string
  description = "ACM Certificate ARN"
  default     = "arn:aws:acm:us-east-1:812894578144:certificate/74d577af-9ea6-44c9-a491-4c18b03c7f9e"
}

variable "create_nlb" {
  type        = bool
  description = "Whether to create a new NLB (true) or use existing (false)"
  default     = true
}

variable "existing_nlb_arn" {
  type        = string
  description = "Existing NLB ARN when create_nlb is false"
  default     = null
}

variable "tenant_short_id" { type = string, description = "Short tenant id", default = "55b51eaa" }
variable "service_resource_name" { type = string, description = "Service resource name", default = "ingestion" }
variable "service_name" { type = string, description = "Service name", default = "ingestion" }
variable "metrics_stream" { type = string, description = "Firehose metrics stream name", default = null }
variable "event_bus_name" { type = string, description = "EventBridge bus name", default = "sb-codecommitaccount-event-bus-medical-idp" }
variable "container_port" { type = number, description = "Container port", default = 8080 }
variable "min_task_count" { type = number, description = "Min desired tasks", default = 1 }
variable "max_task_count" { type = number, description = "Max desired tasks", default = 2 }
variable "container_repository" { type = string, description = "ECR repo name", default = "sb-uat12-core-191g9bof3kcsf-ingestion-8dudyzgzzfnl" }
variable "image_tag" { type = string, description = "ECR image tag", default = "55b51eaa" }
variable "table_name1" { type = string, default = "documents" }
variable "table_name2" { type = string, default = "jobs" }
variable "table_name4" { type = string, default = "projects" }
variable "table_name6" { type = string, default = "document-monitor" }
variable "table_name7" { type = string, default = "user-monitor" }
variable "table_name8" { type = string, default = "file-status" }
variable "url_suffix" { type = string, description = "AWS URL suffix", default = "amazonaws.com" }
variable "partition" { type = string, description = "AWS partition", default = "aws" }
variable "system_identity_provider" { type = string, default = "COGNITO", description = "Configured System IDP" }
variable "admin_username" { type = string, default = "admin", description = "Initial admin username" }
variable "tenant_cost_code" { type = string, default = "test002", description = "Cost code for the tenant" }
variable "service_resource_name_module" { type = string, default = "module", description = "Module service resource name" }
variable "container_repository_tag" { type = string, default = "55b51eaa", description = "Container image tag" }
variable "admin_groupname" { type = string, default = "TenantAdminGroup", description = "Admin group name" }
variable "admin_email_address" { type = string, default = "manish.tiwari2@exlservice.com", description = "Admin email" }
variable "builder_groupname" { type = string, default = "TenantBuilderGroup", description = "Builder group name" }
variable "validator_groupname" { type = string, default = "TenantValidatorGroup", description = "Validator group name" }
variable "manager_groupname" { type = string, default = "TenantManagerGroup", description = "Manager group name" }
variable "parameter_lock_name" { type = string, default = "ConcurrencySemaphore", description = "Semaphore lock name" }
variable "concurrent_access_limit" { type = string, default = "5", description = "Max concurrent access limit" }
variable "code_commit_account_id" { type = string, default = "812894578144", description = "CodeCommit account id" }
variable "lambda_source_folder" { type = string, default = "lambdas", description = "Lambda source folder in S3" }
variable "concurrency_bucket" { type = string, default = "sb-dev18-resources-d37f71f4", description = "S3 bucket for concurrency Lambda code" }
variable "web_url" { type = string, default = "", description = "Custom Web URL for Cognito callbacks" }
variable "service_code_repo_ingestion" { type = string, default = "medical-idp-ingestion-service", description = "Service code repo for ingestion" }
variable "service_code_repo_module" { type = string, default = "medical-idp-module-service", description = "Service code repo for module" }
variable "service_code_repo_ui" { type = string, default = "medical-idp-ui", description = "Service code repo for UI" }
variable "ssm_parameter_ingestion" { type = string, default = "/saas-platform/uat12/app/ingestion/SERVICE_JSON", description = "SSM parameter for ingestion build" }
variable "ssm_parameter_module" { type = string, default = "/saas-platform/uat12/app/module/SERVICE_JSON", description = "SSM parameter for module build" }
variable "github_enterprise_connection_arn" { type = string, default = "arn:aws:codeconnections:us-east-1:812894578144:connection/b3cdba7a-072b-4966-b232-5858331b88dd", description = "CodeStar connection ARN" }
variable "api_repository_name" { type = string, default = "55b51eaa-ingestion-service", description = "GHE repo name for API" }
variable "ui_repository_name" { type = string, default = "medical-idp", description = "GHE repo name for UI" }
variable "api_service_code_branch" { type = string, default = "55b51eaa_EXlerateAI", description = "API branch" }
variable "ui_service_code_branch" { type = string, default = "55b51eaa/uat-EXlerateAIUI", description = "UI branch" }
variable "container_repository_module" { type = string, default = "sb-uat12-core-191g9bof3kcsf-module-ylvbgqo8w7wz", description = "Module ECR repo name" }
