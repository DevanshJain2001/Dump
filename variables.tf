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
