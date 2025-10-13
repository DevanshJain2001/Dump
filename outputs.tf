output "ecs_cluster_id" {
  value       = aws_ecs_cluster.this.id
  description = "ECS Cluster ID"
}

output "alb_arn" {
  value       = aws_lb.app_alb.arn
  description = "Application Load Balancer ARN"
}

output "lambda_function_name" {
  value       = aws_lambda_function.nlb_function.function_name
  description = "Name of the Lambda function"
}
