output "instance_id" {
  value = aws_instance.this.id
}

output "connect" {
  description = "Open a shell on the instance (needs the Session Manager plugin for the AWS CLI)."
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.this.id}"
}

output "token_parameters" {
  description = "Create these as SecureString parameters before running vulnscan-build."
  value       = ["${var.ssm_prefix}/github-token", "${var.ssm_prefix}/source-token", "${var.ssm_prefix}/claude-token"]
}
