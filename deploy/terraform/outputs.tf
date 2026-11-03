output "instance_id" {
  value = aws_instance.this.id
}

output "connect" {
  description = "Open a root shell on the instance (needs the Session Manager plugin for the AWS CLI). Starting the session with a command skips the account-wide Session Manager shell profile."
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.this.id} --document-name AWS-StartInteractiveCommand --parameters '{\"command\":[\"sudo -i\"]}'"
}

output "token_parameters" {
  description = "Replace the placeholder values of these before scanning (and add source-token if the vulnscan repo is private)."
  value       = [for p in aws_ssm_parameter.token : p.name]
}
