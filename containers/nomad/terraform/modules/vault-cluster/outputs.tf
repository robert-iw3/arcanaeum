output "security_group_id" {
  description = "Security group ID for Vault cluster"
  value       = var.vault_enabled ? aws_security_group.vault_sg[0].id : ""
}

output "vault_instance_ips" {
  description = "Private IPs of Vault instances"
  value       = var.vault_enabled ? data.aws_instances.vault_instances[0].private_ips : []
}

output "vault_token" {
  description = "Vault token for Nomad integration"
  value       = var.vault_enabled ? var.vault_token : ""
  sensitive   = true
}

data "aws_instances" "vault_instances" {
  count = var.vault_enabled ? 1 : 0
  instance_tags = {
    Name = "${var.cluster_name}-vault"
  }
  depends_on = [aws_autoscaling_group.vault_asg]
}