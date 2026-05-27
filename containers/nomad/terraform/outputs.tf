output "nomad_lb_address" {
  description = "DNS name of the Nomad load balancer"
  value       = aws_lb.nomad_lb.dns_name
}

output "nomad_acl_token" {
  description = "Nomad ACL bootstrap token"
  value       = random_uuid.nomad_acl_token.result
  sensitive   = true
}

output "nomad_gossip_key" {
  description = "Nomad gossip encryption key"
  value       = random_uuid.nomad_gossip_key.result
  sensitive   = true
}

output "vault_token" {
  description = "Vault token for Nomad integration"
  value       = random_uuid.vault_token.result
  sensitive   = true
}

output "nomad_server_ips" {
  description = "Private IPs of Nomad server nodes"
  value       = module.nomad_servers.instance_ips
}

output "nomad_client_ips" {
  description = "Private IPs of Nomad client nodes"
  value       = module.nomad_clients.instance_ips
}

output "consul_instance_ips" {
  description = "Private IPs of Consul instances"
  value       = module.consul_servers.consul_instance_ips
}

output "vault_instance_ips" {
  description = "Private IPs of Vault instances"
  value       = module.vault_servers.vault_instance_ips
}