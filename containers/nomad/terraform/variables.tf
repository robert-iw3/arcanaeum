variable "aws_region" {
  description = "Primary AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "secondary_region" {
  description = "Secondary AWS region for multi-region deployment"
  type        = string
  default     = "us-west-2"
}

variable "cluster_name" {
  description = "Name of the Nomad cluster"
  type        = string
}

variable "nomad_ami_id" {
  description = "AMI ID for Nomad servers and clients"
  type        = string
}

variable "consul_ami_id" {
  description = "AMI ID for Consul servers"
  type        = string
}

variable "vault_ami_id" {
  description = "AMI ID for Vault servers"
  type        = string
}

variable "ssl_certificate_arn" {
  description = "ARN of the SSL certificate for ALB"
  type        = string
}

variable "num_nomad_servers" {
  description = "Number of Nomad server instances"
  type        = number
  default     = 3
}

variable "num_nomad_clients" {
  description = "Number of Nomad client instances"
  type        = number
  default     = 3
}

variable "num_consul_servers" {
  description = "Number of Consul server instances"
  type        = number
  default     = 3
}

variable "num_vault_servers" {
  description = "Number of Vault server instances"
  type        = number
  default     = 3
}

variable "server_instance_type" {
  description = "Instance type for servers"
  type        = string
  default     = "t3.medium"
}

variable "client_instance_type" {
  description = "Instance type for clients"
  type        = string
  default     = "t3.large"
}

variable "grafana_admin_password" {
  description = "Initial Grafana admin password"
  type        = string
  sensitive   = true
}

variable "ssh_key_name" {
  description = "Name of the SSH key pair"
  type        = string
}

variable "nomad_version" {
  description = "Nomad version to install"
  type        = string
  default     = "1.9.2"
}