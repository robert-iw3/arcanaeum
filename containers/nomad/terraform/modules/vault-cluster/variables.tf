variable "cluster_name" {
  description = "Name of the Vault cluster"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type for Vault servers"
  type        = string
}

variable "ami_id" {
  description = "AMI ID for Vault nodes"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for the Vault cluster"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for the Vault ASG"
  type        = list(string)
}

variable "desired_capacity" {
  description = "Desired number of Vault server instances"
  type        = number
}

variable "vault_enabled" {
  description = "Enable Vault deployment"
  type        = bool
}

variable "vault_token" {
  description = "Vault token for Nomad integration"
  type        = string
  sensitive   = true
}