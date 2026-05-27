variable "cluster_name" {
  description = "Name of the Consul cluster"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type for Consul servers"
  type        = string
}

variable "ami_id" {
  description = "AMI ID for Consul nodes"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for the Consul cluster"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for the Consul ASG"
  type        = list(string)
}

variable "desired_capacity" {
  description = "Desired number of Consul server instances"
  type        = number
}

variable "consul_enabled" {
  description = "Enable Consul deployment"
  type        = bool
}