resource "aws_security_group" "vault_sg" {
  name        = "${var.cluster_name}-vault-sg"
  description = "Security group for Vault cluster"
  vpc_id      = var.vpc_id
  count       = var.vault_enabled ? 1 : 0

  ingress {
    from_port   = 8200
    to_port     = 8200
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Vault HTTP API/UI"
  }
  ingress {
    from_port   = 8201
    to_port     = 8201
    protocol    = "tcp"
    self        = true
    description = "Vault Cluster"
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "${var.cluster_name}-vault-sg"
  }
}

resource "aws_iam_role" "vault_role" {
  name = "${var.cluster_name}-vault-role"
  count = var.vault_enabled ? 1 : 0
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "vault_policy" {
  name = "${var.cluster_name}-vault-policy"
  role = aws_iam_role.vault_role[0].id
  count = var.vault_enabled ? 1 : 0
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "vault_profile" {
  name = "${var.cluster_name}-vault-profile"
  role = aws_iam_role.vault_role[0].name
  count = var.vault_enabled ? 1 : 0
}

resource "aws_launch_template" "vault_lt" {
  name = "${var.cluster_name}-vault-lt"
  count = var.vault_enabled ? 1 : 0
  image_id = var.ami_id
  instance_type = var.instance_type
  iam_instance_profile {
    name = aws_iam_instance_profile.vault_profile[0].name
  }
  vpc_security_group_ids = [aws_security_group.vault_sg[0].id]
  user_data = base64encode(templatefile("${path.module}/user-data-vault.sh", {
    cluster_name = var.cluster_name
    vault_token  = var.vault_token
  }))
  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size = 50
      volume_type = "gp3"
    }
  }
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.cluster_name}-vault"
      ConsulAutoJoin = "auto-join"
    }
  }
}

resource "aws_autoscaling_group" "vault_asg" {
  name                = "${var.cluster_name}-vault-asg"
  desired_capacity    = var.desired_capacity
  max_size            = var.desired_capacity + 1
  min_size            = var.desired_capacity
  vpc_zone_identifier = var.subnet_ids
  count               = var.vault_enabled ? 1 : 0
  launch_template {
    id      = aws_launch_template.vault_lt[0].id
    version = "$Latest"
  }
  health_check_type         = "EC2"
  health_check_grace_period = 300
}