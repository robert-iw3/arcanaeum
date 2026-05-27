resource "aws_security_group" "nomad_sg" {
  name        = "${var.cluster_name}-nomad-sg"
  description = "Security group for Nomad cluster"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 4646
    to_port     = 4646
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Nomad HTTP API/UI"
  }
  ingress {
    from_port   = 4647
    to_port     = 4647
    protocol    = "tcp"
    self        = true
    description = "Nomad RPC"
  }
  ingress {
    from_port   = 4648
    to_port     = 4648
    protocol    = "tcp"
    self        = true
    description = "Nomad Serf"
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Podman CNI networking"
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Podman CNI networking"
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "${var.cluster_name}-nomad-sg"
  }
}

resource "aws_iam_role" "nomad_role" {
  name = "${var.cluster_name}-nomad-role"
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

resource "aws_iam_role_policy" "nomad_policy" {
  name = "${var.cluster_name}-nomad-policy"
  role = aws_iam_role.nomad_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags",
          "autoscaling:DescribeAutoScalingGroups"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "nomad_profile" {
  name = "${var.cluster_name}-nomad-profile"
  role = aws_iam_role.nomad_role.name
}

resource "aws_launch_template" "nomad_lt" {
  name = "${var.cluster_name}-nomad-lt"
  image_id = var.ami_id
  instance_type = var.client_enabled ? var.instance_type : var.instance_type
  iam_instance_profile {
    name = aws_iam_instance_profile.nomad_profile.name
  }
  vpc_security_group_ids = [aws_security_group.nomad_sg.id]
  key_name = var.ssh_key_name
  user_data = base64encode(templatefile("${path.module}/user-data-${var.client_enabled ? "client" : "server"}.sh", {
    cluster_name     = var.cluster_name
    nomad_version     = var.nomad_version
    nomad_acl_token  = var.nomad_acl_token
    nomad_gossip_key = var.nomad_gossip_key
    podman_enabled   = var.podman_enabled
    client_enabled   = var.client_enabled
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
      Name = "${var.cluster_name}-${var.client_enabled ? "client" : "server"}"
      ConsulAutoJoin = "auto-join"
      NomadType = var.client_enabled ? "client" : "server"
    }
  }
}

resource "aws_autoscaling_group" "nomad_asg" {
  name                = "${var.cluster_name}-${var.client_enabled ? "client" : "server"}-asg"
  desired_capacity    = var.desired_capacity
  max_size            = var.desired_capacity + 2
  min_size            = var.desired_capacity
  vpc_zone_identifier = var.subnet_ids
  launch_template {
    id      = aws_launch_template.nomad_lt.id
    version = "$Latest"
  }
  health_check_type         = "EC2"
  health_check_grace_period = 300
  tag {
    key                 = "Name"
    value               = "${var.cluster_name}-${var.client_enabled ? "client" : "server"}"
    propagate_at_launch = true
  }
  tag {
    key                 = "ConsulAutoJoin"
    value               = "auto-join"
    propagate_at_launch = true
  }
  tag {
    key                 = "NomadType"
    value               = var.client_enabled ? "client" : "server"
    propagate_at_launch = true
  }
}

data "aws_instances" "nomad_instances" {
  instance_tags = {
    Name = "${var.cluster_name}-${var.client_enabled ? "client" : "server"}"
  }
  depends_on = [aws_autoscaling_group.nomad_asg]
}