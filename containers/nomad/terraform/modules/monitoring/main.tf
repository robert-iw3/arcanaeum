resource "aws_instance" "monitoring" {
  ami           = var.monitoring_ami_id
  instance_type = var.instance_type
  subnet_id     = var.subnet_ids[0]
  key_name      = var.ssh_key_name
  vpc_security_group_ids = [aws_security_group.monitoring_sg.id]

  user_data = templatefile("${path.module}/user-data-monitoring.sh", {
    prometheus_config = base64encode(templatefile("${path.module}/prometheus.yml", {
      nomad_lb_address = var.nomad_lb_address,
      consul_ips       = var.consul_ips,
      vault_ips        = var.vault_ips
    })),
    grafana_admin_password = var.grafana_admin_password
  })

  tags = {
    Name = "${var.cluster_name}-monitoring"
  }
}

resource "aws_security_group" "monitoring_sg" {
  name_prefix = "${var.cluster_name}-monitoring-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Prometheus access"
  }

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Grafana access"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "grafana_lb" {
  name               = "${var.cluster_name}-grafana-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.monitoring_sg.id]
  subnets            = var.subnet_ids
}

resource "aws_lb_target_group" "grafana_tg" {
  name     = "${var.cluster_name}-grafana-tg"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    path                = "/api/health"
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "grafana_listener" {
  load_balancer_arn = aws_lb.grafana_lb.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.ssl_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.grafana_tg.arn
  }
}

resource "aws_lb_target_group_attachment" "grafana_attachment" {
  target_group_arn = aws_lb_target_group.grafana_tg.arn
  target_id        = aws_instance.monitoring.id
  port             = 3000
}

data "aws_instance" "monitoring_instance" {
  instance_id = aws_instance.monitoring.id
}

output "monitoring_instance_ip" {
  description = "Private IP of the monitoring instance"
  value       = data.aws_instance.monitoring_instance.private_ip
}

output "grafana_lb_address" {
  description = "DNS name of the Grafana load balancer"
  value       = aws_lb.grafana_lb.dns_name
}