data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "aws_ec2_instance_type" "this" {
  instance_type = var.instance_type
}

# Availability zones that offer the chosen instance type.
data "aws_ec2_instance_type_offerings" "this" {
  location_type = "availability-zone"

  filter {
    name   = "instance-type"
    values = [var.instance_type]
  }
}

locals {
  arch = contains(data.aws_ec2_instance_type.this.supported_architectures, "arm64") ? "arm64" : "x86_64"
  az   = sort(data.aws_ec2_instance_type_offerings.this.locations)[0]
}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-${local.arch}"
}

# ---------------------------------------------------------------------------
# Network: vulnscan's own subnet and route table inside an existing, otherwise
# empty VPC, using that VPC's internet gateway. Nothing of the VPC's own is changed.
# Public subnet without a NAT gateway (cost); nothing is allowed in.
# ---------------------------------------------------------------------------

data "aws_vpc" "this" {
  id = var.vpc_id
}

data "aws_internet_gateway" "this" {
  filter {
    name   = "attachment.vpc-id"
    values = [var.vpc_id]
  }
}

resource "aws_subnet" "this" {
  vpc_id            = data.aws_vpc.this.id
  cidr_block        = var.subnet_cidr
  availability_zone = local.az

  tags = { Name = var.name }
}

resource "aws_route_table" "this" {
  vpc_id = data.aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = data.aws_internet_gateway.this.id
  }

  tags = { Name = var.name }
}

resource "aws_route_table_association" "this" {
  subnet_id      = aws_subnet.this.id
  route_table_id = aws_route_table.this.id
}

# No ingress rules at all: shell access is through SSM Session Manager.
resource "aws_security_group" "this" {
  name        = var.name
  description = "vulnscan: no inbound, HTTPS outbound only"
  vpc_id      = data.aws_vpc.this.id
}

resource "aws_vpc_security_group_egress_rule" "https" {
  security_group_id = aws_security_group.this.id
  description       = "GitHub, package registries, OSV, Semgrep, Claude, SSM"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# ---------------------------------------------------------------------------
# IAM: Session Manager plus read access to the vulnscan tokens, nothing else.
# Deliberately not AmazonSSMManagedInstanceCore: that policy allows
# ssm:GetParameter on every parameter in the account.
# ---------------------------------------------------------------------------

resource "aws_iam_role" "this" {
  name = var.name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "this" {
  name = var.name
  role = aws_iam_role.this.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SessionManager"
        Effect = "Allow"
        Action = [
          "ssm:UpdateInstanceInformation",
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel",
        ]
        Resource = "*"
      },
      {
        # SecureStrings encrypted with the default aws/ssm key need no extra KMS permission.
        Sid      = "ReadVulnscanTokens"
        Effect   = "Allow"
        Action   = "ssm:GetParameter"
        Resource = "arn:${data.aws_partition.current.partition}:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter${var.ssm_prefix}/*"
      },
    ]
  })
}

resource "aws_iam_instance_profile" "this" {
  name = var.name
  role = aws_iam_role.this.name
}

# Created with a placeholder; replace the values by hand (deploy/README.md).
# value_wo is write-only: neither the placeholder nor the real token is ever stored in
# Terraform state, and Terraform doesn't overwrite a value changed outside it.
resource "aws_ssm_parameter" "token" {
  for_each = toset(["github-token", "claude-token"])

  name             = "${var.ssm_prefix}/${each.key}"
  type             = "SecureString"
  value_wo         = "todo update me"
  value_wo_version = 1
}

# ---------------------------------------------------------------------------
# Instance and the reports volume.
# ---------------------------------------------------------------------------

# Separate from the root volume so reports survive the instance being replaced.
resource "aws_ebs_volume" "data" {
  availability_zone = local.az
  size              = var.data_volume_gb
  type              = "gp3"
  encrypted         = true

  tags = { Name = "${var.name}-data" }
}

resource "aws_instance" "this" {
  ami                         = data.aws_ssm_parameter.al2023.insecure_value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.this.id
  vpc_security_group_ids      = [aws_security_group.this.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.this.name

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    region         = var.region
    github_org     = var.github_org
    source_repo    = var.source_repo
    source_ref     = var.source_ref
    ssm_prefix     = var.ssm_prefix
    data_volume    = replace(aws_ebs_volume.data.id, "-", "")
    build_script   = file("${path.module}/../host/vulnscan-build")
    wrapper_script = file("${path.module}/../host/vulnscan")
  })

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1          # containers can't reach the instance role's credentials
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_gb
    encrypted   = true
  }

  # Throttle to baseline instead of paying for extra CPU (t-family only).
  credit_specification {
    cpu_credits = "standard"
  }

  tags = { Name = var.name }

  # user_data only runs on first boot. To apply a newer AMI or user_data, run
  # `terraform apply -replace=aws_instance.this`; the reports volume is kept.
  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

resource "aws_volume_attachment" "data" {
  device_name                    = "/dev/sdf"
  volume_id                      = aws_ebs_volume.data.id
  instance_id                    = aws_instance.this.id
  stop_instance_before_detaching = true
}
