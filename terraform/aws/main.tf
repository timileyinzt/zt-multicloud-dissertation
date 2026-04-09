# =============================================================================
# AWS Infrastructure — VPC Microsegmentation + GuardDuty + Least-Privilege IAM
#
# NIST SP 800-207:
#   T1 — Identity verified via OIDC federation (see modules/identity)
#   T2 — VPC security groups enforce network microsegmentation
#   T5 — GuardDuty + CloudTrail provide continuous monitoring
#   T6 — IAM roles scoped to minimum required permissions
#
# This file provisions the AWS-side infrastructure.
# Identity federation is handled in terraform/modules/identity/aws-oidc-trust.tf
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project   = "zt-dissertation"
      ManagedBy = "terraform"
      Author    = "W24065387"
    }
  }
}

# ── Variables ─────────────────────────────────────────────────────────────────
variable "aws_region" {
  default = "eu-west-2"  # London
}
variable "vpc_cidr" {
  default = "10.10.0.0/16"
}
variable "environment" {
  default = "research"
}

# ── VPC — Zero Trust Network Perimeter ────────────────────────────────────────
# NIST T2: Network is not trusted. VPC is a boundary, not a trust zone.
# Every workload must authenticate regardless of VPC membership.
resource "aws_vpc" "zt" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "zt-dissertation-vpc", NistTenet = "T2" }
}

# Private subnets — workloads never exposed directly to internet
resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.zt.id
  cidr_block        = "10.10.1.0/24"
  availability_zone = "${var.aws_region}a"
  map_public_ip_on_launch = false

  tags = { Name = "zt-private-a", Tier = "workload" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.zt.id
  cidr_block        = "10.10.2.0/24"
  availability_zone = "${var.aws_region}b"
  map_public_ip_on_launch = false

  tags = { Name = "zt-private-b", Tier = "workload" }
}

# Public subnet — only for NAT gateway (workloads use this for egress)
resource "aws_subnet" "public_a" {
  vpc_id            = aws_vpc.zt.id
  cidr_block        = "10.10.10.0/24"
  availability_zone = "${var.aws_region}a"
  map_public_ip_on_launch = false

  tags = { Name = "zt-public-a", Tier = "egress-only" }
}

resource "aws_internet_gateway" "zt" {
  vpc_id = aws_vpc.zt.id
  tags   = { Name = "zt-igw" }
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "zt-nat-eip" }
}

resource "aws_nat_gateway" "zt" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_a.id
  tags          = { Name = "zt-nat" }
  depends_on    = [aws_internet_gateway.zt]
}

# Route tables
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.zt.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.zt.id
  }
  tags = { Name = "zt-private-rt" }
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.zt.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.zt.id
  }
  tags = { Name = "zt-public-rt" }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

# ── Security Groups — Microsegmentation (NIST T2) ─────────────────────────────
# Design: default-deny at SG level mirrors Istio AuthorizationPolicy pattern.
# Each SG allows only specific source/destination pairs.

# Default: deny all inbound, allow all outbound (overridden per workload)
resource "aws_default_security_group" "deny_all" {
  vpc_id = aws_vpc.zt.id
  # No ingress rules = deny all inbound by default
  # No egress rules = deny all outbound by default
  tags = { Name = "zt-default-deny-all", NistTenet = "T2-T6" }
}

# Frontend security group — accepts HTTPS from internet only
resource "aws_security_group" "frontend" {
  name        = "zt-frontend-sg"
  description = "ZT: Frontend tier — HTTPS inbound only"
  vpc_id      = aws_vpc.zt.id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description     = "Allow to backend tier only"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.backend.id]
  }

  tags = { Name = "zt-frontend-sg", NistTenet = "T2" }
}

# Backend security group — accepts traffic from frontend SG only
# NIST T2 + T6: Source-based restriction, no broad CIDR blocks
resource "aws_security_group" "backend" {
  name        = "zt-backend-sg"
  description = "ZT: Backend tier — frontend SG inbound only"
  vpc_id      = aws_vpc.zt.id

  ingress {
    description     = "From frontend only — NIST T6 least-privilege"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.frontend.id]
  }

  egress {
    description = "HTTPS egress for AWS API calls"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "zt-backend-sg", NistTenet = "T2-T6" }
}

# ── GuardDuty — Continuous Threat Detection (NIST T5, T7) ────────────────────
resource "aws_guardduty_detector" "zt" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = { NistTenet = "T5-T7" }
}

# ── CloudTrail — Audit logging (NIST T5) ──────────────────────────────────────
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "zt-dissertation-cloudtrail-${var.environment}"
  force_destroy = true  # Research environment — clean teardown

  tags = { NistTenet = "T5" }
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::${aws_s3_bucket.cloudtrail_logs.bucket}"
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::${aws_s3_bucket.cloudtrail_logs.bucket}/AWSLogs/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "zt" {
  name                          = "zt-dissertation-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  # Log all data events on the dissertation S3 bucket
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::zt-dissertation-demo/"]
    }
  }

  tags = { NistTenet = "T5" }
  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

# ── S3 Demo Bucket — for federation test ──────────────────────────────────────
resource "aws_s3_bucket" "zt_demo" {
  bucket        = "zt-dissertation-demo"
  force_destroy = true
  tags          = { Name = "zt-demo-bucket", Purpose = "federation-test" }
}

resource "aws_s3_bucket_public_access_block" "zt_demo" {
  bucket                  = aws_s3_bucket.zt_demo.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── Outputs ───────────────────────────────────────────────────────────────────
output "vpc_id" {
  value = aws_vpc.zt.id
}
output "private_subnet_ids" {
  value = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}
output "guardduty_detector_id" {
  value = aws_guardduty_detector.zt.id
}
output "demo_bucket_name" {
  value = aws_s3_bucket.zt_demo.bucket
}
output "cloudtrail_arn" {
  value = aws_cloudtrail.zt.arn
}
