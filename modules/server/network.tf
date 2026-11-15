# The server's own VPC: one public subnet, an internet gateway and a route
# table, and no NAT gateway. The public IPv4 address carries the server's
# outbound traffic only; nothing comes in (security_group.tf).

data "aws_ec2_instance_type_offerings" "zones" {
  location_type = "availability-zone"

  filter {
    name   = "instance-type"
    values = [var.instance_type]
  }
}

locals {
  availability_zone = coalesce(var.availability_zone, try(sort(data.aws_ec2_instance_type_offerings.zones.locations)[0], null))
}

resource "aws_vpc" "server" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.tags, { Name = local.name })
}

resource "aws_internet_gateway" "server" {
  vpc_id = aws_vpc.server.id

  tags = merge(local.tags, { Name = local.name })
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.server.id
  availability_zone       = local.availability_zone
  cidr_block              = cidrsubnet(var.vpc_cidr, 24 - tonumber(split("/", var.vpc_cidr)[1]), 0)
  map_public_ip_on_launch = false

  tags = merge(local.tags, { Name = "${local.name}-public" })

  lifecycle {
    # Read once: a zone that starts or stops offering the type later must not
    # move the subnet, which would replace the instance and the home on it.
    ignore_changes = [availability_zone]

    precondition {
      condition     = local.availability_zone != null && startswith(local.availability_zone, local.region)
      error_message = "No zone in ${local.region} offers ${var.instance_type}, or availability_zone is not in ${local.region}."
    }
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.server.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.server.id
  }

  tags = merge(local.tags, { Name = "${local.name}-public" })
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}
