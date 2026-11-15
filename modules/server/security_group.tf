# No inbound rule: the server is reached through Session Manager, which
# the SSM agent opens from the inside. All outbound traffic is allowed, with
# no allowlist. It carries HTTPS to fermix.ai, GitHub, Debian's mirrors,
# Tailscale, SSM and S3; UDP for iroh, to the relay's QUIC port 7842 and to
# direct paths at addresses no list can know; and Tailscale's UDP. The VPC's
# DNS resolver and Amazon Time Sync are not filtered by security groups.

resource "aws_security_group" "server" {
  name        = local.name
  description = "fermix-server: nothing in, everything out"
  vpc_id      = aws_vpc.server.id

  # Managed as an empty list, so a rule added by hand is removed again by the
  # next apply.
  ingress = []

  # All outbound; trivy's AWS-0104 is suppressed on this rule alone (DESIGN.md).
  #trivy:ignore:AWS-0104
  egress {
    description = "All outbound: HTTPS, UDP for iroh to the relay and to direct paths, Tailscale"
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = local.name })
}
