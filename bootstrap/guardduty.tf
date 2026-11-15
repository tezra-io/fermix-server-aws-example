# enable_guardduty: a GuardDuty detector in the region, with Runtime
# Monitoring for EC2 and its agent managed by GuardDuty, which installs and
# updates it on every SSM-managed instance in the account and region, the
# server included, through an SSM association. An account has one detector
# per region, so it is bootstrap's, with the owner's sign-in, never the
# deploy role's (README.md, "GuardDuty").
#
# It does not fight a detector already there, the account's own or one an
# organization's GuardDuty administrator manages: GuardDuty refuses a second
# (CreateDetector: "a detector already exists"), so the apply stops before
# changing anything, and the owner leaves this off. The detector's other
# protection plans stay at GuardDuty's own defaults; only Runtime Monitoring
# is set here.

resource "aws_guardduty_detector" "this" {
  count = var.enable_guardduty ? 1 : 0

  enable = true
}

resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "EC2_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
}

# Whichever detector runs in the region, bootstrap's or another, its findings
# go to the security alert topic (alerts.tf); with none, nothing matches.
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${local.name_prefix}-guardduty"
  description = "fermix-server: a GuardDuty finding in this account and region."

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "alert-topic"
  arn       = aws_sns_topic.security_alerts.arn

  input_transformer {
    input_paths = {
      severity = "$.detail.severity"
      title    = "$.detail.title"
      type     = "$.detail.type"
      resource = "$.detail.resource.resourceType"
      id       = "$.detail.id"
      updated  = "$.detail.updatedAt"
      region   = "$.detail.region"
    }

    input_template = <<-EOT
      "fermix-server: a GuardDuty finding, severity <severity>: <title>"
      "Type: <type>, on a resource of type <resource>"
      "Finding: <id>, updated <updated>"
      "https://console.aws.amazon.com/guardduty/home?region=<region>#/findings?fId=<id>"
    EOT
  }
}
