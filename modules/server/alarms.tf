# The status-check alarm, always; with alert_emails, an encrypted SNS topic it
# notifies and a monthly budget. A budget nobody hears from does nothing, so
# without an address there is none.

resource "aws_sns_topic" "alerts" {
  count = local.alerts ? 1 : 0

  name              = "${local.name}-alerts"
  kms_master_key_id = aws_kms_key.server.arn

  tags = local.tags
}

resource "aws_sns_topic_policy" "alerts" {
  count = local.alerts ? 1 : 0

  arn = aws_sns_topic.alerts[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ThisAccountsAlarmsPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts[0].arn
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:${local.partition}:cloudwatch:${local.region}:${local.account_id}:alarm:${local.name}-*" }
      }
    }]
  })
}

# Terraform creates an email subscription as pending; the owner confirms it
# from the email AWS sends.
resource "aws_sns_topic_subscription" "alerts" {
  for_each = toset(var.alert_emails)

  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = each.value
}

# The operating system stops answering EC2's instance check. (A failed system
# check is AWS hardware, which automatic recovery handles.)
resource "aws_cloudwatch_metric_alarm" "instance_status" {
  alarm_name          = "${local.name}-instance-status"
  alarm_description   = "fermix-server: the instance status check fails, so the server's operating system does not answer. RUNBOOK.md, \"The status-check alarm\"."
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_Instance"
  dimensions          = { InstanceId = aws_instance.server.id }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = aws_sns_topic.alerts[*].arn

  tags = local.tags
}

resource "aws_budgets_budget" "monthly" {
  count = local.alerts ? 1 : 0

  name         = "${local.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # Counted before credits: with credits subtracted, a month the credits pay
  # for would count nothing.
  cost_types {
    include_credit = false
  }

  dynamic "notification" {
    for_each = [50, 80, 100]

    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = var.alert_emails
    }
  }

  tags = local.tags
}
