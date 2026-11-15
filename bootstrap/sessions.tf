# require_session_mfa (README.md, "Sessions with MFA"): admin_role_arn runs no
# code on the server through Systems Manager unless the credentials making
# the call carry MFA: no session, command, automation, association or
# maintenance-window task (bootstrap/POLICY.md lists each action and why).
# IAM checks aws:MultiFactorAuthPresent on each of those calls, against the
# caller's own policies, so the deny is written on admin_role_arn
# itself: an inline policy on its role, or on the IAM user it names. It holds
# the owner's credentials to MFA; it cannot hold anyone else's (README.md,
# "Who can open a session").

locals {
  admin_kind = split("/", split(":", var.admin_role_arn)[5])[0] # role or user
  admin_name = reverse(split("/", var.admin_role_arn))[0]
}

resource "aws_iam_role_policy" "session_mfa" {
  count = var.require_session_mfa && local.admin_kind == "role" ? 1 : 0

  name   = "fermix-server-sessions-need-mfa"
  role   = local.admin_name
  policy = data.aws_iam_policy_document.session_mfa.json
}

resource "aws_iam_user_policy" "session_mfa" {
  count = var.require_session_mfa && local.admin_kind == "user" ? 1 : 0

  name   = "fermix-server-sessions-need-mfa"
  user   = local.admin_name
  policy = data.aws_iam_policy_document.session_mfa.json
}

data "aws_iam_policy_document" "session_mfa" {
  # The actions whose request names the instance, held to the server's tag.
  # Run Command checks each node, those it reaches through Targets too.
  statement {
    sid       = "ServerSessionsAndCommandsNeedMfa"
    effect    = "Deny"
    actions   = ["ssm:StartSession", "ssm:SendCommand"]
    resources = ["arn:${local.partition}:ec2:${var.region}:${local.account_id}:instance/*"]

    condition {
      test     = "StringEquals"
      variable = "ssm:resourceTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }

    # IfExists: credentials that cannot carry MFA at all, as no federated
    # sign-in's do, are refused too.
    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }
  }

  # The actions that reach the server without naming it: a resumed session
  # names the session, an automation its steps, an association or a
  # maintenance window its targets, which may be the server's tag. bootstrap
  # does not know the instance id, so these hold in the whole region.
  statement {
    sid    = "CodeOnTheRegionsInstancesNeedsMfa"
    effect = "Deny"
    actions = [
      "ssm:ResumeSession",
      "ssm:StartAutomationExecution",
      "ssm:StartChangeRequestExecution",
      "ssm:CreateAssociation",
      "ssm:CreateAssociationBatch",
      "ssm:UpdateAssociation",
      "ssm:StartAssociationsOnce",
      "ssm:RegisterTaskWithMaintenanceWindow",
      "ssm:UpdateMaintenanceWindowTask",
      "ssm:RegisterTargetWithMaintenanceWindow",
      "ssm:UpdateMaintenanceWindowTarget",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.region]
    }

    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }
  }
}
