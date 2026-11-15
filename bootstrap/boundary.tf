# The deploy role's permissions boundary: the ceiling over everything the role
# is ever given, its own policy (permissions.tf) or anything attached later.
# It allows what server/ needs and no more: server/'s state, EC2 and VPC
# in the chosen region, KMS keys, SNS topics, DLM policies, alarms and budgets
# carrying the server stack's tag, the snapshot bucket by name (DESIGN.md),
# the two server roles and the instance profile bootstrap made, and SSM
# public parameters. Its denies hold whatever is
# attached (bootstrap/POLICY.md lists every action, resource and condition):
# the state key and bucket are never managed; no EC2 resource is changed
# without the tag; a launch takes the owner's image only, into a tagged subnet
# and security group, with no other kind of resource; no snapshot is shared;
# no other key or DLM policy is given the tag; no role or instance profile is
# created, deleted or retrusted and no boundary changed; no managed policy but
# the CloudWatch agent's is attached; an inline policy goes on the instance
# role alone; and a role is passed only to EC2 and DLM. A managed policy holds
# at most 6,144 characters, so related statements share one and none carries a
# Sid; the comment above each says what it is.

resource "aws_iam_policy" "boundary" {
  name        = local.deploy_boundary_name
  path        = "/"
  description = "The permissions boundary of fermix-server-deploy: the most server/ may ever need."
  policy      = data.aws_iam_policy_document.boundary.json
}

locals {
  # Named by its ARN, which a plan already knows, so the tests hold the
  # boundary's attachment without an apply (tests/bootstrap.tftest.hcl).
  deploy_boundary_name = "fermix-server-deploy-boundary"
  deploy_boundary_arn  = "arn:${local.partition}:iam::${local.account_id}:policy/${local.deploy_boundary_name}"

  ec2_any = "arn:${local.partition}:ec2:*:*"
  # Images and snapshots, the account-less ARNs a launch reads.
  ec2_accountless = "arn:${local.partition}:ec2:*::*"
  ec2_tag_keys    = [local.stack_tag_key, "Name"]
  topics          = "${local.arn.sns}:${local.name_prefix}-*"
  alarms          = "${local.arn.cloudwatch}:alarm:${local.name_prefix}-*"
  budgets         = "arn:${local.partition}:budgets::${local.account_id}:budget/${local.name_prefix}-*"

  # What a launch or a create may only go into when it carries the tag
  # (boundary.tf and permissions.tf deny the same).
  into_tagged_actions = ["ec2:RunInstances", "ec2:CreateSubnet", "ec2:CreateRouteTable", "ec2:CreateSecurityGroup"]
  into_tagged_resources = [
    "${local.ec2_any}:vpc/vpc-*",
    "${local.ec2_any}:subnet/subnet-*",
    "${local.ec2_any}:security-group/sg-*",
    "${local.ec2_any}:network-interface/eni-*",
  ]
}

data "aws_iam_policy_document" "boundary" {
  # ---------------------------------------------------------------- state
  # server/'s state object and its lock (terraform.tfstate*), through the state
  # key.
  statement {
    actions = [
      "s3:ListBucket",
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
    ]
    resources = [
      local.state_bucket_arn,
      "${local.state_bucket_arn}/${local.state_key}*",
      aws_kms_key.state.arn,
    ]
  }

  statement {
    effect      = "Deny"
    not_actions = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
    resources   = [aws_kms_key.state.arn]
  }

  statement {
    effect      = "Deny"
    not_actions = ["s3:ListBucket", "s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources   = [local.state_bucket_arn, "${local.state_bucket_arn}/*"]
  }

  # bootstrap's own state and its lock, in the same bucket: never.
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["${local.state_bucket_arn}/${local.bootstrap_state_key}*"]
  }

  # ---------------------------------------------------------------- EC2 and VPC
  # EC2 on resources in the chosen region; nothing that authorizes on no
  # resource at all (an account's EC2 settings), but the reads.
  statement {
    actions   = ["ec2:*"]
    resources = ["arn:${local.partition}:ec2:${var.region}:*"]

    condition {
      test     = "ForAllValues:StringEquals"
      variable = "aws:TagKeys"
      values   = local.ec2_tag_keys
    }
  }

  statement {
    actions   = ["ec2:Describe*"]
    resources = ["*"]
  }

  # No change to an EC2 resource that does not carry the tag. Reads, and the
  # creates, whose new resource has no tag yet, are left to the role's policy,
  # which holds every create to the tag in its request.
  statement {
    effect = "Deny"
    not_actions = [
      "ec2:Describe*",
      "ec2:RunInstances",
      "ec2:CreateVpc",
      "ec2:CreateSubnet",
      "ec2:CreateRouteTable",
      "ec2:CreateSecurityGroup",
      "ec2:CreateInternetGateway",
      "ec2:CreateTags",
    ]
    resources = ["${local.ec2_any}:*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:ResourceTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }
  }

  # A launch here is made of these seven kinds of resource and nothing else:
  # no key pair, launch template, placement group, capacity reservation,
  # elastic GPU or inference accelerator, license, Spot request or secondary
  # interface.
  statement {
    effect  = "Deny"
    actions = ["ec2:RunInstances"]
    not_resources = [
      "${local.ec2_any}:instance/*",
      "${local.ec2_any}:volume/*",
      "${local.ec2_any}:network-interface/*",
      "${local.ec2_any}:subnet/*",
      "${local.ec2_any}:security-group/*",
      local.ec2_accountless,
    ]
  }

  statement {
    effect    = "Deny"
    actions   = ["ec2:RunInstances"]
    resources = [local.ec2_accountless]

    condition {
      test     = "StringNotEquals"
      variable = "aws:ResourceAccount"
      values   = [var.ami_owner_id]
    }
  }

  # A launch, or a subnet, route table or security group, only into what
  # already carries the tag. Existing resources' ARNs name their ids
  # (vpc/vpc-..., network-interface/eni-...); the one a request creates is
  # vpc/*, network-interface/* and so on, which the patterns do not match.
  statement {
    effect    = "Deny"
    actions   = local.into_tagged_actions
    resources = local.into_tagged_resources

    condition {
      test     = "StringNotEquals"
      variable = "aws:ResourceTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }
  }

  # A tag only on create, or on what carries the tag already.
  statement {
    effect    = "Deny"
    actions   = ["ec2:CreateTags"]
    resources = ["${local.ec2_any}:*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:ResourceTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }

    condition {
      test     = "Null"
      variable = "ec2:CreateAction"
      values   = ["true"]
    }
  }

  statement {
    effect    = "Deny"
    actions   = ["ec2:ModifySnapshotAttribute"]
    resources = ["*"]
  }

  # ---------------------------------------------------------------- KMS, SNS, DLM
  # Created only with the tag, in the chosen region (a key needs kms:TagResource
  # on no particular key to be tagged at create), and managed only while they
  # carry it.
  statement {
    actions   = ["kms:CreateKey", "kms:TagResource", "dlm:CreateLifecyclePolicy", "dlm:TagResource"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }

    condition {
      test     = "ForAllValues:StringEquals"
      variable = "aws:TagKeys"
      values   = [local.stack_tag_key]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.region]
    }
  }

  # Under their own names: the topic, the alarm and the budget.
  statement {
    actions = [
      "sns:CreateTopic",
      "sns:TagResource",
      "cloudwatch:PutMetricAlarm",
      "cloudwatch:TagResource",
      "budgets:ModifyBudget",
      "budgets:TagResource",
    ]
    resources = [local.topics, local.alarms, local.budgets]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }

    condition {
      test     = "ForAllValues:StringEquals"
      variable = "aws:TagKeys"
      values   = [local.stack_tag_key]
    }
  }

  statement {
    actions = ["kms:*", "sns:*", "dlm:*", "cloudwatch:*", "budgets:*"]
    resources = [
      "${local.arn.kms}:key/*",
      local.topics,
      "${local.arn.dlm}:policy/*",
      local.alarms,
      local.budgets,
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }

    condition {
      test     = "ForAllValues:StringEquals"
      variable = "aws:TagKeys"
      values   = [local.stack_tag_key]
    }
  }

  # No other key, DLM policy or topic is given the tag, or has it taken away.
  # DLM's own ids begin "policy-".
  statement {
    effect = "Deny"
    actions = [
      "kms:TagResource",
      "kms:UntagResource",
      "dlm:TagResource",
      "dlm:UntagResource",
      "sns:TagResource",
      "sns:UntagResource",
    ]
    resources = [
      "arn:${local.partition}:kms:*:*:key/*",
      "arn:${local.partition}:dlm:*:*:policy/policy-*",
      "arn:${local.partition}:sns:*:*:*",
    ]

    condition {
      test     = "StringNotEquals"
      variable = "aws:ResourceTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }
  }

  # A subscription has no tags; its ARN is its topic's and an id.
  statement {
    actions   = ["sns:GetSubscriptionAttributes", "sns:SetSubscriptionAttributes", "sns:Unsubscribe"]
    resources = [local.topics]
  }

  # The server key's alias alone (also authorized on the key it names, which is
  # held to the tag), and listing aliases.
  statement {
    actions   = ["kms:CreateAlias", "kms:DeleteAlias", "kms:UpdateAlias"]
    resources = ["${local.arn.kms}:${local.server_key}"]
  }

  statement {
    actions   = ["kms:ListAliases"]
    resources = ["*"]
  }

  # ---------------------------------------------------------------- S3
  # The one bucket's configuration (bucket-level actions on its ARN never reach
  # an object) and deleting objects to empty it on destroy.
  statement {
    actions = [
      "s3:CreateBucket",
      "s3:DeleteBucket*",
      "s3:ListBucket*",
      "s3:GetBucket*",
      "s3:PutBucket*",
      "s3:Get*Configuration",
      "s3:Put*Configuration",
      "s3:DeleteObject*",
    ]
    resources = [
      "arn:${local.partition}:s3:::${local.snapshot_bucket}",
      "arn:${local.partition}:s3:::${local.snapshot_bucket}/*",
    ]
  }

  # ---------------------------------------------------------------- IAM
  # Only the two server roles and the instance profile bootstrap made.
  statement {
    actions   = ["iam:Get*", "iam:List*", "iam:PassRole", "iam:*RolePolicy"]
    resources = [local.instance_role_arn, local.dlm_role_arn, local.instance_profile_arn]
  }

  statement {
    effect = "Deny"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:Update*Role*",
      "iam:CreateInstanceProfile",
      "iam:DeleteInstanceProfile",
      "iam:*RoleToInstanceProfile",
      "iam:*RoleFromInstanceProfile",
      "iam:*RolePermissionsBoundary",
    ]
    resources = ["*"]
  }

  statement {
    effect    = "Deny"
    actions   = ["iam:AttachRolePolicy", "iam:DetachRolePolicy"]
    resources = ["*"]

    condition {
      test     = "ArnNotEquals"
      variable = "iam:PolicyARN"
      values   = [local.cloudwatch_agent_policy]
    }
  }

  statement {
    effect        = "Deny"
    actions       = ["iam:PutRolePolicy", "iam:DeleteRolePolicy"]
    not_resources = [local.instance_role_arn]
  }

  statement {
    effect    = "Deny"
    actions   = ["iam:PassRole"]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "iam:PassedToService"
      values   = ["ec2.amazonaws.com", "dlm.amazonaws.com"]
    }
  }

  # ---------------------------------------------------------------- SSM
  statement {
    actions   = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = ["arn:${local.partition}:ssm:${var.region}::parameter/aws/service/*"]
  }
}
