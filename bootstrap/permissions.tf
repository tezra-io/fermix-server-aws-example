# The deploy role's own policy: exactly what server/ needs, every action
# named. It is an inline policy because it is longer than a managed policy may
# be; the role's permissions boundary (boundary.tf) is the ceiling over it and
# holds the denies, with denies.tf for those it has no room for.
#   - server/'s state object and lock, through the state key;
#   - EC2 and VPC in the chosen region, on the resources server/ creates:
#     created only carrying the server stack's tag, changed only while they
#     carry it;
#   - KMS keys created with the tag and managed only while they carry it;
#   - the snapshot bucket, by its exact name (DESIGN.md), each write named;
#   - the two server roles bootstrap made (server_roles.tf): read them, pass
#     each to its one service, attach the CloudWatch agent's policy to the
#     instance role and write the S3 backups' inline policy on it; never
#     create, delete or retrust a role;
#   - CloudWatch alarms and budgets named fermix-server-*, SNS topics carrying
#     the tag, DLM policies created with it and managed only while they carry
#     it, and reading SSM public parameters (the AMI id).

resource "aws_iam_role_policy" "deploy" {
  name   = "server"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}

locals {
  # arn:<partition>:<service>:<region>:<account>, the stem of the regional ARNs.
  arn = { for service in ["ec2", "kms", "sns", "dlm", "cloudwatch"] : service => "arn:${local.partition}:${service}:${var.region}:${local.account_id}" }

  state_bucket_arn = "arn:${local.partition}:s3:::${local.state_bucket}"

  # The tag keys server/ writes, and the only ones the role may write.
  tag_keys = [local.stack_tag_key, "Name"]

  # What creates a tagged EC2 resource; CreateTags is allowed with them alone.
  ec2_creates = ["RunInstances", "CreateVpc", "CreateSubnet", "CreateRouteTable", "CreateSecurityGroup", "CreateInternetGateway"]

  # The snapshot bucket's actions: what each resource in
  # modules/server/storage.tf calls through the pinned provider (6.67.0), by
  # IAM's name for it, which is not always the call's. The denies policy
  # (denies.tf) refuses every other action on the bucket and its objects.
  snapshot_bucket_actions = [
    # aws_s3_bucket: CreateBucket with a private ACL, which needs
    # s3:CreateBucket alone; tags at create need s3:TagResource, which nothing
    # allows, so the provider creates it untagged and tags it with
    # PutBucketTagging (and DeleteBucketTagging); HeadBucket; DeleteBucket.
    "s3:CreateBucket",
    "s3:DeleteBucket",
    "s3:ListBucket",
    "s3:PutBucketTagging",
    # force_destroy empties it: ListObjectVersions (and DeleteObjects below).
    "s3:ListBucketVersions",
    # Refresh reads every setting of the bucket.
    "s3:GetBucket*",
    "s3:Get*Configuration",
    # One write per resource; each resource's delete is its write's action.
    "s3:PutBucketOwnershipControls", # _ownership_controls
    "s3:PutBucketPublicAccessBlock", # _public_access_block
    "s3:PutBucketVersioning",        # _versioning
    "s3:PutEncryptionConfiguration", # _server_side_encryption_configuration
    "s3:PutLifecycleConfiguration",  # _lifecycle_configuration
    "s3:PutBucketPolicy",            # _policy
    "s3:DeleteBucketPolicy",
  ]

  # On its objects: deleting them to empty it on destroy, never a read or a
  # write.
  snapshot_object_actions = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
}

data "aws_iam_policy_document" "deploy" {
  # ---------------------------------------------------------------- state
  statement {
    sid       = "ListTheStateBucket"
    actions   = ["s3:ListBucket"]
    resources = [local.state_bucket_arn]
  }

  statement {
    sid       = "ReadAndWriteTheServerState"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${local.state_bucket_arn}/${local.state_key}", "${local.state_bucket_arn}/${local.state_key}.tflock"]
  }

  statement {
    sid       = "UseTheStateKey"
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.state.arn]
  }

  # ---------------------------------------------------------------- EC2 and VPC
  statement {
    sid       = "DescribeEc2"
    actions   = ["ec2:Describe*"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.region]
    }
  }

  # Creates, each only with the tag. The VPC is its own statement, and the
  # instance's, so a subnet, route table or security group is created only in
  # a tagged VPC, and an instance only in a tagged subnet and security group
  # (Ec2ChangeTagged), never in another one by way of the request's own tags.
  statement {
    sid       = "CreateTheVpc"
    actions   = ["ec2:CreateVpc"]
    resources = ["${local.arn.ec2}:vpc/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }

    condition {
      test     = "ForAllValues:StringEquals"
      variable = "aws:TagKeys"
      values   = local.tag_keys
    }
  }

  statement {
    sid       = "CreateInTheVpc"
    actions   = ["ec2:CreateSubnet", "ec2:CreateRouteTable", "ec2:CreateSecurityGroup", "ec2:CreateInternetGateway"]
    resources = ["${local.arn.ec2}:subnet/*", "${local.arn.ec2}:route-table/*", "${local.arn.ec2}:security-group/*", "${local.arn.ec2}:internet-gateway/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }

    condition {
      test     = "ForAllValues:StringEquals"
      variable = "aws:TagKeys"
      values   = local.tag_keys
    }
  }

  statement {
    sid       = "LaunchTheInstance"
    actions   = ["ec2:RunInstances"]
    resources = ["${local.arn.ec2}:instance/*", "${local.arn.ec2}:volume/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }

    condition {
      test     = "ForAllValues:StringEquals"
      variable = "aws:TagKeys"
      values   = local.tag_keys
    }
  }

  # The primary network interface RunInstances creates. EC2 gives the request
  # no tags for it, so it cannot be held to the tag; the deny below keeps an
  # existing interface out, and the subnet and security group it is created in
  # are held to the tag (ChangeTaggedEc2).
  statement {
    sid       = "LaunchTheInstancesInterface"
    actions   = ["ec2:RunInstances"]
    resources = ["${local.arn.ec2}:network-interface/*"]
  }

  # The image a launch reads, and the snapshot its root volume is made from
  # (ARNs that carry no account), only when the AMI's publisher owns them.
  statement {
    sid       = "LaunchFromTheOwnersImage"
    actions   = ["ec2:RunInstances"]
    resources = ["arn:${local.partition}:ec2:${var.region}::image/*", "arn:${local.partition}:ec2:${var.region}::snapshot/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceAccount"
      values   = [var.ami_owner_id]
    }
  }

  # A launch never takes an existing interface, subnet or security group, and
  # a subnet, route table or security group never goes into a VPC, that does
  # not carry the tag. Existing resources' ARNs name their ids
  # (network-interface/eni-...); the one a request creates is
  # network-interface/* and so on, which the patterns do not match.
  statement {
    sid       = "OnlyIntoTagged"
    effect    = "Deny"
    actions   = local.into_tagged_actions
    resources = local.into_tagged_resources

    condition {
      test     = "StringNotEquals"
      variable = "aws:ResourceTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }
  }

  statement {
    sid       = "TagOnlyOnCreate"
    actions   = ["ec2:CreateTags"]
    resources = ["${local.arn.ec2}:*"]

    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = local.ec2_creates
    }
  }

  # Everything server/ changes, only on resources carrying the tag; tags only
  # of server/'s own keys, and the stack's tag never changed to another value.
  statement {
    sid = "ChangeTaggedEc2"
    actions = [
      "ec2:RunInstances",
      "ec2:CreateSubnet",
      "ec2:CreateRouteTable",
      "ec2:CreateSecurityGroup",
      "ec2:ModifyVpcAttribute",
      "ec2:DeleteVpc",
      "ec2:ModifySubnetAttribute",
      "ec2:DeleteSubnet",
      "ec2:AttachInternetGateway",
      "ec2:DetachInternetGateway",
      "ec2:DeleteInternetGateway",
      "ec2:CreateRoute",
      "ec2:ReplaceRoute",
      "ec2:DeleteRoute",
      "ec2:AssociateRouteTable",
      "ec2:DisassociateRouteTable",
      "ec2:DeleteRouteTable",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:DeleteSecurityGroup",
      "ec2:StartInstances",
      "ec2:StopInstances",
      "ec2:TerminateInstances",
      "ec2:ModifyInstanceAttribute",
      "ec2:ModifyInstanceMetadataOptions",
      "ec2:ModifyInstanceMaintenanceOptions",
      "ec2:ModifyVolume",
      "ec2:CreateTags",
      "ec2:DeleteTags",
    ]
    resources = ["${local.arn.ec2}:*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }

    condition {
      test     = "ForAllValues:StringEquals"
      variable = "aws:TagKeys"
      values   = local.tag_keys
    }

    condition {
      test     = "StringEqualsIfExists"
      variable = "aws:RequestTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }
  }

  # ---------------------------------------------------------------- KMS
  # Tagging a key while creating it needs kms:TagResource on no particular key
  # (AWS KMS, "Controlling access to tags"); the boundary's deny keeps any
  # other key from being given the tag.
  statement {
    sid       = "CreateServerKeys"
    actions   = ["kms:CreateKey", "kms:TagResource"]
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

  statement {
    sid = "ManageAndUseServerKeys"
    actions = [
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListResourceTags",
      "kms:PutKeyPolicy",
      "kms:EnableKeyRotation",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:UpdateKeyDescription",
      "kms:ScheduleKeyDeletion",
      "kms:CreateAlias",
      "kms:DeleteAlias",
      "kms:UpdateAlias",
      # EC2 launches an encrypted volume with the launching principal's key
      # access.
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:Decrypt",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
    ]
    resources = ["${local.arn.kms}:key/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }
  }

  statement {
    sid       = "GrantServerKeysToEbs"
    actions   = ["kms:CreateGrant"]
    resources = ["${local.arn.kms}:key/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }

  statement {
    sid       = "NameTheServerKey"
    actions   = ["kms:CreateAlias", "kms:DeleteAlias", "kms:UpdateAlias"]
    resources = ["${local.arn.kms}:${local.server_key}"]
  }

  statement {
    sid       = "ListKeyAliases"
    actions   = ["kms:ListAliases"]
    resources = ["*"]
  }

  # ---------------------------------------------------------------- S3
  # Bucket-level actions on the one bucket's ARN, which never reach an object
  # (object actions authorize against object ARNs): the reads, and each write
  # storage.tf makes, named (snapshot_bucket_actions).
  statement {
    sid       = "ManageTheSnapshotBucket"
    actions   = local.snapshot_bucket_actions
    resources = ["arn:${local.partition}:s3:::${local.snapshot_bucket}"]
  }

  # allow_destroy empties the versioned bucket on destroy (force_destroy); the
  # role deletes objects, never reads or writes them.
  statement {
    sid       = "EmptyTheSnapshotBucketOnDestroy"
    actions   = local.snapshot_object_actions
    resources = ["arn:${local.partition}:s3:::${local.snapshot_bucket}/*"]
  }

  # ---------------------------------------------------------------- IAM
  # bootstrap made the two server roles and the instance profile (server_roles.tf),
  # with their trust fixed. The role reads them, passes each to its one
  # service, attaches the CloudWatch agent's policy to the instance role, and
  # keeps an inline policy on it for S3 backups; it creates, deletes or
  # retrusts nothing.
  statement {
    sid     = "ReadTheServerRoles"
    actions = ["iam:GetRole", "iam:GetInstanceProfile", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies"]
    resources = [
      local.instance_role_arn,
      local.dlm_role_arn,
      local.instance_profile_arn,
    ]
  }

  statement {
    sid       = "PassTheInstanceRoleToEc2"
    actions   = ["iam:PassRole"]
    resources = [local.instance_role_arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ec2.amazonaws.com"]
    }
  }

  statement {
    sid       = "PassTheDlmRoleToDlm"
    actions   = ["iam:PassRole"]
    resources = [local.dlm_role_arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["dlm.amazonaws.com"]
    }
  }

  # enable_cloudwatch_agent: the agent's policy, on the instance role, and
  # nothing else.
  statement {
    sid       = "AttachTheCloudWatchAgentPolicy"
    actions   = ["iam:AttachRolePolicy", "iam:DetachRolePolicy"]
    resources = [local.instance_role_arn]

    condition {
      test     = "ArnEquals"
      variable = "iam:PolicyARN"
      values   = [local.cloudwatch_agent_policy]
    }
  }

  # enable_s3_backups: the grant to assume the snapshot writer, an inline
  # policy on the instance role;
  # the server roles' boundary caps whatever it says.
  statement {
    sid       = "TheInstanceRolesInlinePolicy"
    actions   = ["iam:PutRolePolicy", "iam:GetRolePolicy", "iam:DeleteRolePolicy"]
    resources = [local.instance_role_arn]
  }

  # ---------------------------------------------------------------- alarms and budgets
  # An alarm and a budget, each created only with the tag, under its name, and
  # changed only while it carries it.
  statement {
    sid     = "CreateTheAlarmAndBudget"
    actions = ["cloudwatch:PutMetricAlarm", "cloudwatch:TagResource", "budgets:ModifyBudget", "budgets:TagResource"]
    resources = [
      "${local.arn.cloudwatch}:alarm:${local.name_prefix}-*",
      "arn:${local.partition}:budgets::${local.account_id}:budget/${local.name_prefix}-*",
    ]

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
    sid = "ManageTheAlarmAndBudget"
    actions = [
      "cloudwatch:PutMetricAlarm",
      "cloudwatch:DeleteAlarms",
      "cloudwatch:DescribeAlarms",
      "cloudwatch:ListTagsForResource",
      "cloudwatch:TagResource",
      "cloudwatch:UntagResource",
      "budgets:ModifyBudget",
      "budgets:ViewBudget",
      "budgets:ListTagsForResource",
      "budgets:TagResource",
      "budgets:UntagResource",
    ]
    resources = [
      "${local.arn.cloudwatch}:alarm:${local.name_prefix}-*",
      "arn:${local.partition}:budgets::${local.account_id}:budget/${local.name_prefix}-*",
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }
  }

  # ---------------------------------------------------------------- SNS
  statement {
    sid       = "CreateTheAlertTopic"
    actions   = ["sns:CreateTopic", "sns:TagResource"]
    resources = ["${local.arn.sns}:${local.name_prefix}-*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }
  }

  statement {
    sid = "ManageTheAlertTopic"
    actions = [
      "sns:GetTopicAttributes",
      "sns:SetTopicAttributes",
      "sns:DeleteTopic",
      "sns:ListTagsForResource",
      "sns:TagResource",
      "sns:UntagResource",
      "sns:Subscribe",
    ]
    resources = ["${local.arn.sns}:${local.name_prefix}-*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }
  }

  # A subscription carries no tags of its own; its ARN is the topic's ARN and
  # an id, so the name scopes it.
  statement {
    sid       = "ManageTheAlertSubscription"
    actions   = ["sns:GetSubscriptionAttributes", "sns:SetSubscriptionAttributes", "sns:Unsubscribe"]
    resources = ["${local.arn.sns}:${local.name_prefix}-*"]
  }

  # ---------------------------------------------------------------- DLM
  # Tagged on create, managed only while tagged; the boundary's deny keeps any
  # other DLM policy from being given the tag.
  statement {
    sid       = "CreateTheSnapshotPolicy"
    actions   = ["dlm:CreateLifecyclePolicy", "dlm:TagResource"]
    resources = ["${local.arn.dlm}:policy/*"]

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
    sid = "ManageTheSnapshotPolicy"
    actions = [
      "dlm:GetLifecyclePolicy",
      "dlm:UpdateLifecyclePolicy",
      "dlm:DeleteLifecyclePolicy",
      "dlm:ListTagsForResource",
      "dlm:TagResource",
      "dlm:UntagResource",
    ]
    resources = ["${local.arn.dlm}:policy/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }
  }

  # ---------------------------------------------------------------- SSM
  statement {
    sid       = "ReadPublicParameters"
    actions   = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = ["arn:${local.partition}:ssm:${var.region}::parameter/aws/service/*"]
  }
}
