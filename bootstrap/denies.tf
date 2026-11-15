# The deploy role's denies that its boundary has no room for (DESIGN.md, "The
# deploy role's policy is inline, under a boundary"): a managed policy of
# denies alone, which bootstrap attaches to the role. An explicit deny in any
# policy the role holds refuses the request whatever any other policy allows,
# so these hold over the role's own policy and anything attached later, as
# the boundary's denies do. The role cannot detach, edit or replace this
# policy: its IAM rights stop at the two server roles and the instance
# profile, and the boundary denies attaching or detaching any policy but the
# CloudWatch agent's. It denies:
#   - every action on the snapshot bucket and its objects but those
#     storage.tf's resources call (permissions.tf), so no public access
#     block, ACL, replication, website, logging, notification, inventory,
#     Object Lock or ABAC, and no object read or write;
#   - a key policy written past KMS's lockout safety check;
#   - every instance attribute but termination protection (allow_destroy) and
#     the instance type, so never the user data, kernel or RAM disk, which
#     run code at the next boot with no session or command to see.

resource "aws_iam_policy" "deploy_denies" {
  name        = local.deploy_denies_name
  path        = "/"
  description = "The denies of fermix-server-deploy that its boundary has no room for."
  policy      = data.aws_iam_policy_document.deploy_denies.json
}

# By the policy's ARN, which a plan already knows (tests/findings.tftest.hcl).
resource "aws_iam_role_policy_attachment" "deploy_denies" {
  role       = aws_iam_role.deploy.name
  policy_arn = local.deploy_denies_arn

  depends_on = [aws_iam_policy.deploy_denies]
}

locals {
  deploy_denies_name = "fermix-server-deploy-denies"
  deploy_denies_arn  = "arn:${local.partition}:iam::${local.account_id}:policy/${local.deploy_denies_name}"

  snapshot_bucket_arn = "arn:${local.partition}:s3:::${local.snapshot_bucket}"
}

data "aws_iam_policy_document" "deploy_denies" {
  # The snapshot bucket as storage.tf makes it, and nothing else. The
  # provider asks S3 for a bucket's tags with ListTagsForResource and
  # TagResource first and, refused, falls back to GetBucketTagging and
  # PutBucketTagging: the role's policy allows neither, and they are left
  # out of this deny so that the refusal stays the one the fallback has
  # always seen. A bucket's tags authorize nothing while ABAC is off, and
  # PutBucketAbac is denied.
  statement {
    sid    = "TheSnapshotBucketAsServerMakesIt"
    effect = "Deny"
    not_actions = concat(
      local.snapshot_bucket_actions,
      local.snapshot_object_actions,
      ["s3:ListTagsForResource", "s3:TagResource", "s3:UntagResource"],
    )
    resources = [local.snapshot_bucket_arn, "${local.snapshot_bucket_arn}/*"]
  }

  # KMS's lockout safety check refuses a key policy that would leave the
  # caller unable to change it again; no key policy skips it. server/ never
  # sets bypass_policy_lockout_safety_check.
  statement {
    sid       = "NoKeyPolicyPastTheLockoutCheck"
    effect    = "Deny"
    actions   = ["kms:CreateKey", "kms:PutKeyPolicy"]
    resources = ["*"]

    condition {
      test     = "Bool"
      variable = "kms:BypassPolicyLockoutSafetyCheck"
      values   = ["true"]
    }
  }

  # ModifyInstanceAttribute changes one attribute per call, named either by
  # the request's Attribute (ec2:Attribute, "userData") or by its own field
  # (ec2:Attribute/UserData), which is how the provider calls it. Denied
  # unless the call sets termination protection or the type, either way:
  # what server/ changes (allow_destroy, instance_type; the user data is read
  # once: DESIGN.md, "The AMI and the user data are read once"). Any other
  # attribute, the user data, kernel and RAM disk among them, is refused, and
  # so is one this deny does not know.
  statement {
    sid       = "NoInstanceAttributeButProtectionAndType"
    effect    = "Deny"
    actions   = ["ec2:ModifyInstanceAttribute"]
    resources = ["*"]

    condition {
      test     = "Null"
      variable = "ec2:Attribute/DisableApiTermination"
      values   = ["true"]
    }

    condition {
      test     = "Null"
      variable = "ec2:Attribute/InstanceType"
      values   = ["true"]
    }

    condition {
      test     = "StringNotEqualsIgnoreCaseIfExists"
      variable = "ec2:Attribute"
      values   = ["disableApiTermination", "instanceType"]
    }
  }
}
