# enable_cloudtrail: the least trail that lets EventBridge see the account's
# API calls, the session email's StartSession among them (alerts.tf).
# EventBridge receives "AWS API Call via CloudTrail" events only while a trail
# logs them. Write management events, this region, encrypted with its own key
# into a private bucket; no data events and no Insights. It is the owner's,
# made here with the owner's sign-in: the deploy role reaches no CloudTrail
# action, and neither the key (tagged bootstrap) nor the bucket.

locals {
  trail_name = "fermix-server"
  trail_arn  = "arn:${local.partition}:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"
  # CHANGE ME only if S3 says this name is taken: bucket names are global; this one carries your account id and region.
  trail_bucket = "fermix-server-trail-${local.account_id}-${var.region}"

  # Logs are kept 90 days, as CloudTrail's own event history keeps them.
  trail_log_days = 90
}

resource "aws_kms_key" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  description             = "fermix-server-trail: the session email's CloudTrail logs"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.trail_key[0].json
}

resource "aws_kms_alias" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  name          = "alias/fermix-server-trail"
  target_key_id = aws_kms_key.trail[0].key_id
}

data "aws_iam_policy_document" "trail_key" {
  count = var.enable_cloudtrail ? 1 : 0

  statement {
    sid       = "AccountAdministersThroughIam"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "CloudTrailEncryptsThisTrailsLogs"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }

  statement {
    sid       = "CloudTrailDescribesTheKey"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_s3_bucket" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket = local.trail_bucket
}

resource "aws_s3_bucket_ownership_controls" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket = aws_s3_bucket.trail[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket                  = aws_s3_bucket.trail[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket = aws_s3_bucket.trail[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket = aws_s3_bucket.trail[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.trail[0].arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket = aws_s3_bucket.trail[0].id

  rule {
    id     = "logs"
    status = "Enabled"

    filter {}

    expiration {
      days = local.trail_log_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.trail]
}

resource "aws_s3_bucket_policy" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket = aws_s3_bucket.trail[0].id
  policy = data.aws_iam_policy_document.trail_bucket[0].json

  depends_on = [aws_s3_bucket_public_access_block.trail]
}

data "aws_iam_policy_document" "trail_bucket" {
  count = var.enable_cloudtrail ? 1 : 0

  statement {
    sid       = "RefuseAnythingButTls"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail[0].arn, "${aws_s3_bucket.trail[0].arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "CloudTrailChecksTheBucket"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail[0].arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailWritesThisTrailsLogs"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail[0].arn}/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_cloudtrail" "this" {
  count = var.enable_cloudtrail ? 1 : 0

  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail[0].bucket
  kms_key_id                    = aws_kms_key.trail[0].arn
  enable_log_file_validation    = true
  is_multi_region_trail         = false
  include_global_service_events = false

  event_selector {
    read_write_type           = "WriteOnly"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.trail]
}
