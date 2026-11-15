# The state bucket for server/: versioned, encrypted with its own key, public
# access blocked, TLS only, with S3's own lock file (use_lockfile) and no
# DynamoDB table.

resource "aws_kms_key" "state" {
  description             = "fermix-server-state: server/'s Terraform state and its lock file"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30

  # The account administers and uses the key through IAM only: the owner's
  # sign-in, and the deploy role through its boundary (boundary.tf). Nothing on
  # the server can read the state: the instance role has no grant on it.
  policy = data.aws_iam_policy_document.state_key.json

  # Losing this key loses the state.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "state" {
  name          = "alias/fermix-server-state"
  target_key_id = aws_kms_key.state.key_id
}

data "aws_iam_policy_document" "state_key" {
  statement {
    sid       = "AccountAdministersThroughIam"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_s3_bucket" "state" {
  bucket = local.state_bucket

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.state_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.state]
}

data "aws_iam_policy_document" "state_bucket" {
  statement {
    sid       = "RefuseAnythingButTls"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]

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
}
