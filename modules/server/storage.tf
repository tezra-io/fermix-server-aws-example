# The snapshot bucket, with enable_s3_backups: Fermix's own encrypted
# snapshots, put by the snapshot writer's session (iam.tf). Off, there is
# no bucket. The moved blocks keep a bucket that an earlier version of this
# module made before the switch existed.

resource "aws_s3_bucket" "snapshots" {
  count = var.enable_s3_backups ? 1 : 0

  bucket = local.snapshot_bucket

  # allow_destroy lets terraform destroy empty it, every version included.
  force_destroy = var.allow_destroy

  tags = local.tags
}

resource "aws_s3_bucket_ownership_controls" "snapshots" {
  count = var.enable_s3_backups ? 1 : 0

  bucket = aws_s3_bucket.snapshots[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "snapshots" {
  count = var.enable_s3_backups ? 1 : 0

  bucket                  = aws_s3_bucket.snapshots[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "snapshots" {
  count = var.enable_s3_backups ? 1 : 0

  bucket = aws_s3_bucket.snapshots[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "snapshots" {
  count = var.enable_s3_backups ? 1 : 0

  bucket = aws_s3_bucket.snapshots[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.server.arn
    }
    bucket_key_enabled = true

    # An object under a key its uploader brings (SSE-C) would bypass the
    # server key; the bucket policy refuses it too.
    blocked_encryption_types = ["SSE-C"]
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "snapshots" {
  count = var.enable_s3_backups ? 1 : 0

  bucket = aws_s3_bucket.snapshots[0].id

  rule {
    id     = "noncurrent-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = var.snapshot_noncurrent_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.snapshots]
}

resource "aws_s3_bucket_policy" "snapshots" {
  count = var.enable_s3_backups ? 1 : 0

  bucket = aws_s3_bucket.snapshots[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RefuseAnythingButTls"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.snapshots[0].arn, "${aws_s3_bucket.snapshots[0].arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      # An upload that names no encryption gets the bucket's default, the
      # server key; Fermix's uploads name none. One that names another encryption,
      # SSE-KMS with another key or none, or a key of its own (SSE-C, which
      # sets no x-amz-server-side-encryption header), is refused. The Null
      # test holds each deny to an upload that names an encryption: a negated
      # test alone is true when the header is absent.
      {
        Sid       = "RefuseUploadsNamingAnotherEncryption"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.snapshots[0].arn}/*"
        Condition = {
          Null            = { "s3:x-amz-server-side-encryption" = "false" }
          StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" }
        }
      },
      {
        Sid       = "RefuseUploadsNamingAnotherKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.snapshots[0].arn}/*"
        Condition = {
          Null                    = { "s3:x-amz-server-side-encryption" = "false" }
          StringNotEqualsIfExists = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.server.arn }
        }
      },
      {
        Sid       = "RefuseCustomerProvidedKeys"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.snapshots[0].arn}/*"
        Condition = { Null = { "s3:x-amz-server-side-encryption-customer-algorithm" = "false" } }
      },
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.snapshots]
}

moved {
  from = aws_s3_bucket.snapshots
  to   = aws_s3_bucket.snapshots[0]
}

moved {
  from = aws_s3_bucket_ownership_controls.snapshots
  to   = aws_s3_bucket_ownership_controls.snapshots[0]
}

moved {
  from = aws_s3_bucket_public_access_block.snapshots
  to   = aws_s3_bucket_public_access_block.snapshots[0]
}

moved {
  from = aws_s3_bucket_versioning.snapshots
  to   = aws_s3_bucket_versioning.snapshots[0]
}

moved {
  from = aws_s3_bucket_server_side_encryption_configuration.snapshots
  to   = aws_s3_bucket_server_side_encryption_configuration.snapshots[0]
}

moved {
  from = aws_s3_bucket_lifecycle_configuration.snapshots
  to   = aws_s3_bucket_lifecycle_configuration.snapshots[0]
}

moved {
  from = aws_s3_bucket_policy.snapshots
  to   = aws_s3_bucket_policy.snapshots[0]
}
