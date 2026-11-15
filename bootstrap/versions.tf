terraform {
  # 1.10 brought S3's native lock file (use_lockfile), which server/ uses.
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.67.0"
    }
  }

  # bootstrap's own state lives in the state bucket it makes, under its own key,
  # read and written with the owner's sign-in. Partial configuration: the
  # bucket, its region and key come from backend.s3.tfbackend (gitignored),
  # which bootstrap_backend writes. The very first apply runs on local state
  # through a gitignored backend_override.tf; then `init -migrate-state` moves
  # the state into the bucket that apply made (README.md, "Step 3: apply
  # bootstrap/").
  backend "s3" {
    key          = "bootstrap/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

# The owner's own sign-in (README.md, "Step 3: apply bootstrap/").
# allowed_account_ids refuses any account but the one admin_role_arn names.
provider "aws" {
  region              = var.region
  allowed_account_ids = [local.account_id]

  default_tags {
    tags = local.stack_tags
  }
}
