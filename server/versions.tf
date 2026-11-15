terraform {
  # 1.10 brought S3's native lock file (use_lockfile).
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.67.0"
    }
  }

  # Partial configuration: the bucket, its region and key, and the deploy role
  # come from backend.s3.tfbackend, which bootstrap's server_backend output
  # writes (README.md, "Step 4: apply server/"). The state is read and
  # written as the deploy role, through S3's own lock file.
  backend "s3" {
    key          = "server/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
