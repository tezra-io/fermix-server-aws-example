# server/ with a mocked provider: no credentials, no API calls.
#   terraform -chdir=server init -backend=false
#   terraform -chdir=server test

mock_provider "aws" {
  mock_data "aws_region" {
    defaults = { region = "us-east-1" }
  }

  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }

  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }

  mock_data "aws_ssm_parameter" {
    defaults = { insecure_value = "ami-0aaaaaaaaaaaaaaaa", value = "ami-0aaaaaaaaaaaaaaaa" }
  }

  mock_data "aws_ec2_instance_type_offerings" {
    defaults = { locations = ["us-east-1a"] }
  }

  mock_resource "aws_instance" {
    defaults = { id = "i-0123456789abcdef0" }
  }

  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555" }
  }

  mock_data "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/fermix-server/fermix-server-dlm" }
  }

  mock_data "aws_iam_instance_profile" {
    defaults = { arn = "arn:aws:iam::111122223333:instance-profile/fermix-server/fermix-server-instance" }
  }
}

# Every variable, so an owner's own server/terraform.tfvars, which terraform
# test also reads, changes nothing here.
variables {
  region                   = "us-east-1"
  deploy_role_arn          = "arn:aws:iam::111122223333:role/fermix-server-deploy"
  instance_type            = "t4g.small"
  root_volume_gb           = 20
  availability_zone        = null
  vpc_cidr                 = "10.75.0.0/16"
  enable_cloudwatch_agent  = false
  enable_ebs_snapshots     = true
  ebs_snapshot_time_utc    = "03:00"
  snapshot_noncurrent_days = 30
  alert_emails             = []
  monthly_budget_usd       = 30
  allow_destroy            = false
}

run "an_unknown_region_is_refused" {
  command = plan

  variables {
    region = "virginia"
  }

  expect_failures = [var.region]
}

run "only_bootstraps_deploy_role_is_assumed" {
  command = plan

  variables {
    deploy_role_arn = "arn:aws:iam::111122223333:role/managed/OwnerAdmin"
  }

  expect_failures = [var.deploy_role_arn]
}

# Applied against the mock so the outputs exist; allow_destroy lets the test's
# own cleanup through the destroy guard.
run "s3_backups_off_reach_the_module" {
  command = plan

  variables {
    enable_s3_backups = false
  }

  assert {
    condition     = output.snapshot_bucket == null && output.snapshot_bucket_region == null
    error_message = "enable_s3_backups = false reaches the module: there is no bucket to name"
  }
}

run "the_outputs_open_a_session_and_name_the_bucket" {
  variables {
    allow_destroy = true
  }

  assert {
    condition     = output.session_command == "aws ssm start-session --target i-0123456789abcdef0 --region us-east-1"
    error_message = "the output's Session Manager command names the instance and its region"
  }

  assert {
    condition     = output.snapshot_bucket == "fermix-server-snapshots-111122223333-us-east-1" && output.snapshot_bucket_region == "us-east-1"
    error_message = "the bucket's name and region, with enable_s3_backups on by default"
  }

  assert {
    condition     = output.instance_id == "i-0123456789abcdef0" && output.region == "us-east-1"
    error_message = "the instance id and region"
  }
}
