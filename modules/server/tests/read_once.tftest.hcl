# What the server is created with stays: a later AMI or a changed user data
# never replaces it, since replacing it destroys the home it holds. A mocked
# apply, then a second apply in the same state with a newer AMI and the
# CloudWatch agent turned on. allow_destroy lets the test's own cleanup run.
#   terraform -chdir=modules/server test -filter=tests/read_once.tftest.hcl

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

  mock_data "aws_ec2_instance_type_offerings" {
    defaults = { locations = ["us-east-1a"] }
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

  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::fermix-server-snapshots-111122223333-us-east-1" }
  }
}

variables {
  allow_destroy = true
}

run "create" {
  override_data {
    target = data.aws_ssm_parameter.debian
    values = { insecure_value = "ami-0aaaaaaaaaaaaaaaa", value = "ami-0aaaaaaaaaaaaaaaa" }
  }

  assert {
    condition     = aws_instance.server.ami == "ami-0aaaaaaaaaaaaaaaa"
    error_message = "the server is created from the AMI the parameter names"
  }
}

run "a_newer_ami_and_the_cloudwatch_agent_replace_nothing" {
  variables {
    enable_cloudwatch_agent = true
  }

  override_data {
    target = data.aws_ssm_parameter.debian
    values = { insecure_value = "ami-0bbbbbbbbbbbbbbbb", value = "ami-0bbbbbbbbbbbbbbbb" }
  }

  # The CloudWatch agent turned on after create: the policy follows, the
  # agent waits for a first boot, and every plan says so.
  expect_failures = [check.cloudwatch_agent_matches_first_boot]

  assert {
    condition     = aws_instance.server.ami == "ami-0aaaaaaaaaaaaaaaa"
    error_message = "the AMI is read once: a newer one is ignored after create (lifecycle ignore_changes)"
  }

  assert {
    condition     = strcontains(aws_instance.server.user_data, "with_cloudwatch_agent='false'")
    error_message = "the user data is read once: a change after create neither restarts nor replaces the server"
  }

  assert {
    condition     = length(aws_iam_role_policy_attachment.cloudwatch_agent) == 1
    error_message = "the instance role's policy still follows enable_cloudwatch_agent"
  }
}
