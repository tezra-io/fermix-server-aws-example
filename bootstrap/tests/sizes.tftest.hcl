# The deploy role's documents against IAM's size limits, rendered by the real
# aws_iam_policy_document, which the provider computes locally: no account,
# no credentials, no API call. IAM counts a policy without its whitespace
# (minified_json): 6,144 characters for a managed policy (the boundary, the
# denies, the server roles' boundary) and 10,240 for a role's inline policies
# together, which for the deploy role is permissions.tf's alone.
# us-east-1, and a 14-character region (ap-southeast-2, the longest region
# names), which every regional ARN lengthens by five (DESIGN.md, "The deploy
# role's policy is inline, under a boundary").
#   terraform -chdir=bootstrap test -filter=tests/sizes.tftest.hcl
#
# Each run applies the documents alone, targeted (so Terraform warns that
# targeting is in effect), since a plan would defer them: they name the state
# key, which a plan only creates. The state key is overridden with an
# ARN of the real length, so nothing is created, nothing else is planned and
# the provider makes no call; the second run keeps its own state, so its key
# is the second region's.

# The documents name var.region; the provider's own region reaches nothing.
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "offline"
  secret_key                  = "offline"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

variables {
  admin_role_arn = "arn:aws:iam::111122223333:role/managed/OwnerAdmin"
}

run "the_documents_fit_in_us_east_1" {
  command = apply

  variables {
    region = "us-east-1"
  }

  override_resource {
    target = aws_kms_key.state
    values = {
      arn = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000"
    }
  }

  plan_options {
    target = [
      data.aws_iam_policy_document.boundary,
      data.aws_iam_policy_document.deploy,
      data.aws_iam_policy_document.deploy_denies,
      data.aws_iam_policy_document.workload,
    ]
  }

  assert {
    condition     = length(data.aws_iam_policy_document.boundary.minified_json) <= 6144
    error_message = "the boundary is ${length(data.aws_iam_policy_document.boundary.minified_json)} characters, over IAM's 6,144 for a managed policy"
  }

  assert {
    condition     = length(data.aws_iam_policy_document.deploy.minified_json) <= 10240
    error_message = "the deploy role's inline policy is ${length(data.aws_iam_policy_document.deploy.minified_json)} characters, over IAM's 10,240 for a role's inline policies"
  }

  assert {
    condition     = length(data.aws_iam_policy_document.deploy_denies.minified_json) <= 6144
    error_message = "the deploy role's denies are ${length(data.aws_iam_policy_document.deploy_denies.minified_json)} characters, over IAM's 6,144 for a managed policy"
  }

  assert {
    condition     = length(data.aws_iam_policy_document.workload.minified_json) <= 6144
    error_message = "the server roles' boundary is ${length(data.aws_iam_policy_document.workload.minified_json)} characters, over IAM's 6,144 for a managed policy"
  }
}

run "the_documents_fit_in_a_14_character_region" {
  command   = apply
  state_key = "ap-southeast-2"

  variables {
    region = "ap-southeast-2"
  }

  override_resource {
    target = aws_kms_key.state
    values = {
      arn = "arn:aws:kms:ap-southeast-2:111122223333:key/00000000-0000-0000-0000-000000000000"
    }
  }

  plan_options {
    target = [
      data.aws_iam_policy_document.boundary,
      data.aws_iam_policy_document.deploy,
      data.aws_iam_policy_document.deploy_denies,
      data.aws_iam_policy_document.workload,
    ]
  }

  assert {
    condition     = length(data.aws_iam_policy_document.boundary.minified_json) <= 6144
    error_message = "in ap-southeast-2 the boundary is ${length(data.aws_iam_policy_document.boundary.minified_json)} characters, over IAM's 6,144 for a managed policy"
  }

  assert {
    condition     = length(data.aws_iam_policy_document.deploy.minified_json) <= 10240
    error_message = "in ap-southeast-2 the deploy role's inline policy is ${length(data.aws_iam_policy_document.deploy.minified_json)} characters, over IAM's 10,240 for a role's inline policies"
  }

  assert {
    condition     = length(data.aws_iam_policy_document.deploy_denies.minified_json) <= 6144
    error_message = "in ap-southeast-2 the deploy role's denies are ${length(data.aws_iam_policy_document.deploy_denies.minified_json)} characters, over IAM's 6,144 for a managed policy"
  }

  assert {
    condition     = length(data.aws_iam_policy_document.workload.minified_json) <= 6144
    error_message = "in ap-southeast-2 the server roles' boundary is ${length(data.aws_iam_policy_document.workload.minified_json)} characters, over IAM's 6,144 for a managed policy"
  }
}
