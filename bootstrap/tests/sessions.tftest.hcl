# require_session_mfa (README.md, "Sessions with MFA"), with a mocked
# provider and plans, as tests/bootstrap.tftest.hcl.
#   terraform -chdir=bootstrap test -filter=tests/sessions.tftest.hcl
#
# IAM checks MFA on the call that starts a session, against the caller's own
# policies, so the deny goes on admin_role_arn itself.

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  region         = "us-east-1"
  admin_role_arn = "arn:aws:iam::111122223333:role/managed/OwnerAdmin"
}

run "nothing_is_written_on_the_owner_by_default" {
  command = plan

  assert {
    condition     = try(aws_iam_role_policy.session_mfa[0].name, null) == null && try(aws_iam_user_policy.session_mfa[0].name, null) == null
    error_message = "without require_session_mfa, bootstrap writes nothing on admin_role_arn"
  }
}

run "mfa_on_denies_the_owner_a_session_without_mfa" {
  command = plan

  variables {
    require_session_mfa = true
  }

  assert {
    condition = (
      try(aws_iam_role_policy.session_mfa[0].role, null) == "OwnerAdmin" &&
      try(aws_iam_role_policy.session_mfa[0].name, null) == "fermix-server-sessions-need-mfa" &&
      try(aws_iam_user_policy.session_mfa[0].name, null) == null
    )
    error_message = "require_session_mfa writes one inline policy on admin_role_arn's role, by its name"
  }

  # Every SSM action that can run code on the server: on the server's
  # instance where the request names it, in the whole region where it names
  # none (bootstrap does not know the instance id).
  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.session_mfa.statement : (
        s.effect == "Deny" && contains(s.actions, "ssm:StartSession") &&
        s.resources == toset(["arn:aws:ec2:us-east-1:111122223333:instance/*"]) &&
        anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "ssm:resourceTag/fermix-server-stack" && c.values == tolist(["server"])]) &&
        anytrue([for c in s.condition : c.test == "BoolIfExists" && c.variable == "aws:MultiFactorAuthPresent" && c.values == tolist(["false"])])
      )
    ])
    error_message = "without MFA, admin_role_arn is denied ssm:StartSession on the server, which opens a shell"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.session_mfa.statement : (
        s.effect == "Deny" && contains(s.actions, "ssm:SendCommand") &&
        s.resources == toset(["arn:aws:ec2:us-east-1:111122223333:instance/*"]) &&
        anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "ssm:resourceTag/fermix-server-stack" && c.values == tolist(["server"])]) &&
        anytrue([for c in s.condition : c.test == "BoolIfExists" && c.variable == "aws:MultiFactorAuthPresent" && c.values == tolist(["false"])])
      )
    ])
    error_message = "without MFA, admin_role_arn is denied ssm:SendCommand on the server, which runs a command as root (Run Command)"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.session_mfa.statement : (
        s.effect == "Deny" && contains(s.actions, "ssm:ResumeSession") && s.resources == toset(["*"]) &&
        anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "aws:RequestedRegion" && c.values == tolist(["us-east-1"])]) &&
        anytrue([for c in s.condition : c.test == "BoolIfExists" && c.variable == "aws:MultiFactorAuthPresent" && c.values == tolist(["false"])])
      )
    ])
    error_message = "without MFA, admin_role_arn is denied ssm:ResumeSession in the region: it names no instance, and reconnects to an open session"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.session_mfa.statement : (
        s.effect == "Deny" && contains(s.actions, "ssm:StartAutomationExecution") && s.resources == toset(["*"]) &&
        anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "aws:RequestedRegion" && c.values == tolist(["us-east-1"])]) &&
        anytrue([for c in s.condition : c.test == "BoolIfExists" && c.variable == "aws:MultiFactorAuthPresent" && c.values == tolist(["false"])])
      )
    ])
    error_message = "without MFA, admin_role_arn is denied ssm:StartAutomationExecution in the region: it names no instance, and runs an automation, whose steps can run a command"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.session_mfa.statement : (
        s.effect == "Deny" && contains(s.actions, "ssm:StartChangeRequestExecution") && s.resources == toset(["*"]) &&
        anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "aws:RequestedRegion" && c.values == tolist(["us-east-1"])]) &&
        anytrue([for c in s.condition : c.test == "BoolIfExists" && c.variable == "aws:MultiFactorAuthPresent" && c.values == tolist(["false"])])
      )
    ])
    error_message = "without MFA, admin_role_arn is denied ssm:StartChangeRequestExecution in the region: it names no instance, and runs a change template's automation"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.session_mfa.statement : (
        s.effect == "Deny" && contains(s.actions, "ssm:CreateAssociation") && s.resources == toset(["*"]) &&
        anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "aws:RequestedRegion" && c.values == tolist(["us-east-1"])]) &&
        anytrue([for c in s.condition : c.test == "BoolIfExists" && c.variable == "aws:MultiFactorAuthPresent" && c.values == tolist(["false"])])
      )
    ])
    error_message = "without MFA, admin_role_arn is denied ssm:CreateAssociation in the region: it names no instance, and makes a State Manager association, which can target it by tag"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.session_mfa.statement : (
        s.effect == "Deny" && contains(s.actions, "ssm:CreateAssociationBatch") && s.resources == toset(["*"]) &&
        anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "aws:RequestedRegion" && c.values == tolist(["us-east-1"])]) &&
        anytrue([for c in s.condition : c.test == "BoolIfExists" && c.variable == "aws:MultiFactorAuthPresent" && c.values == tolist(["false"])])
      )
    ])
    error_message = "without MFA, admin_role_arn is denied ssm:CreateAssociationBatch in the region: it names no instance, and makes several associations"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.session_mfa.statement : (
        s.effect == "Deny" && contains(s.actions, "ssm:UpdateAssociation") && s.resources == toset(["*"]) &&
        anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "aws:RequestedRegion" && c.values == tolist(["us-east-1"])]) &&
        anytrue([for c in s.condition : c.test == "BoolIfExists" && c.variable == "aws:MultiFactorAuthPresent" && c.values == tolist(["false"])])
      )
    ])
    error_message = "without MFA, admin_role_arn is denied ssm:UpdateAssociation in the region: it names no instance, and changes an association's document or targets and runs it"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.session_mfa.statement : (
        s.effect == "Deny" && contains(s.actions, "ssm:StartAssociationsOnce") && s.resources == toset(["*"]) &&
        anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "aws:RequestedRegion" && c.values == tolist(["us-east-1"])]) &&
        anytrue([for c in s.condition : c.test == "BoolIfExists" && c.variable == "aws:MultiFactorAuthPresent" && c.values == tolist(["false"])])
      )
    ])
    error_message = "without MFA, admin_role_arn is denied ssm:StartAssociationsOnce in the region: it names no instance, and runs an association now"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.session_mfa.statement : (
        s.effect == "Deny" && contains(s.actions, "ssm:RegisterTaskWithMaintenanceWindow") && s.resources == toset(["*"]) &&
        anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "aws:RequestedRegion" && c.values == tolist(["us-east-1"])]) &&
        anytrue([for c in s.condition : c.test == "BoolIfExists" && c.variable == "aws:MultiFactorAuthPresent" && c.values == tolist(["false"])])
      )
    ])
    error_message = "without MFA, admin_role_arn is denied ssm:RegisterTaskWithMaintenanceWindow in the region: it names no instance, and gives a maintenance window a task to run"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.session_mfa.statement : (
        s.effect == "Deny" && contains(s.actions, "ssm:UpdateMaintenanceWindowTask") && s.resources == toset(["*"]) &&
        anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "aws:RequestedRegion" && c.values == tolist(["us-east-1"])]) &&
        anytrue([for c in s.condition : c.test == "BoolIfExists" && c.variable == "aws:MultiFactorAuthPresent" && c.values == tolist(["false"])])
      )
    ])
    error_message = "without MFA, admin_role_arn is denied ssm:UpdateMaintenanceWindowTask in the region: it names no instance, and changes a maintenance window's task"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.session_mfa.statement : (
        s.effect == "Deny" && contains(s.actions, "ssm:RegisterTargetWithMaintenanceWindow") && s.resources == toset(["*"]) &&
        anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "aws:RequestedRegion" && c.values == tolist(["us-east-1"])]) &&
        anytrue([for c in s.condition : c.test == "BoolIfExists" && c.variable == "aws:MultiFactorAuthPresent" && c.values == tolist(["false"])])
      )
    ])
    error_message = "without MFA, admin_role_arn is denied ssm:RegisterTargetWithMaintenanceWindow in the region: it names no instance, and gives a maintenance window a target"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.session_mfa.statement : (
        s.effect == "Deny" && contains(s.actions, "ssm:UpdateMaintenanceWindowTarget") && s.resources == toset(["*"]) &&
        anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "aws:RequestedRegion" && c.values == tolist(["us-east-1"])]) &&
        anytrue([for c in s.condition : c.test == "BoolIfExists" && c.variable == "aws:MultiFactorAuthPresent" && c.values == tolist(["false"])])
      )
    ])
    error_message = "without MFA, admin_role_arn is denied ssm:UpdateMaintenanceWindowTarget in the region: it names no instance, and changes a maintenance window's targets"
  }
}


run "an_iam_user_owner_gets_it_on_the_user" {
  command = plan

  variables {
    admin_role_arn      = "arn:aws:iam::111122223333:user/owner"
    require_session_mfa = true
  }

  assert {
    condition     = try(aws_iam_user_policy.session_mfa[0].user, null) == "owner" && try(aws_iam_role_policy.session_mfa[0].name, null) == null
    error_message = "an IAM user's ARN gets the policy on the user"
  }
}
