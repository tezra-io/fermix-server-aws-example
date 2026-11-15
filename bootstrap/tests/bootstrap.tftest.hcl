# Plans bootstrap with a mocked provider: no credentials, no API calls. Plans
# only: the state key and bucket carry prevent_destroy, so the test's own
# cleanup could not destroy an apply. A mocked test cannot evaluate IAM, so the
# policies are held by their shape: the statements are configuration, which a
# plan knows.
#   terraform -chdir=bootstrap init -backend=false
#   terraform -chdir=bootstrap test

# A mocked policy document must still be a JSON policy for the resources that
# take it. Assertions iterate statement lists, never whole data sources: a
# failing assertion over a whole object crashes Terraform 1.16.6's test output.
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

run "the_deploy_roles_boundary_is_attached" {
  command = plan

  assert {
    condition     = aws_iam_role.deploy.permissions_boundary == "arn:aws:iam::111122223333:policy/fermix-server-deploy-boundary"
    error_message = "the deploy role carries its permissions boundary"
  }

  assert {
    condition     = aws_iam_policy.boundary.name == "fermix-server-deploy-boundary" && aws_iam_policy.boundary.path == "/"
    error_message = "the boundary is the policy the role's ARN names"
  }

  assert {
    condition     = aws_iam_role_policy.deploy.name == "server"
    error_message = "the role's own policy is the inline policy permissions.tf writes"
  }

  assert {
    condition     = aws_iam_role.deploy.path == "/" && aws_iam_role.deploy.name == "fermix-server-deploy"
    error_message = "the deploy role sits outside /fermix-server/, where its own IAM rights stop"
  }
}

run "only_the_owners_role_is_trusted" {
  command = plan

  assert {
    condition = (
      length(data.aws_iam_policy_document.trust.statement) == 1 &&
      data.aws_iam_policy_document.trust.statement[0].actions == toset(["sts:AssumeRole"]) &&
      one(data.aws_iam_policy_document.trust.statement[0].principals).type == "AWS" &&
      one(data.aws_iam_policy_document.trust.statement[0].principals).identifiers == toset([var.admin_role_arn])
    )
    error_message = "the deploy role trusts admin_role_arn and nothing else"
  }
}

run "a_session_arn_is_refused" {
  command = plan

  variables {
    admin_role_arn = "arn:aws:sts::111122223333:assumed-role/OwnerAdmin/owner-session"
  }

  expect_failures = [var.admin_role_arn]
}

# Finding 1: kms:TagResource on any key let the role give the state key, or
# any other, the server tag and with it the tag's rights.
run "no_kms_key_can_be_taken_over" {
  command = plan

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.deploy.statement : (
        (s.resources == toset(["*"]) &&
          anytrue([for c in s.condition : c.variable == "aws:RequestTag/fermix-server-stack" && c.values == tolist(["server"])]) &&
        anytrue([for c in s.condition : c.test == "ForAllValues:StringEquals" && c.variable == "aws:TagKeys" && c.values == tolist(["fermix-server-stack"])])) ||
        (alltrue([for r in s.resources : startswith(r, "arn:aws:kms:us-east-1:111122223333:key/")]) &&
        anytrue([for c in s.condition : c.variable == "aws:ResourceTag/fermix-server-stack" && c.values == tolist(["server"])]))
      ) if contains(s.actions, "kms:TagResource") || contains(s.actions, "kms:CreateKey")
    ])
    error_message = "the role tags a key only while creating it with the server tag alone, or a key that already carries it"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        contains(coalesce(s.actions, toset([])), "kms:TagResource") && contains(coalesce(s.actions, toset([])), "kms:UntagResource") &&
        contains(coalesce(s.resources, toset([])), "arn:aws:kms:*:*:key/*") &&
        anytrue([for c in s.condition : c.test == "StringNotEquals" && c.variable == "aws:ResourceTag/fermix-server-stack" && c.values == tolist(["server"])])
      )
    ])
    error_message = "the boundary denies tagging or untagging any key that does not already carry the server tag"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        toset(coalesce(s.not_actions, toset([]))) == toset(["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]) &&
        length(s.resources) == 1
      )
    ])
    error_message = "the boundary denies everything on the state key but using it for the state"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        toset(coalesce(s.not_actions, toset([]))) == toset(["s3:ListBucket", "s3:GetObject", "s3:PutObject", "s3:DeleteObject"]) &&
        coalesce(s.resources, toset([])) == toset(["arn:aws:s3:::fermix-server-state-111122223333-us-east-1", "arn:aws:s3:::fermix-server-state-111122223333-us-east-1/*"])
      )
    ])
    error_message = "the boundary denies every change to the state bucket itself"
  }
}

# Finding 2: the same for Data Lifecycle Manager policies.
run "no_dlm_policy_can_be_taken_over" {
  command = plan

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.deploy.statement : (
        (contains(s.actions, "dlm:CreateLifecyclePolicy") &&
          anytrue([for c in s.condition : c.variable == "aws:RequestTag/fermix-server-stack" && c.values == tolist(["server"])]) &&
        anytrue([for c in s.condition : c.test == "ForAllValues:StringEquals" && c.variable == "aws:TagKeys" && c.values == tolist(["fermix-server-stack"])])) ||
        anytrue([for c in s.condition : c.variable == "aws:ResourceTag/fermix-server-stack" && c.values == tolist(["server"])])
      ) if contains(s.actions, "dlm:TagResource")
    ])
    error_message = "the role tags a DLM policy only while creating it with the server tag alone, or one that already carries it"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        contains(coalesce(s.actions, toset([])), "dlm:TagResource") && contains(coalesce(s.actions, toset([])), "dlm:UntagResource") &&
        contains(coalesce(s.resources, toset([])), "arn:aws:dlm:*:*:policy/policy-*") &&
        anytrue([for c in s.condition : c.test == "StringNotEquals" && c.variable == "aws:ResourceTag/fermix-server-stack"])
      )
    ])
    error_message = "the boundary denies tagging or untagging any DLM policy that does not already carry the server tag"
  }
}

# Finding 3: ec2:* on every resource. The role's policy names each EC2 action
# and holds every one but the reads to the server stack's tag.
run "ec2_is_named_and_held_to_the_tag" {
  command = plan

  assert {
    condition = alltrue(flatten([
      for s in data.aws_iam_policy_document.deploy.statement : [
        for a in s.actions : a == "ec2:Describe*" || !strcontains(a, "*") if startswith(a, "ec2:")
      ]
    ]))
    error_message = "no EC2 action is a wildcard but the reads (ec2:Describe*)"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.deploy.statement : (
        anytrue([for c in s.condition : contains(["aws:ResourceTag/fermix-server-stack", "aws:RequestTag/fermix-server-stack"], c.variable) && c.values == tolist(["server"])]) ||
        anytrue([for c in s.condition : c.variable == "ec2:CreateAction"]) ||
        s.resources == toset(["arn:aws:ec2:us-east-1::image/*", "arn:aws:ec2:us-east-1::snapshot/*"]) ||
        (s.actions == toset(["ec2:RunInstances"]) && s.resources == toset(["arn:aws:ec2:us-east-1:111122223333:network-interface/*"]))
      ) if anytrue([for a in s.actions : startswith(a, "ec2:") && a != "ec2:Describe*"])
    ])
    error_message = "every EC2 change is held to a resource carrying the server tag, a create that applies it, the public image (and its snapshot) a launch reads, or the interface a launch creates in a tagged subnet"
  }

  # A request's own tags are the request's, not one resource's: a create that
  # names an existing VPC, subnet or security group must find it tagged.
  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.deploy.statement : (
        (!contains(s.resources, "arn:aws:ec2:us-east-1:111122223333:vpc/*") || s.actions == toset(["ec2:CreateVpc"])) &&
        (!contains(s.actions, "ec2:RunInstances") || alltrue([for r in s.resources : !strcontains(r, ":subnet/") && !strcontains(r, ":security-group/")]))
      ) if anytrue([for c in s.condition : c.variable == "aws:RequestTag/fermix-server-stack"])
    ])
    error_message = "a tag in the request alone never lets the role use an untagged VPC, subnet or security group"
  }

  # Finding 7: the launch's interface statement let a launch take an existing
  # interface. Both policies deny a launch into an existing interface, subnet
  # or security group, and a create into a VPC, without the tag; what a
  # request creates is network-interface/* and so on, which the id patterns
  # do not match.
  assert {
    condition = alltrue([
      for statements in [data.aws_iam_policy_document.deploy.statement, data.aws_iam_policy_document.boundary.statement] : anytrue([
        for s in statements : (
          s.effect == "Deny" &&
          s.actions == toset(["ec2:RunInstances", "ec2:CreateSubnet", "ec2:CreateRouteTable", "ec2:CreateSecurityGroup"]) &&
          s.resources == toset([
            "arn:aws:ec2:*:*:vpc/vpc-*",
            "arn:aws:ec2:*:*:subnet/subnet-*",
            "arn:aws:ec2:*:*:security-group/sg-*",
            "arn:aws:ec2:*:*:network-interface/eni-*",
          ]) &&
          anytrue([for c in s.condition : c.test == "StringNotEquals" && c.variable == "aws:ResourceTag/fermix-server-stack" && c.values == tolist(["server"])])
        )
      ])
    ])
    error_message = "a launch never takes an existing interface, subnet or security group, and a create never a VPC, that does not carry the server tag"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.deploy.statement : anytrue([
        for c in s.condition : c.variable == "aws:ResourceTag/fermix-server-stack" && c.values == tolist(["server"])
      ]) if s.effect != "Deny" && contains(s.actions, "ec2:RunInstances") && anytrue([for r in s.resources : strcontains(r, ":subnet/") || strcontains(r, ":security-group/") || endswith(r, ":*")])
    ])
    error_message = "a launch's subnet and security group are allowed only carrying the server tag"
  }

  # Finding 8: a launch from any image or shared snapshot. The role launches
  # only the AMI publisher's image and snapshot, and the boundary denies every
  # other owner's, and every kind of resource a launch here does not use.
  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.deploy.statement : anytrue([
        for c in s.condition : c.test == "StringEquals" && c.variable == "aws:ResourceAccount" && c.values == tolist(["136693071363"])
      ]) if s.effect != "Deny" && contains(s.actions, "ec2:RunInstances") && anytrue([for r in s.resources : strcontains(r, "::image/") || strcontains(r, "::snapshot/")])
    ])
    error_message = "the role launches only from the AMI publisher's image and snapshot (ami_owner_id)"
  }

  assert {
    condition = alltrue([
      anytrue([for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" && s.actions == toset(["ec2:RunInstances"]) &&
        s.resources == toset(["arn:aws:ec2:*::*"]) &&
        anytrue([for c in s.condition : c.test == "StringNotEquals" && c.variable == "aws:ResourceAccount" && c.values == tolist(["136693071363"])])
      )]),
      anytrue([for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" && s.actions == toset(["ec2:RunInstances"]) &&
        s.not_resources == toset([
          "arn:aws:ec2:*:*:instance/*",
          "arn:aws:ec2:*:*:volume/*",
          "arn:aws:ec2:*:*:network-interface/*",
          "arn:aws:ec2:*:*:subnet/*",
          "arn:aws:ec2:*:*:security-group/*",
          "arn:aws:ec2:*::*",
        ])
      )]),
    ])
    error_message = "the boundary denies a launch of another owner's image or snapshot, and of any kind of resource but the seven a launch here uses"
  }

  # The boundary's ceiling is EC2 in the region; these hold it to the tag
  # whatever is attached.
  assert {
    condition = alltrue([
      anytrue([for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" && s.resources == toset(["arn:aws:ec2:*:*:*"]) &&
        contains(coalesce(s.not_actions, toset([])), "ec2:Describe*") && !contains(coalesce(s.not_actions, toset([])), "ec2:TerminateInstances") &&
        anytrue([for c in s.condition : c.test == "StringNotEquals" && c.variable == "aws:ResourceTag/fermix-server-stack"])
      )]),
      anytrue([for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" && s.actions == toset(["ec2:CreateTags"]) &&
        anytrue([for c in s.condition : c.test == "Null" && c.variable == "ec2:CreateAction" && c.values == tolist(["true"])])
      )]),
    ])
    error_message = "the boundary denies changing or tagging any EC2 resource that does not carry the server tag, but in the create that makes it"
  }

  assert {
    condition = (
      alltrue([for s in data.aws_iam_policy_document.deploy.statement : !contains(s.actions, "ec2:ModifySnapshotAttribute")]) &&
      anytrue([for s in data.aws_iam_policy_document.boundary.statement : s.effect == "Deny" && s.actions == toset(["ec2:ModifySnapshotAttribute"]) && s.resources == toset(["*"])]) &&
      anytrue([for s in data.aws_iam_policy_document.workload.statement : s.effect == "Deny" && s.actions == toset(["ec2:ModifySnapshotAttribute"])])
    )
    error_message = "no snapshot is ever shared or made public: the deploy role and every server role are denied ec2:ModifySnapshotAttribute"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.actions == toset(["ec2:Describe*"]) ||
        alltrue([for r in s.resources : startswith(r, "arn:aws:ec2:us-east-1:")])
      ) if s.effect != "Deny" && anytrue([for a in s.actions : startswith(a, "ec2:")])
    ])
    error_message = "the boundary's EC2 changes are held to resources in the chosen region, and no account-wide EC2 setting is reachable"
  }
}

# Findings 4 and 5: a role the deploy role created could be given more than
# it needs, and IAM cannot hold a trust policy's contents to a condition. The
# deploy role now creates, deletes and retrusts no role: bootstrap makes both.
run "the_deploy_role_creates_or_retrusts_no_role" {
  command = plan

  assert {
    condition = alltrue(flatten([
      for s in data.aws_iam_policy_document.deploy.statement : [
        for a in s.actions : !contains([
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:UpdateRole",
          "iam:UpdateAssumeRolePolicy",
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:PutRolePermissionsBoundary",
          "iam:DeleteRolePermissionsBoundary",
          "iam:CreatePolicy",
          "iam:CreatePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:DeletePolicy",
          "iam:*",
          "*",
        ], a)
      ]
    ]))
    error_message = "the deploy role creates, deletes or retrusts no role or profile, changes no boundary and writes no managed policy"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.deploy.statement : alltrue([
        for r in s.resources : contains([
          "arn:aws:iam::111122223333:role/fermix-server/fermix-server-instance",
          "arn:aws:iam::111122223333:role/fermix-server/fermix-server-dlm",
          "arn:aws:iam::111122223333:instance-profile/fermix-server/fermix-server-instance",
        ], r)
      ]) if anytrue([for a in s.actions : startswith(a, "iam:")])
    ])
    error_message = "IAM reaches the two server roles and the instance profile bootstrap made, and nothing else"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.deploy.statement : (
        (s.resources == toset(["arn:aws:iam::111122223333:role/fermix-server/fermix-server-instance"]) &&
        anytrue([for c in s.condition : c.variable == "iam:PassedToService" && c.values == tolist(["ec2.amazonaws.com"])])) ||
        (s.resources == toset(["arn:aws:iam::111122223333:role/fermix-server/fermix-server-dlm"]) &&
        anytrue([for c in s.condition : c.variable == "iam:PassedToService" && c.values == tolist(["dlm.amazonaws.com"])]))
      ) if contains(s.actions, "iam:PassRole")
    ])
    error_message = "the instance role is passed to EC2 alone and the DLM role to DLM alone"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.deploy.statement : (
        s.resources == toset(["arn:aws:iam::111122223333:role/fermix-server/fermix-server-instance"]) &&
        anytrue([for c in s.condition : c.test == "ArnEquals" && c.variable == "iam:PolicyARN" && c.values == tolist(["arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"])])
      ) if contains(s.actions, "iam:AttachRolePolicy") || contains(s.actions, "iam:DetachRolePolicy")
    ])
    error_message = "the only policy the deploy role attaches is the CloudWatch agent's (enable_cloudwatch_agent), to the instance role"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.deploy.statement :
      s.resources == toset(["arn:aws:iam::111122223333:role/fermix-server/fermix-server-instance"])
      if contains(s.actions, "iam:PutRolePolicy") || contains(s.actions, "iam:DeleteRolePolicy")
    ])
    error_message = "an inline policy (the S3 backups' grant) goes on the instance role alone"
  }

  # Whatever else is ever attached to the deploy role, the boundary holds it.
  assert {
    condition = alltrue([
      anytrue([for s in data.aws_iam_policy_document.boundary.statement : s.effect == "Deny" && alltrue([for a in ["iam:CreateRole", "iam:DeleteRole", "iam:Update*Role*", "iam:CreateInstanceProfile", "iam:*RolePermissionsBoundary"] : contains(coalesce(s.actions, toset([])), a)]) && s.resources == toset(["*"])]),
      anytrue([for s in data.aws_iam_policy_document.boundary.statement : s.effect == "Deny" && toset(coalesce(s.actions, toset([]))) == toset(["iam:AttachRolePolicy", "iam:DetachRolePolicy"]) && anytrue([for c in s.condition : c.test == "ArnNotEquals" && c.values == tolist(["arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"])])]),
      anytrue([for s in data.aws_iam_policy_document.boundary.statement : s.effect == "Deny" && toset(coalesce(s.actions, toset([]))) == toset(["iam:PutRolePolicy", "iam:DeleteRolePolicy"]) && s.not_resources == toset(["arn:aws:iam::111122223333:role/fermix-server/fermix-server-instance"])]),
      anytrue([for s in data.aws_iam_policy_document.boundary.statement : s.effect == "Deny" && coalesce(s.actions, toset([])) == toset(["iam:PassRole"]) && anytrue([for c in s.condition : c.test == "StringNotEquals" && c.variable == "iam:PassedToService"])]),
    ])
    error_message = "the boundary denies creating, deleting or retrusting a role or profile, changing a boundary, any managed policy but the CloudWatch agent's, an inline policy off the instance role, and passing a role to anything but EC2 and DLM"
  }
}

run "the_server_roles_trust_one_service_and_stay_bounded" {
  command = plan

  assert {
    condition = (
      aws_iam_role.instance.permissions_boundary == "arn:aws:iam::111122223333:policy/fermix-server-workload-boundary" &&
      aws_iam_role.dlm.permissions_boundary == "arn:aws:iam::111122223333:policy/fermix-server-workload-boundary"
    )
    error_message = "both server roles carry the server roles' boundary"
  }

  assert {
    condition = (
      length(jsondecode(aws_iam_role.instance.assume_role_policy).Statement) == 1 &&
      jsondecode(aws_iam_role.instance.assume_role_policy).Statement[0].Effect == "Allow" &&
      jsondecode(aws_iam_role.instance.assume_role_policy).Statement[0].Action == "sts:AssumeRole" &&
      jsondecode(aws_iam_role.instance.assume_role_policy).Statement[0].Principal == { Service = "ec2.amazonaws.com" }
    )
    error_message = "the instance role trusts EC2 alone"
  }

  assert {
    condition = (
      length(jsondecode(aws_iam_role.dlm.assume_role_policy).Statement) == 1 &&
      jsondecode(aws_iam_role.dlm.assume_role_policy).Statement[0].Effect == "Allow" &&
      jsondecode(aws_iam_role.dlm.assume_role_policy).Statement[0].Action == "sts:AssumeRole" &&
      jsondecode(aws_iam_role.dlm.assume_role_policy).Statement[0].Principal == { Service = "dlm.amazonaws.com" } &&
      try(jsondecode(aws_iam_role.dlm.assume_role_policy).Statement[0].Condition, null) == { StringEquals = { "aws:SourceAccount" = "111122223333" } }
    )
    error_message = "the DLM role trusts DLM alone, for this account's policies"
  }

  assert {
    condition = (
      aws_iam_role.instance.path == "/fermix-server/" && aws_iam_role.instance.name == "fermix-server-instance" &&
      aws_iam_role.dlm.path == "/fermix-server/" && aws_iam_role.dlm.name == "fermix-server-dlm" &&
      aws_iam_instance_profile.instance.name == "fermix-server-instance" && aws_iam_instance_profile.instance.role == "fermix-server-instance" &&
      aws_iam_role_policy_attachment.instance_ssm.policy_arn == "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore" &&
      aws_iam_role_policy_attachment.dlm.policy_arn == "arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"
    )
    error_message = "bootstrap makes the roles and the profile server/ reads by name, with Session Manager's and DLM's policies"
  }

  assert {
    condition = (
      aws_iam_policy.workload.name == "fermix-server-workload-boundary" && aws_iam_policy.workload.path == "/" &&
      alltrue(flatten([for s in data.aws_iam_policy_document.workload.statement : [for a in coalesce(s.actions, toset([])) : !startswith(a, "iam:") && !startswith(a, "s3:")]]))
    )
    error_message = "the server roles' boundary is where the roles name it, and holds no IAM or S3 action: the bucket's rights live in the snapshot writer's session alone"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.workload.statement : (
        alltrue([for a in coalesce(s.actions, toset([])) : !startswith(a, "sts:")]) ||
        (s.actions == toset(["sts:AssumeRole"]) && s.resources == toset(["arn:aws:iam::111122223333:role/fermix-server/fermix-server-snapshot-writer"]))
      )
    ])
    error_message = "the only STS action the server roles' boundary allows is assuming the snapshot writer"
  }
}

# The snapshot writer: the role whose one-hour session the server's
# credentials helper hands the engine. It puts objects into the snapshot
# bucket and does nothing else, and only the instance role, while server/
# grants it, can assume it.
run "the_snapshot_writer_only_puts_into_the_bucket" {
  command = plan

  assert {
    condition = (
      aws_iam_role.snapshot_writer.name == "fermix-server-snapshot-writer" &&
      aws_iam_role.snapshot_writer.path == "/fermix-server/" &&
      aws_iam_role.snapshot_writer.max_session_duration == 3600
    )
    error_message = "the snapshot writer sits under /fermix-server/, and its session lasts an hour at most"
  }

  assert {
    condition = (
      length(jsondecode(aws_iam_role.snapshot_writer.assume_role_policy).Statement) == 1 &&
      jsondecode(aws_iam_role.snapshot_writer.assume_role_policy).Statement[0].Effect == "Allow" &&
      jsondecode(aws_iam_role.snapshot_writer.assume_role_policy).Statement[0].Action == "sts:AssumeRole" &&
      jsondecode(aws_iam_role.snapshot_writer.assume_role_policy).Statement[0].Principal == { AWS = "arn:aws:iam::111122223333:root" } &&
      jsondecode(aws_iam_role.snapshot_writer.assume_role_policy).Statement[0].Condition == { ArnEquals = { "aws:PrincipalArn" = "arn:aws:iam::111122223333:role/fermix-server/fermix-server-instance" } }
    )
    error_message = "the snapshot writer trusts the account, so the caller needs its own grant (server/'s, with enable_s3_backups), and only the instance role"
  }

  assert {
    condition = (
      aws_iam_role_policy.snapshot_writer.role == "fermix-server-snapshot-writer" &&
      length(data.aws_iam_policy_document.snapshot_writer.statement) == 2 &&
      alltrue([for s in data.aws_iam_policy_document.snapshot_writer.statement : s.effect == null || s.effect == "Allow"])
    )
    error_message = "the snapshot writer holds one inline policy of two allows"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.snapshot_writer.statement :
      s.actions == toset(["s3:PutObject"]) && s.resources == toset(["arn:aws:s3:::fermix-server-snapshots-111122223333-us-east-1/*"])
    ])
    error_message = "the snapshot writer puts objects into the snapshot bucket"
  }

  # The bucket's name is predictable and S3's names are global, so while the
  # owner's bucket does not exist another account could make one of that name.
  # The writer puts only into a bucket of this account.
  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.snapshot_writer.statement :
      anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "s3:ResourceAccount" && toset(c.values) == toset(["111122223333"])])
      if anytrue([for a in s.actions : startswith(a, "s3:")])
    ])
    error_message = "every S3 right of the snapshot writer is held to a bucket of the owner's account (s3:ResourceAccount)"
  }

  assert {
    condition = alltrue(flatten([
      for s in data.aws_iam_policy_document.snapshot_writer.statement : [
        for a in coalesce(s.actions, toset([])) : contains(["s3:PutObject", "kms:GenerateDataKey"], a)
      ]
    ]))
    error_message = "the snapshot writer cannot read, list or delete an object, or do anything else"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.snapshot_writer.statement :
      s.actions == toset(["kms:GenerateDataKey"]) &&
      s.resources == toset(["arn:aws:kms:us-east-1:111122223333:key/*"]) &&
      anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "kms:ViaService" && toset(c.values) == toset(["s3.us-east-1.amazonaws.com"])]) &&
      anytrue([for c in s.condition : c.test == "StringLike" && c.variable == "kms:EncryptionContext:aws:s3:arn" && toset(c.values) == toset(["arn:aws:s3:::fermix-server-snapshots-111122223333-us-east-1", "arn:aws:s3:::fermix-server-snapshots-111122223333-us-east-1/*"])])
    ])
    error_message = "the snapshot writer uses a key only through S3 in the region, for the snapshot bucket alone"
  }

  assert {
    condition     = aws_iam_role.snapshot_writer.permissions_boundary == null
    error_message = "bootstrap alone writes the snapshot writer: the deploy role's boundary refuses every IAM write on it"
  }
}

# Finding 6: the DLM role's boundary allowed snapshots of, and deleting, any
# volume's snapshots.
run "dlm_snapshots_only_the_server_stack" {
  command = plan

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.workload.statement : (
        (alltrue([for r in s.resources : startswith(r, "arn:aws:ec2:us-east-1:111122223333:volume/") || startswith(r, "arn:aws:ec2:us-east-1:111122223333:instance/")]) &&
        anytrue([for c in s.condition : c.variable == "aws:ResourceTag/fermix-server-stack" && c.values == tolist(["server"])])) ||
        (s.resources == toset(["arn:aws:ec2:us-east-1::snapshot/*"]) &&
        anytrue([for c in s.condition : c.variable == "aws:RequestTag/fermix-server-stack" && c.values == tolist(["server"])]))
      ) if contains(coalesce(s.actions, toset([])), "ec2:CreateSnapshot") || contains(coalesce(s.actions, toset([])), "ec2:CreateSnapshots")
    ])
    error_message = "DLM snapshots only a volume carrying the server tag, and only into a snapshot carrying it"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.workload.statement : (
        s.resources == toset(["arn:aws:ec2:us-east-1::snapshot/*"]) &&
        anytrue([for c in s.condition : c.variable == "aws:ResourceTag/fermix-server-stack" && c.values == tolist(["server"])])
      ) if contains(coalesce(s.actions, toset([])), "ec2:DeleteSnapshot")
    ])
    error_message = "DLM deletes only a snapshot carrying the server tag"
  }

  assert {
    condition = alltrue(flatten([
      for s in data.aws_iam_policy_document.workload.statement : [
        for a in coalesce(s.actions, toset([])) : startswith(a, "ec2:Describe")
      ] if s.effect != "Deny" && s.resources == toset(["*"]) && anytrue([for a in coalesce(s.actions, toset([])) : startswith(a, "ec2:")])
    ]))
    error_message = "no EC2 action but a read is allowed to a server role on every resource"
  }
}

run "the_policy_stays_inside_what_server_needs" {
  command = plan

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.deploy.statement : anytrue([
        for c in s.condition : c.variable == "aws:RequestedRegion" && c.values == tolist(["us-east-1"])
      ]) if contains(s.actions, "ec2:Describe*")
    ])
    error_message = "EC2 reads are held to the chosen region"
  }

  # S3: server/'s state object and lock, and the snapshot bucket by its exact
  # name; nothing reaches bootstrap's own state or another bucket.
  assert {
    condition = alltrue(flatten([
      for s in data.aws_iam_policy_document.deploy.statement : [
        for r in s.resources : contains([
          "arn:aws:s3:::fermix-server-state-111122223333-us-east-1",
          "arn:aws:s3:::fermix-server-state-111122223333-us-east-1/server/terraform.tfstate",
          "arn:aws:s3:::fermix-server-state-111122223333-us-east-1/server/terraform.tfstate.tflock",
          "arn:aws:s3:::fermix-server-snapshots-111122223333-us-east-1",
          "arn:aws:s3:::fermix-server-snapshots-111122223333-us-east-1/*",
        ], r)
      ] if anytrue([for a in s.actions : startswith(a, "s3:")])
    ]))
    error_message = "S3 reaches server/'s state and the snapshot bucket, by exact name"
  }

  # KMS keys, SNS topics and DLM policies only while they carry the server
  # stack's tag (on create, in the request).
  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.deploy.statement : anytrue([
        for c in s.condition : contains(["aws:ResourceTag/fermix-server-stack", "aws:RequestTag/fermix-server-stack"], c.variable) && c.values == tolist(["server"])
      ]) if contains(["CreateServerKeys", "ManageAndUseServerKeys", "GrantServerKeysToEbs", "CreateTheAlertTopic", "ManageTheAlertTopic", "CreateTheSnapshotPolicy", "ManageTheSnapshotPolicy", "CreateTheAlarmAndBudget", "ManageTheAlarmAndBudget"], s.sid)
    ])
    error_message = "KMS keys, SNS topics, DLM policies, the alarm and the budget are managed only with the server stack's tag"
  }

  # Session Manager runs with the owner's own sign-in, never this role.
  assert {
    condition = alltrue(flatten([
      for statements in [data.aws_iam_policy_document.deploy.statement, data.aws_iam_policy_document.boundary.statement] : [
        for s in statements : [for a in coalesce(s.actions, toset([])) : !startswith(a, "ssm:StartSession") && !startswith(a, "ssm:SendCommand") && !startswith(a, "ssmmessages:")]
      ]
    ]))
    error_message = "the deploy role opens no session and runs no command on the server"
  }

  # The account's alerting is the owner's (trail.tf, alerts.tf, guardduty.tf):
  # the deploy role cannot stop the trail, the rules or the detector, resume a
  # session, or reach any of it through a wildcard.
  assert {
    condition = alltrue(flatten([
      for statements in [data.aws_iam_policy_document.deploy.statement, data.aws_iam_policy_document.boundary.statement] : [
        for s in statements : [
          for a in coalesce(s.actions, toset([])) : !anytrue([for p in ["*", "ssm:*", "ssm:ResumeSession", "cloudtrail:", "events:", "guardduty:"] : startswith(a, p)])
        ]
      ]
    ]))
    error_message = "the deploy role reaches no trail, rule or detector, resumes no session, and holds no wildcard over SSM"
  }

  # The security alert topic and its key (alerts.tf), by ARN match: each
  # resource pattern is made a regular expression ("." literal, "*" any).
  assert {
    condition = alltrue(flatten([
      for statements in [data.aws_iam_policy_document.deploy.statement, data.aws_iam_policy_document.boundary.statement] : [
        for s in statements : [
          for r in coalesce(s.resources, toset([])) : !can(regex("^${replace(replace(r, ".", "\\."), "*", ".*")}$", "arn:aws:sns:us-east-1:111122223333:fermix-owner-security-alerts"))
        ] if s.effect != "Deny" && anytrue([for a in coalesce(s.actions, toset([])) : startswith(a, "sns:")])
      ]
    ]))
    error_message = "no SNS grant of the deploy role, in its policy or its boundary, reaches the security alert topic"
  }

  # Every KMS grant that matches the security alert key or its alias needs
  # the server tag, which that key never carries (listing aliases aside). The
  # state key's statements name the state key alone and a plan cannot list it.
  assert {
    condition = alltrue(flatten([
      for statements in [data.aws_iam_policy_document.deploy.statement, data.aws_iam_policy_document.boundary.statement] : [
        for s in statements : (
          coalesce(s.actions, toset([])) == toset(["kms:ListAliases"]) ||
          anytrue([for c in s.condition : contains(["aws:ResourceTag/fermix-server-stack", "aws:RequestTag/fermix-server-stack"], c.variable) && c.values == tolist(["server"])])
        ) if s.effect != "Deny" && s.sid != "UseTheStateKey" && !contains(coalesce(s.actions, toset([])), "s3:GetObject") &&
        anytrue([for a in coalesce(s.actions, toset([])) : startswith(a, "kms:")]) && anytrue(flatten([
          for r in coalesce(s.resources, toset([])) : [
            for arn in ["arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000", "arn:aws:kms:us-east-1:111122223333:alias/fermix-owner-security-alerts"] :
            can(regex("^${replace(replace(r, ".", "\\."), "*", ".*")}$", arn))
          ]
        ]))
      ]
    ]))
    error_message = "no KMS grant of the deploy role reaches the security alert key or its alias without the server tag"
  }
}

# The whole-boundary pass (bootstrap/POLICY.md): outside EC2, IAM, S3 and the
# public parameters, every service the boundary allows is held to the server
# stack's tag, in the request on create or on the resource after; the only
# exceptions are a subscription's three actions (a subscription has no tags)
# and the alias actions (authorized on the key too, which is held to the tag).
run "the_boundary_holds_every_service_to_the_tag" {
  command = plan

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        anytrue([for c in s.condition : contains(["aws:RequestTag/fermix-server-stack", "aws:ResourceTag/fermix-server-stack"], c.variable) && c.test == "StringEquals" && c.values == tolist(["server"])]) ||
        s.actions == toset(["sns:GetSubscriptionAttributes", "sns:SetSubscriptionAttributes", "sns:Unsubscribe"]) ||
        s.actions == toset(["kms:CreateAlias", "kms:DeleteAlias", "kms:UpdateAlias"]) ||
        s.actions == toset(["kms:ListAliases"]) ||
        s.actions == toset(["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "s3:ListBucket", "s3:GetObject", "s3:PutObject", "s3:DeleteObject"])
      ) if s.effect != "Deny" && anytrue([for a in coalesce(s.actions, toset([])) : anytrue([for svc in ["kms:", "sns:", "dlm:", "cloudwatch:", "budgets:"] : startswith(a, svc)])])
    ])
    error_message = "the boundary holds KMS, SNS, DLM, CloudWatch and Budgets to the server stack's tag, but a subscription's actions and the alias actions"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.boundary.statement : alltrue([
        for r in s.resources : contains([
          "arn:aws:s3:::fermix-server-state-111122223333-us-east-1",
          "arn:aws:s3:::fermix-server-state-111122223333-us-east-1/server/terraform.tfstate",
          "arn:aws:s3:::fermix-server-state-111122223333-us-east-1/server/terraform.tfstate.tflock",
          "arn:aws:s3:::fermix-server-snapshots-111122223333-us-east-1",
          "arn:aws:s3:::fermix-server-snapshots-111122223333-us-east-1/*",
        ], r)
      ]) if s.effect != "Deny" && anytrue([for a in coalesce(s.actions, toset([])) : startswith(a, "s3:")]) && !contains(coalesce(s.actions, toset([])), "kms:Decrypt")
    ])
    error_message = "the boundary's S3 reaches the snapshot bucket by exact name (the state statement, which also names the state key, a plan cannot list)"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.boundary.statement : alltrue([
        for r in s.resources : contains([
          "arn:aws:iam::111122223333:role/fermix-server/fermix-server-instance",
          "arn:aws:iam::111122223333:role/fermix-server/fermix-server-dlm",
          "arn:aws:iam::111122223333:instance-profile/fermix-server/fermix-server-instance",
        ], r)
      ]) if s.effect != "Deny" && anytrue([for a in coalesce(s.actions, toset([])) : startswith(a, "iam:")])
    ])
    error_message = "the boundary's IAM reaches the two server roles and the instance profile and nothing else"
  }
}

run "the_state_bucket_is_locked_down" {
  command = plan

  assert {
    condition     = aws_s3_bucket.state.bucket == "fermix-server-state-111122223333-us-east-1"
    error_message = "the state bucket's name is the one the backend output names"
  }

  assert {
    condition = (
      one(aws_s3_bucket_server_side_encryption_configuration.state.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms" &&
      aws_kms_key.state.enable_key_rotation == true &&
      aws_kms_key.state.deletion_window_in_days == 30
    )
    error_message = "the state bucket is encrypted with KMS (its own key, which rotates and has a 30-day deletion window)"
  }

  assert {
    condition = (
      aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled" &&
      aws_s3_bucket_public_access_block.state.block_public_acls &&
      aws_s3_bucket_public_access_block.state.block_public_policy &&
      aws_s3_bucket_public_access_block.state.ignore_public_acls &&
      aws_s3_bucket_public_access_block.state.restrict_public_buckets
    )
    error_message = "the state bucket keeps versions and blocks all public access"
  }

  assert {
    condition = (
      data.aws_iam_policy_document.state_bucket.statement[0].effect == "Deny" &&
      one(data.aws_iam_policy_document.state_bucket.statement[0].condition).variable == "aws:SecureTransport" &&
      one(data.aws_iam_policy_document.state_bucket.statement[0].condition).values == tolist(["false"])
    )
    error_message = "the state bucket refuses every request without TLS"
  }
}

# bootstrap's own state lives in the state bucket under its own key, which no
# S3 statement the deploy role holds reaches.
run "the_deploy_role_never_reaches_bootstraps_state" {
  command = plan

  assert {
    condition = local.bootstrap_state_key == "bootstrap/terraform.tfstate" && alltrue(flatten([
      for s in data.aws_iam_policy_document.deploy.statement : [
        for r in s.resources : !startswith("arn:aws:s3:::fermix-server-state-111122223333-us-east-1/${local.bootstrap_state_key}", trimsuffix(r, "*"))
      ] if anytrue([for a in s.actions : startswith(a, "s3:")]) && !contains(s.actions, "s3:ListBucket")
    ]))
    error_message = "no object pattern the deploy role may read or write matches bootstrap's own state"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" && coalesce(s.actions, toset([])) == toset(["s3:*"]) &&
        coalesce(s.resources, toset([])) == toset(["arn:aws:s3:::fermix-server-state-111122223333-us-east-1/bootstrap/terraform.tfstate*"])
      )
    ])
    error_message = "the boundary denies every S3 action on bootstrap's own state and its lock"
  }
}

run "names_the_server_stack_uses" {
  command = plan

  assert {
    condition = (
      local.snapshot_bucket == "fermix-server-snapshots-111122223333-us-east-1" &&
      local.iam_path == "/fermix-server/" &&
      local.server_key == "alias/fermix-server" &&
      local.stack_tag_key == "fermix-server-stack" &&
      local.server_tag == "server" &&
      local.stack_tags == { "fermix-server-stack" = "bootstrap" } &&
      local.workload_boundary_arn == "arn:aws:iam::111122223333:policy/fermix-server-workload-boundary" &&
      local.instance_role == "fermix-server-instance" &&
      local.dlm_role == "fermix-server-dlm" &&
      local.snapshot_writer_role_arn == "arn:aws:iam::111122223333:role/fermix-server/fermix-server-snapshot-writer" &&
      var.ami_owner_id == "136693071363"
    )
    error_message = "the names, path, tags and boundary modules/server uses (its tests pin the same)"
  }
}
