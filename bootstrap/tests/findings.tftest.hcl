# A security review of the deploy role's boundary found the eleven gaps
# numbered below. Each is held here on the boundary's own policy document
# (and, for finding 6, on the server roles' boundary): the action, the
# resource and the condition that closed it. Whatever else is ever attached to
# the deploy role, these hold. Removing any one fails its assertion.
#   terraform -chdir=bootstrap test -filter=tests/findings.tftest.hcl
#
# Mocked provider and a plan, as tests/bootstrap.tftest.hcl. Assertions iterate
# statement lists, never whole data sources (a failing assertion over a whole
# object crashes Terraform 1.16.6's test output), and coalesce a statement's
# actions or resources, which are null where it names not_actions or
# not_resources.

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

run "every_finding_holds_in_the_boundary" {
  command = plan

  # 1. KMS tag takeover: no key that lacks the tag can be given it.
  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        contains(coalesce(s.actions, toset([])), "kms:TagResource") && contains(coalesce(s.actions, toset([])), "kms:UntagResource") &&
        contains(coalesce(s.resources, toset([])), "arn:aws:kms:*:*:key/*") &&
        anytrue([for c in s.condition : c.test == "StringNotEquals" && c.variable == "aws:ResourceTag/fermix-server-stack" && c.values == tolist(["server"])])
      )
    ])
    error_message = "finding 1: the boundary denies kms:TagResource and kms:UntagResource on any key without the server tag"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.resources == toset(["*"]) &&
        anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "aws:RequestTag/fermix-server-stack" && c.values == tolist(["server"])]) &&
        anytrue([for c in s.condition : c.test == "StringEquals" && c.variable == "aws:RequestedRegion" && c.values == tolist(["us-east-1"])])
      ) if s.effect != "Deny" && contains(coalesce(s.actions, toset([])), "kms:CreateKey")
    ])
    error_message = "finding 1: the boundary allows kms:CreateKey only with the server tag in the request, in the chosen region"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        coalesce(s.not_actions, toset([])) == toset(["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]) &&
        length(s.resources) == 1
      )
    ])
    error_message = "finding 1: the boundary denies everything on the state key but the state's own encryption"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        coalesce(s.not_actions, toset([])) == toset(["s3:ListBucket", "s3:GetObject", "s3:PutObject", "s3:DeleteObject"]) &&
        coalesce(s.resources, toset([])) == toset(["arn:aws:s3:::fermix-server-state-111122223333-us-east-1", "arn:aws:s3:::fermix-server-state-111122223333-us-east-1/*"])
      )
    ])
    error_message = "finding 1: the boundary denies every change to the state bucket itself"
  }

  # 2. DLM tag takeover.
  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        contains(coalesce(s.actions, toset([])), "dlm:TagResource") && contains(coalesce(s.actions, toset([])), "dlm:UntagResource") &&
        contains(coalesce(s.resources, toset([])), "arn:aws:dlm:*:*:policy/policy-*") &&
        anytrue([for c in s.condition : c.test == "StringNotEquals" && c.variable == "aws:ResourceTag/fermix-server-stack" && c.values == tolist(["server"])])
      )
    ])
    error_message = "finding 2: the boundary denies dlm:TagResource and dlm:UntagResource on any DLM policy without the server tag"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.boundary.statement : anytrue([
        for c in s.condition : c.test == "StringEquals" && c.variable == "aws:RequestTag/fermix-server-stack" && c.values == tolist(["server"])
      ]) if s.effect != "Deny" && contains(coalesce(s.actions, toset([])), "dlm:CreateLifecyclePolicy")
    ])
    error_message = "finding 2: the boundary allows dlm:CreateLifecyclePolicy only with the server tag in the request"
  }

  # 3. ec2:* on every resource.
  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.resources == toset(["arn:aws:ec2:us-east-1:*"])
      ) if s.effect != "Deny" && contains(coalesce(s.actions, toset([])), "ec2:*")
    ])
    error_message = "finding 3: the boundary's ec2:* reaches only resources in the chosen region, nothing that names no resource"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        coalesce(s.resources, toset([])) == toset(["arn:aws:ec2:*:*:*"]) &&
        coalesce(s.not_actions, toset([])) == toset(["ec2:Describe*", "ec2:RunInstances", "ec2:CreateVpc", "ec2:CreateSubnet", "ec2:CreateRouteTable", "ec2:CreateSecurityGroup", "ec2:CreateInternetGateway", "ec2:CreateTags"]) &&
        anytrue([for c in s.condition : c.test == "StringNotEquals" && c.variable == "aws:ResourceTag/fermix-server-stack" && c.values == tolist(["server"])])
      )
    ])
    error_message = "finding 3: the boundary denies every EC2 action but the reads and the six creates on a resource without the server tag"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        coalesce(s.actions, toset([])) == toset(["ec2:CreateTags"]) &&
        anytrue([for c in s.condition : c.test == "Null" && c.variable == "ec2:CreateAction" && c.values == tolist(["true"])]) &&
        anytrue([for c in s.condition : c.test == "StringNotEquals" && c.variable == "aws:ResourceTag/fermix-server-stack"])
      )
    ])
    error_message = "finding 3: the boundary denies ec2:CreateTags on an untagged resource outside a create"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" && coalesce(s.actions, toset([])) == toset(["ec2:ModifySnapshotAttribute"]) && coalesce(s.resources, toset([])) == toset(["*"])
      )
    ])
    error_message = "finding 3: the boundary denies ec2:ModifySnapshotAttribute everywhere"
  }

  # 4. A role kept bounded, given no other policy, and passed only to EC2 and DLM.
  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        contains(coalesce(s.actions, toset([])), "iam:*RolePermissionsBoundary") &&
        coalesce(s.resources, toset([])) == toset(["*"])
      )
    ])
    error_message = "finding 4: the boundary denies putting or deleting any role's permissions boundary"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        coalesce(s.actions, toset([])) == toset(["iam:AttachRolePolicy", "iam:DetachRolePolicy"]) &&
        anytrue([for c in s.condition : c.test == "ArnNotEquals" && c.variable == "iam:PolicyARN" && c.values == tolist(["arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"])])
      )
    ])
    error_message = "finding 4: the boundary denies attaching or detaching any managed policy but the CloudWatch agent's"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        coalesce(s.actions, toset([])) == toset(["iam:PutRolePolicy", "iam:DeleteRolePolicy"]) &&
        coalesce(s.not_resources, toset([])) == toset(["arn:aws:iam::111122223333:role/fermix-server/fermix-server-instance"])
      )
    ])
    error_message = "finding 4: the boundary denies an inline policy on any role but the instance role"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        coalesce(s.actions, toset([])) == toset(["iam:PassRole"]) &&
        anytrue([for c in s.condition : c.test == "StringNotEquals" && c.variable == "iam:PassedToService" && toset(c.values) == toset(["ec2.amazonaws.com", "dlm.amazonaws.com"])])
      )
    ])
    error_message = "finding 4: the boundary denies passing a role to anything but EC2 and DLM"
  }

  # 5. A trust written at CreateRole: no role or instance profile created,
  # deleted or retrusted, and IAM only on bootstrap's three.
  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        alltrue([for a in ["iam:CreateRole", "iam:DeleteRole", "iam:Update*Role*", "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile", "iam:*RoleToInstanceProfile", "iam:*RoleFromInstanceProfile"] : contains(coalesce(s.actions, toset([])), a)]) &&
        coalesce(s.resources, toset([])) == toset(["*"])
      )
    ])
    error_message = "finding 5: the boundary denies creating, deleting or retrusting a role, and creating, deleting or refilling an instance profile"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        coalesce(s.resources, toset([])) == toset([
          "arn:aws:iam::111122223333:role/fermix-server/fermix-server-instance",
          "arn:aws:iam::111122223333:role/fermix-server/fermix-server-dlm",
          "arn:aws:iam::111122223333:instance-profile/fermix-server/fermix-server-instance",
        ])
      ) if s.effect != "Deny" && anytrue([for a in coalesce(s.actions, toset([])) : startswith(a, "iam:")])
    ])
    error_message = "finding 5: the boundary's IAM reaches bootstrap's two roles and the instance profile alone"
  }

  # 6. The DLM role snapshots and deletes only the server stack's.
  assert {
    condition = alltrue([
      anytrue([for s in data.aws_iam_policy_document.workload.statement : (
        coalesce(s.actions, toset([])) == toset(["ec2:CreateSnapshot", "ec2:CreateSnapshots"]) &&
        coalesce(s.resources, toset([])) == toset(["arn:aws:ec2:us-east-1:111122223333:volume/*", "arn:aws:ec2:us-east-1:111122223333:instance/*"]) &&
        anytrue([for c in s.condition : c.variable == "aws:ResourceTag/fermix-server-stack" && c.values == tolist(["server"])])
      )]),
      anytrue([for s in data.aws_iam_policy_document.workload.statement : (
        coalesce(s.actions, toset([])) == toset(["ec2:CreateSnapshot", "ec2:CreateSnapshots"]) &&
        coalesce(s.resources, toset([])) == toset(["arn:aws:ec2:us-east-1::snapshot/*"]) &&
        anytrue([for c in s.condition : c.variable == "aws:RequestTag/fermix-server-stack" && c.values == tolist(["server"])])
      )]),
      anytrue([for s in data.aws_iam_policy_document.workload.statement : (
        coalesce(s.actions, toset([])) == toset(["ec2:DeleteSnapshot"]) &&
        coalesce(s.resources, toset([])) == toset(["arn:aws:ec2:us-east-1::snapshot/*"]) &&
        anytrue([for c in s.condition : c.variable == "aws:ResourceTag/fermix-server-stack" && c.values == tolist(["server"])])
      )]),
    ])
    error_message = "finding 6: the server roles' boundary snapshots only tagged volumes into tagged snapshots, and deletes only tagged snapshots"
  }

  # 7. A launch into an existing interface, subnet or security group, or a
  # create into a VPC, that lacks the tag.
  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        coalesce(s.actions, toset([])) == toset(["ec2:RunInstances", "ec2:CreateSubnet", "ec2:CreateRouteTable", "ec2:CreateSecurityGroup"]) &&
        coalesce(s.resources, toset([])) == toset(["arn:aws:ec2:*:*:vpc/vpc-*", "arn:aws:ec2:*:*:subnet/subnet-*", "arn:aws:ec2:*:*:security-group/sg-*", "arn:aws:ec2:*:*:network-interface/eni-*"]) &&
        anytrue([for c in s.condition : c.test == "StringNotEquals" && c.variable == "aws:ResourceTag/fermix-server-stack" && c.values == tolist(["server"])])
      )
    ])
    error_message = "finding 7: the boundary denies a launch or create into an existing interface, subnet, security group or VPC without the server tag"
  }

  # 8. A launch from any image or snapshot, or of any other resource type.
  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        coalesce(s.actions, toset([])) == toset(["ec2:RunInstances"]) &&
        coalesce(s.resources, toset([])) == toset(["arn:aws:ec2:*::*"]) &&
        anytrue([for c in s.condition : c.test == "StringNotEquals" && c.variable == "aws:ResourceAccount" && c.values == tolist(["136693071363"])])
      )
    ])
    error_message = "finding 8: the boundary denies a launch from an image or snapshot of any account but ami_owner_id"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        coalesce(s.actions, toset([])) == toset(["ec2:RunInstances"]) &&
        coalesce(s.not_resources, toset([])) == toset([
          "arn:aws:ec2:*:*:instance/*",
          "arn:aws:ec2:*:*:volume/*",
          "arn:aws:ec2:*:*:network-interface/*",
          "arn:aws:ec2:*:*:subnet/*",
          "arn:aws:ec2:*:*:security-group/*",
          "arn:aws:ec2:*::*",
        ])
      )
    ])
    error_message = "finding 8: the boundary denies a launch of any resource type but the instance, volume, interface, subnet, security group, image and snapshot"
  }

  # 9. A create or tag that writes any tag key but the stack's (and Name, on
  # EC2).
  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.boundary.statement : anytrue([
        for c in s.condition : c.test == "ForAllValues:StringEquals" && c.variable == "aws:TagKeys" && length(setsubtract(toset(c.values), toset(["fermix-server-stack", "Name"]))) == 0
        ]) if s.effect != "Deny" && length(setintersection(coalesce(s.actions, toset([])), toset([
          "kms:CreateKey", "kms:TagResource", "kms:*",
          "sns:CreateTopic", "sns:TagResource", "sns:*",
          "dlm:CreateLifecyclePolicy", "dlm:TagResource", "dlm:*",
          "cloudwatch:PutMetricAlarm", "cloudwatch:TagResource", "cloudwatch:*",
          "budgets:ModifyBudget", "budgets:TagResource", "budgets:*",
          "ec2:*", "ec2:CreateTags",
      ]))) > 0
    ])
    error_message = "finding 9: every boundary statement that creates or tags holds the tag keys to the stack's (and Name)"
  }

  # 10. KMS aliases on every resource.
  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        coalesce(s.resources, toset([])) == toset(["arn:aws:kms:us-east-1:111122223333:alias/fermix-server"])
      ) if s.effect != "Deny" && length(setintersection(coalesce(s.actions, toset([])), toset(["kms:CreateAlias", "kms:DeleteAlias", "kms:UpdateAlias"]))) > 0
    ])
    error_message = "finding 10: the boundary allows creating, moving or deleting an alias only on alias/fermix-server"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        coalesce(s.actions, toset([])) == toset(["kms:ListAliases"]) && coalesce(s.resources, toset([])) == toset(["*"])
      ) if s.effect != "Deny" && contains(coalesce(s.actions, toset([])), "kms:ListAliases")
    ])
    error_message = "finding 10: kms:ListAliases has its own statement on every resource, with no other action"
  }

  # 11. SNS in the shared statement on every resource.
  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        !contains(coalesce(s.resources, toset([])), "*")
      ) if s.effect != "Deny" && length(setintersection(coalesce(s.actions, toset([])), toset(["sns:CreateTopic", "sns:TagResource", "sns:*"]))) > 0
    ])
    error_message = "finding 11: the boundary allows sns:CreateTopic and sns:TagResource only on topics named fermix-server-*"
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.boundary.statement : (
        s.effect == "Deny" &&
        contains(coalesce(s.actions, toset([])), "sns:TagResource") && contains(coalesce(s.actions, toset([])), "sns:UntagResource") &&
        anytrue([for r in coalesce(s.resources, toset([])) : startswith(r, "arn:aws:sns:")]) &&
        anytrue([for c in s.condition : c.test == "StringNotEquals" && c.variable == "aws:ResourceTag/fermix-server-stack" && c.values == tolist(["server"])])
      )
    ])
    error_message = "finding 11: the boundary denies sns:TagResource and sns:UntagResource on a topic without the server tag"
  }
}
