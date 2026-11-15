# The deploy role: every plan and apply of server/ runs as it, from the
# owner's computer. Only the role the owner signs in with may assume it. Its
# policy is permissions.tf, its boundary boundary.tf. It sits at the IAM root
# path, outside /fermix-server/ where its own IAM rights stop, so it can never
# change itself.

resource "aws_iam_role" "deploy" {
  name                 = "fermix-server-deploy"
  path                 = "/"
  description          = "Plans and applies fermix-server-aws server/; assumed by the owner's own sign-in only."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  permissions_boundary = local.deploy_boundary_arn
  max_session_duration = 3600

  # The server roles' boundary exists before the role can create a role with it.
  depends_on = [aws_iam_policy.boundary, aws_iam_policy.workload]
}

data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "TheOwnersSignInOnly"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.admin_role_arn]
    }
  }
}
