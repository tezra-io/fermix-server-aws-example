locals {
  partition  = split(":", var.admin_role_arn)[1]
  account_id = split(":", var.admin_role_arn)[4]

  # The two stacks carry one tag key with different values, so the deploy role
  # can manage what server/ made and never what bootstrap made, and "nothing
  # tagged remains" after a destroy means the server stack's resources alone.
  stack_tag_key = "fermix-server-stack"
  stack_tags    = { (local.stack_tag_key) = "bootstrap" }
  server_tag    = "server"

  # CHANGE ME only if S3 says this name is taken: bucket names are global; this one carries your account id and region.
  state_bucket        = "fermix-server-state-${local.account_id}-${var.region}"
  state_key           = "server/terraform.tfstate"
  bootstrap_state_key = "bootstrap/terraform.tfstate" # versions.tf's backend key

  # Names modules/server uses. The deploy role is scoped by them because
  # server/ creates those resources later; both stacks' tests pin them.
  iam_path      = "/fermix-server/"
  instance_role = "fermix-server-instance"
  dlm_role      = "fermix-server-dlm"
  # The snapshot writer: the role whose session the server's credentials
  # helper hands Fermix (server_roles.tf); server/ grants the instance role
  # the right to assume it with enable_s3_backups.
  snapshot_writer_role = "fermix-server-snapshot-writer"
  # CHANGE ME only if S3 says this name is taken: change it with modules/server/locals.tf and the tests that pin it.
  snapshot_bucket = "fermix-server-snapshots-${local.account_id}-${var.region}"
  server_key      = "alias/fermix-server"
  name_prefix     = "fermix-server"

  # By their ARNs, which a plan already knows (server_roles.tf makes them).
  instance_role_arn        = "arn:${local.partition}:iam::${local.account_id}:role${local.iam_path}${local.instance_role}"
  dlm_role_arn             = "arn:${local.partition}:iam::${local.account_id}:role${local.iam_path}${local.dlm_role}"
  instance_profile_arn     = "arn:${local.partition}:iam::${local.account_id}:instance-profile${local.iam_path}${local.instance_role}"
  snapshot_writer_role_arn = "arn:${local.partition}:iam::${local.account_id}:role${local.iam_path}${local.snapshot_writer_role}"

  # The managed policies the server roles hold. bootstrap attaches the first
  # and the last; server/ attaches only the CloudWatch agent's, with
  # enable_cloudwatch_agent.
  ssm_core_policy         = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
  cloudwatch_agent_policy = "arn:${local.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
  dlm_service_policy      = "arn:${local.partition}:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"
}
