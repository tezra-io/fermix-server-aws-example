output "deploy_role_arn" {
  description = "server/'s deploy_role_arn: the role every plan and apply of server/ assumes."
  value       = aws_iam_role.deploy.arn
}

output "server_backend" {
  description = "Paste into server/backend.s3.tfbackend (gitignored), then `terraform -chdir=server init -backend-config=backend.s3.tfbackend`. The other half (key, encrypt, use_lockfile) is in server/versions.tf; the state is read and written as the deploy role."
  value       = <<-EOT
    bucket     = "${aws_s3_bucket.state.bucket}"
    region     = "${var.region}"
    kms_key_id = "${aws_kms_key.state.arn}"
    assume_role = {
      role_arn = "${aws_iam_role.deploy.arn}"
    }
  EOT
}

output "bootstrap_backend" {
  description = "bootstrap's own backend, after its first apply: `terraform -chdir=bootstrap output -raw bootstrap_backend > bootstrap/backend.s3.tfbackend`, then `terraform -chdir=bootstrap init -migrate-state -backend-config=backend.s3.tfbackend`. Read and written with the owner's sign-in."
  value       = <<-EOT
    bucket     = "${aws_s3_bucket.state.bucket}"
    region     = "${var.region}"
    kms_key_id = "${aws_kms_key.state.arn}"
  EOT
}

output "state_bucket" {
  description = "The state bucket's name."
  value       = aws_s3_bucket.state.bucket
}

output "state_key_arn" {
  description = "The state bucket's key."
  value       = aws_kms_key.state.arn
}

output "workload_boundary_arn" {
  description = "The boundary every role server/ creates must carry."
  value       = aws_iam_policy.workload.arn
}

output "deploy_boundary_arn" {
  description = "The deploy role's permissions boundary."
  value       = aws_iam_policy.boundary.arn
}

output "server_roles" {
  description = "The two roles and the instance profile server/ reads by name."
  value = {
    instance_role    = aws_iam_role.instance.arn
    instance_profile = aws_iam_instance_profile.instance.arn
    dlm_role         = aws_iam_role.dlm.arn
  }
}
