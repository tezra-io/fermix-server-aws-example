output "instance_id" {
  description = "The server's instance id."
  value       = aws_instance.server.id
}

output "region" {
  description = "The server's region."
  value       = local.region
}

output "session_command" {
  description = "Opens a shell on the server through Session Manager, with the owner's own sign-in (not the deploy role)."
  value       = "aws ssm start-session --target ${aws_instance.server.id} --region ${local.region}"
}

output "snapshot_bucket" {
  description = "The snapshot bucket's name, which the user data hands Fermix's first boot; null without enable_s3_backups."
  value       = one(aws_s3_bucket.snapshots[*].bucket)
}

output "snapshot_bucket_region" {
  description = "The snapshot bucket's region; null without enable_s3_backups."
  value       = var.enable_s3_backups ? local.region : null
}
