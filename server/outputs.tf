output "instance_id" {
  description = "The server's instance id."
  value       = module.server.instance_id
}

output "region" {
  description = "The server's region."
  value       = module.server.region
}

output "session_command" {
  description = "Opens a shell on the server; run it with the owner's own sign-in, then paste the command Always On shows."
  value       = module.server.session_command
}

output "snapshot_bucket" {
  description = "The snapshot bucket's name; null without enable_s3_backups."
  value       = module.server.snapshot_bucket
}

output "snapshot_bucket_region" {
  description = "The snapshot bucket's region; null without enable_s3_backups."
  value       = module.server.snapshot_bucket_region
}
