# One Always On server (README.md). The caller's aws provider decides the
# region and runs as the deploy role bootstrap created. server/ passes every
# variable here, so the defaults that apply are server/variables.tf's: set
# your values in server/terraform.tfvars.

variable "instance_type" {
  description = "The instance type. Graviton only: the AMI is Debian 13 arm64."
  type        = string
  default     = "t4g.small"

  validation {
    condition     = can(regex("^(t4g|m7g|c7g|r7g|m8g|c8g|r8g)\\.[a-z0-9]+$", var.instance_type))
    error_message = "instance_type must be a Graviton type (t4g, m7g, c7g, r7g, m8g, c8g or r8g); the AMI is arm64."
  }
}

variable "root_volume_gb" {
  description = "The encrypted gp3 root volume's size in GB. It holds the Fermix home."
  type        = number
  default     = 20

  validation {
    condition     = var.root_volume_gb == floor(var.root_volume_gb) && var.root_volume_gb >= 8 && var.root_volume_gb <= 1024
    error_message = "root_volume_gb must be a whole number from 8 (the AMI's own snapshot) to 1024."
  }
}

variable "availability_zone" {
  description = "The zone of the subnet and the instance. Null takes the first zone, in name order, that offers instance_type. Read once, like the AMI: a later change moves nothing (DESIGN.md)."
  type        = string
  default     = null
}

variable "vpc_cidr" {
  description = "The server VPC's IPv4 range; the public subnet is its first /24."
  type        = string
  default     = "10.75.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0)) && tonumber(split("/", var.vpc_cidr)[1]) <= 24
    error_message = "vpc_cidr must be an IPv4 CIDR of /24 or larger."
  }
}

variable "enable_cloudwatch_agent" {
  description = "At the server's first boot, install AWS's CloudWatch agent (signature checked) to send memory and disk use, and give the instance role CloudWatchAgentServerPolicy. Off by default."
  type        = bool
  default     = false
}

variable "enable_ebs_snapshots" {
  description = "A daily EBS snapshot of the root volume through Data Lifecycle Manager, 7 kept."
  type        = bool
  default     = true
}

variable "enable_s3_backups" {
  description = "The snapshot bucket, the instance role's grant to assume bootstrap's snapshot writer, and the user data's /etc/fermix/snapshot-destination, which Fermix's first boot reads to keep its snapshots in the bucket, signed with a one-hour session of that role. No access key exists anywhere. Off: no bucket, no grant, no file. The user data is read once (DESIGN.md): RUNBOOK.md, \"Turning S3 backups on or off later\"."
  type        = bool
  default     = true
}

variable "ebs_snapshot_time_utc" {
  description = "When the daily snapshot starts, HH:MM in UTC; DLM starts it within the hour after. The default comes before Fermix's nightly update at 04:00 UTC."
  type        = string
  default     = "03:00"

  validation {
    condition     = can(regex("^([01][0-9]|2[0-3]):[0-5][0-9]$", var.ebs_snapshot_time_utc))
    error_message = "ebs_snapshot_time_utc must be HH:MM, 24-hour, in UTC."
  }
}

variable "snapshot_noncurrent_days" {
  description = "Days the snapshot bucket keeps an object's noncurrent versions."
  type        = number
  default     = 30

  validation {
    condition     = var.snapshot_noncurrent_days == floor(var.snapshot_noncurrent_days) && var.snapshot_noncurrent_days >= 1
    error_message = "snapshot_noncurrent_days must be a positive whole number."
  }
}

variable "alert_emails" {
  description = "Where the status-check alarm (through an encrypted SNS topic) and the monthly budget send, one email address per entry. Empty: the alarm exists without a notification, and no topic or budget is made."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for address in var.alert_emails : can(regex("^[^@\\s\"]+@[^@\\s\"]+\\.[^@\\s\"]+$", address))])
    error_message = "alert_emails must be a list of email addresses, one per entry."
  }
}

variable "monthly_budget_usd" {
  description = "The monthly budget for the account's cost in USD, counted before credits; it emails every address in alert_emails at 50%, 80% and 100%."
  type        = number
  default     = 30

  validation {
    condition     = var.monthly_budget_usd > 0
    error_message = "monthly_budget_usd must be more than 0."
  }
}

variable "allow_destroy" {
  description = "The one switch that lets the server stack be removed: it lifts the instance's termination protection, lets Terraform empty the versioned snapshot bucket, and lets terraform destroy run. Apply it first; move Fermix back to the Mac before that (README.md, \"Removing the server\")."
  type        = bool
  default     = false
}
