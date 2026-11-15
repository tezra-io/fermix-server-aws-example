# CHANGE ME in terraform.tfvars: the region you applied bootstrap/ with.
variable "region" {
  description = "The server's AWS region, the one bootstrap was applied with. No default: nothing lands in a region the owner did not choose."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", var.region))
    error_message = "region must be an AWS region name, such as us-east-1."
  }
}

# CHANGE ME in terraform.tfvars: bootstrap's deploy_role_arn output (terraform -chdir=bootstrap output -raw deploy_role_arn).
variable "deploy_role_arn" {
  description = "bootstrap's deploy_role_arn output: the role every plan and apply assumes."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/fermix-server-deploy$", var.deploy_role_arn))
    error_message = "deploy_role_arn must be bootstrap's deploy_role_arn output, arn:aws:iam::<account>:role/fermix-server-deploy."
  }
}

# The server's own choices; each is described in modules/server/variables.tf.

# CHANGE ME (review): a bigger Graviton type for more memory or CPU; t4g.small costs about $12 a month in us-east-1.
variable "instance_type" {
  description = "See modules/server."
  type        = string
  default     = "t4g.small"
}

# CHANGE ME (review): the disk that holds the Fermix home, in GB; raise it if you keep large files.
variable "root_volume_gb" {
  description = "See modules/server."
  type        = number
  default     = 20
}

variable "availability_zone" {
  description = "See modules/server."
  type        = string
  default     = null
}

variable "vpc_cidr" {
  description = "See modules/server."
  type        = string
  default     = "10.75.0.0/16"
}

variable "enable_cloudwatch_agent" {
  description = "See modules/server."
  type        = bool
  default     = false
}

variable "enable_ebs_snapshots" {
  description = "See modules/server."
  type        = bool
  default     = true
}

variable "enable_s3_backups" {
  description = "See modules/server."
  type        = bool
  default     = true
}

variable "ebs_snapshot_time_utc" {
  description = "See modules/server."
  type        = string
  default     = "03:00"
}

variable "snapshot_noncurrent_days" {
  description = "See modules/server."
  type        = number
  default     = 30
}

# CHANGE ME in terraform.tfvars: your email address(es) for the status-check alarm and the budget; empty, there are neither.
variable "alert_emails" {
  description = "See modules/server."
  type        = list(string)
  default     = []
}

# CHANGE ME (review): the whole account's monthly budget in USD, which emails alert_emails at 50, 80 and 100%.
variable "monthly_budget_usd" {
  description = "See modules/server."
  type        = number
  default     = 30
}

variable "allow_destroy" {
  description = "See modules/server: the one switch that lets the server stack be removed."
  type        = bool
  default     = false
}
