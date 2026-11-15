# CHANGE ME in terraform.tfvars: your AWS region, the same one for bootstrap/ and server/.
variable "region" {
  description = "The AWS region for the state bucket and, through the deploy role's boundary, for the server. No default: nothing lands in a region the owner did not choose."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", var.region))
    error_message = "region must be an AWS region name, such as us-east-1."
  }
}

# CHANGE ME in terraform.tfvars: the full ARN of the role (or IAM user) you sign in with, the only one the deploy role trusts.
variable "admin_role_arn" {
  description = "The IAM role the owner signs in with, the only principal the deploy role trusts: its full ARN with its path, as `aws iam get-role --role-name <RoleName> --query Role.Arn` prints it (README.md, \"Step 2: fill in your values\"). An IAM user's ARN works the same way."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:(role|user)/[A-Za-z0-9+=,.@_/-]+$", var.admin_role_arn))
    error_message = "admin_role_arn must be an IAM role or user ARN, arn:aws:iam::<account>:role/<path/>RoleName. A session ARN (arn:aws:sts::<account>:assumed-role/<RoleName>/<session>) cannot be trusted: take the role's own ARN from `aws iam get-role --role-name <RoleName> --query Role.Arn`."
  }
}

variable "ami_owner_id" {
  description = "The AWS account that publishes the server's AMI: Debian's, which owns the images /aws/service/debian/release/13/latest/arm64 names. The deploy role launches from no other account's image or snapshot."
  type        = string
  default     = "136693071363"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.ami_owner_id))
    error_message = "ami_owner_id must be a 12-digit AWS account id."
  }
}

# CHANGE ME in terraform.tfvars: your email address(es); empty, the security alerts reach no one.
variable "alert_emails" {
  description = "Where the account's security alerts go, one email address per entry: each gets the email that a Session Manager session started or resumed, a Run Command command sent, or a GuardDuty finding raised in this region. They go through bootstrap's own topic, out of the deploy role's reach (README.md, \"The session email\"). Empty: the alerts reach no one."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for address in var.alert_emails : can(regex("^[^@\\s\"]+@[^@\\s\"]+\\.[^@\\s\"]+$", address))])
    error_message = "alert_emails must be a list of email addresses, one per entry."
  }
}

# CHANGE ME (review): true only if your sign-in carries MFA, or every session on the server is refused.
variable "require_session_mfa" {
  description = "Sessions with MFA: bootstrap writes an inline policy on admin_role_arn itself that denies it every Systems Manager action that can run code on the server (a session, Run Command, and in the region automations, associations and maintenance-window tasks) unless its credentials carry MFA (aws:MultiFactorAuthPresent). A sign-in that carries none, as no federated one does, then runs none of them (README.md, \"Sessions with MFA\"). Off by default."
  type        = bool
  default     = false
}

# CHANGE ME (review): false if a trail already logs this region's management events, to avoid paying for a second copy.
variable "enable_cloudtrail" {
  description = "A minimal CloudTrail trail (write management events, this region, its own KMS key, a private bucket kept 90 days): EventBridge sees the session email's StartSession only while a trail logs it. About $1 a month, the key's; the first copy of management events is free. If a trail already logs this region's management events, set false (README.md, \"The session email\"). On by default."
  type        = bool
  default     = true
}

# CHANGE ME (review): true for GuardDuty's Runtime Monitoring (about $3 a month); leave false if the region has a detector.
variable "enable_guardduty" {
  description = "A GuardDuty detector in region with Runtime Monitoring for EC2: GuardDuty installs and updates its agent on every SSM-managed instance in the account and region, the server included. About $3 a month for the server's two vCPUs after GuardDuty's 30-day trial. If the region already has a detector, the account's or an organization's, leave this off: GuardDuty refuses a second (README.md, \"GuardDuty\"). Off by default."
  type        = bool
  default     = false
}
