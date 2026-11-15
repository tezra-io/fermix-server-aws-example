# Every plan and apply runs as the deploy role bootstrap made, assumed
# from the owner's own sign-in. allowed_account_ids refuses any other account.

provider "aws" {
  region              = var.region
  allowed_account_ids = [split(":", var.deploy_role_arn)[4]]

  assume_role {
    role_arn     = var.deploy_role_arn
    session_name = "fermix-server-deploy"
  }
}
