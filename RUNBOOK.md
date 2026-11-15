# fermix-server-aws-example runbook

Operating the server once it runs. Building it and removing it are in [`README.md`](README.md).

Commands assume the AWS CLI v2 signed in with your own sign-in (`aws login --profile fermix-admin`,
then `export AWS_PROFILE=fermix-admin`, or your own profile), AWS's Session Manager plugin, and the
region both stacks use. Terraform runs as the deploy role by itself; everything else here runs with
your own sign-in.

```sh
id=$(terraform -chdir=server output -raw instance_id)
region=$(terraform -chdir=server output -raw region)
```

## Getting onto the server

There is no SSH and no inbound rule. Session Manager, logged in CloudTrail:

```sh
aws ssm start-session --target "$id" --region "$region"
sudo -i
```

The SSM agent registers a minute or two after the first boot starts. Until it has,
`aws ssm describe-instance-information --region "$region" --filters Key=InstanceIds,Values="$id"`
lists nothing and `start-session` answers `TargetNotConnected`. With `require_session_mfa`, a
sign-in without MFA gets `AccessDeniedException` (README.md, "Sessions with MFA"). What the first
boot did is in the console output, which needs no agent:

```sh
aws ec2 get-console-output --instance-id "$id" --region "$region" --latest --output text | grep fermix-server:
```

On the server, `cat /var/log/cloud-init-output.log` holds the same lines. A line `fermix-server: ...
so it was not installed.` means a package's signature did not check out against the pinned key, and
nothing was installed; never install it by hand.

## The status-check alarm

`fermix-server-instance-status`: EC2's instance status check failed for three minutes running, so
the operating system does not answer. (A failed system check is AWS hardware, which EC2's automatic
recovery moves to healthy hardware by itself, same volume, same addresses.)

1. `aws ec2 describe-instance-status --instance-ids "$id" --region "$region"`.
2. The console output (above) shows a kernel panic or a full disk.
3. Reboot: `aws ec2 reboot-instances --instance-ids "$id" --region "$region"`. The home is on the
   root volume and survives a reboot, a stop and a start.

## A session email you did not expect

The email names who started or resumed the session, or sent the command, and when. If it was not
you, end it, then look at what that principal did:

```sh
aws ssm terminate-session --region "$region" --session-id <the email's session>
aws ssm cancel-command --region "$region" --command-id <the email's command>
aws cloudtrail lookup-events --region "$region" \
  --lookup-attributes AttributeKey=Username,AttributeValue=<the session name in the email's ARN>
```

Then decide whether to rotate that principal's access. README.md, "Who can open a session", says
what one account cannot stop. To see that the rule is working:

```sh
aws cloudwatch get-metric-statistics --region "$region" --namespace AWS/Events \
  --metric-name Invocations --dimensions Name=RuleName,Value=fermix-server-sessions \
  --start-time <a day ago, 2026-01-01T00:00:00Z> --end-time <now> --period 3600 --statistics Sum
```

`FailedInvocations` in place of `Invocations` counts deliveries the security alert topic
refused.

## Moving Fermix back before anything destroys the server

The server's root volume holds the Fermix home. Before replacing the instance or removing the
server, move Fermix back: on the Mac, open Always On and move back to this Mac, and wait for the
move to finish. A server that is still the primary takes the home with it when it goes.

## Replacing the AMI deliberately

The AMI and the user data are read once, at create: a newer Debian 13 image never replaces the
server by itself (DESIGN.md, "The AMI and the user data are read once"). To move to a newer image
on purpose:

1. Move Fermix back to the Mac (above).
2. Apply with `allow_destroy = true` in `server/terraform.tfvars`: termination protection is off.
3. Replace the instance alone:
   ```sh
   terraform -chdir=server apply -replace=module.server.aws_instance.server
   ```
   The new instance boots the AMI the parameter names now and today's user data.
4. Set `allow_destroy = false` again and apply.
5. Run the command Always On shows on the new server, then move to it.

## Turning metrics on or off later

`enable_cloudwatch_agent` installs the agent only at a server's first boot. Changed later, the
next apply attaches or detaches `CloudWatchAgentServerPolicy` and every plan warns that the server
booted with the other value. Install or remove the agent with AWS's own signed distributor package,
through Run Command, with your own sign-in:

```sh
# on
aws ssm send-command --region "$region" --instance-ids "$id" --document-name AWS-ConfigureAWSPackage \
  --parameters action=Install,name=AmazonCloudWatchAgent
aws ssm send-command --region "$region" --instance-ids "$id" --document-name AmazonCloudWatch-ManageAgent \
  --parameters action=configure,mode=ec2,optionalConfigurationSource=default,optionalRestart=yes
# off
aws ssm send-command --region "$region" --instance-ids "$id" --document-name AWS-ConfigureAWSPackage \
  --parameters action=Uninstall,name=AmazonCloudWatchAgent
```

The default configuration sends memory and disk use, as the first boot's does. The warning stays
until the server is replaced; it says the instance's user data, not the agent, is what differs.

## Turning S3 backups on or off later

`enable_s3_backups` writes `/etc/fermix/snapshot-destination` only at a server's first boot,
and Fermix's own first boot reads it from there into the home's settings. Changed later, the next
apply makes or removes the bucket and the instance role's grant, and every plan warns that the
server booted with the other value.

- **Off later:** the apply refuses to delete a bucket that holds snapshots unless `allow_destroy`
  is set; empty it first, or keep `enable_s3_backups` on. Fermix's next snapshot to S3 then fails,
  naming STS's refusal of the session, which Always On shows; the desktops' copies go on.
- **On later:** the apply makes the bucket and the grant, which nothing uses until a server boots
  with the destination. Replace the server (README.md, "Removing the server", then apply again and
  run the command Always On shows on the new one).

## Fermix's snapshots in the bucket

Each is one encrypted file, `fermix/<profile>/<UTC>-e<epoch>.fxsnap`. The server's session can
only add files; your own sign-in reads them:

```sh
aws s3 ls "s3://$(terraform -chdir=server output -raw snapshot_bucket)/fermix/" --recursive
aws s3 cp "s3://<bucket>/fermix/<profile>/<name>.fxsnap" .
```

A snapshot opens only with the recovery passphrase it was written under: restore it on a fresh
server with Fermix's `first-boot.sh --restore`, or with `fermix home import` on a computer.

## Reading the DLM snapshots

`enable_ebs_snapshots` takes a snapshot of the root volume every day, starting within an hour of
`ebs_snapshot_time_utc`, and keeps 7. Each carries the server stack's tag.

```sh
aws ec2 describe-snapshots --region "$region" --owner-ids self \
  --filters Name=tag:fermix-server-stack,Values=server \
  --query 'Snapshots[].{id:SnapshotId,state:State,start:StartTime,volume:VolumeId,gb:VolumeSize}' --output table
aws dlm get-lifecycle-policies --region "$region" --query 'Policies[].{id:PolicyId,state:State,description:Description}'
```

A policy in state `ERROR` names what failed in `aws dlm get-lifecycle-policy --policy-id <id>`
(`StatusMessage`). To get a whole server back from one: create a volume from the snapshot in the
server's zone, stop the instance, detach its root volume, attach the new one as `/dev/xvda`, and
start it. Fermix's own way back is a home snapshot restored on a fresh server with
`first-boot.sh --restore`; a DLM snapshot is the whole disk as it was that night.

## Removing the server

README.md, "Removing the server", walks through it: move Fermix back, apply with
`allow_destroy = true`, destroy, delete GuardDuty's endpoint if it made one, delete the DLM
snapshots, and check that nothing tagged remains.

## Rotating the deploy role's trust

The deploy role trusts one principal, `admin_role_arn`. When your sign-in role changes (a new
Identity Center permission set, a renamed role, a role deleted and made again, which IAM treats as a
new principal):

1. Sign in with a role that may change IAM roles.
2. Take the new role's full ARN: `aws iam get-role --role-name <RoleName> --query Role.Arn --output text`.
3. Set `admin_role_arn` in `bootstrap/terraform.tfvars` and apply (the state comes from the bucket):
   ```sh
   terraform -chdir=bootstrap plan    # one change: aws_iam_role.deploy's assume_role_policy
   terraform -chdir=bootstrap apply
   ```
   `allowed_account_ids` refuses a role in another account: moving to another account is a new
   bootstrap there, not a trust change.
4. `terraform -chdir=server plan` as the deploy role proves the new trust.

A trust policy that names a role which no longer exists shows the role's unique id (`AROA...`) in
place of its ARN; rotate it the same way.

## Bootstrap's own state

It lives in the state bucket, `bootstrap/terraform.tfstate`, encrypted with the state key and
versioned, and is read with your own sign-in. A fresh clone reaches it with
`terraform -chdir=bootstrap init -backend-config=backend.s3.tfbackend`, the file
`bootstrap_backend` wrote (`bucket`, `region`, `kms_key_id`; nothing secret). A bad write is undone
from the bucket's versions:

```sh
aws s3api list-object-versions --bucket fermix-server-state-<account>-<region> --prefix bootstrap/terraform.tfstate
```

The first apply's steps, local state through `backend_override.tf` and then
`init -migrate-state`, are in README.md, "Step 3: apply bootstrap/". They run once: once the state
is in the bucket, `bootstrap/` needs local state again only to be removed (README.md, "Removing
bootstrap/, last").
