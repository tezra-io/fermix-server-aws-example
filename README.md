# fermix-server-aws-example

Terraform that builds an AWS server you can then make your Fermix's Always On primary. Making it
the primary is the same step as on any server: run the command the Fermix app's Always On screen
shows, in a shell on the server. Fermix itself creates no server; this repository is one way to
build one. Fermix's own guide to Always On is at <https://fermix.ai/docs/always-on/>.
[`DESIGN.md`](DESIGN.md) explains the choices that are not obvious, and
[`RUNBOOK.md`](RUNBOOK.md) is for operating the server once it runs.

| | |
|---|---|
| Host | one `t4g.small`, Debian 13 arm64 (`/aws/service/debian/release/13/latest/arm64`), 20 GB gp3 |
| Access | AWS Systems Manager Session Manager only: no SSH, no key pair, no inbound rule |
| Encryption | a KMS key each for the Terraform state; the server (root volume, its snapshots, the snapshot bucket, the alert topic); the security alert topic; and the trail's logs |
| Backups | daily EBS snapshots through Data Lifecycle Manager, 7 kept; Fermix's own encrypted snapshots in an S3 bucket, signed with a short role session (no keys); your Mac's backups of the home |
| Cost | about $23 a month in us-east-1 ("Cost" below) |

## What this builds, and what it does not

**It builds** two Terraform stacks and a module:

- `bootstrap/`, applied once with your own sign-in: the state bucket and its key, a deploy role,
  and the three roles the server uses, plus the account's security alerts (EventBridge rules, an
  encrypted SNS topic and, unless you turn it off, a minimal CloudTrail trail) and, if you want
  it, GuardDuty;
- `server/`, which builds the server through `modules/server/`, as the deploy role `bootstrap/`
  made: its own VPC with one public subnet and no NAT gateway, a security group with no inbound
  rule, the instance, its KMS key, the snapshot bucket, the daily EBS snapshots, a status-check
  alarm and, with an email address, an alert topic and a monthly budget.

Every value you choose is a variable. The only account this repository names is Debian's, the
publisher of the server's image (`ami_owner_id`), and it names no person.

**It does not** install Fermix. The server's user data installs AWS's SSM agent (and, with
`enable_cloudwatch_agent`, the CloudWatch agent), turns Debian's sshd off, so nothing listens on
port 22 even inside the VPC, and with `enable_s3_backups` writes where Fermix keeps its snapshots
(`/etc/fermix/snapshot-destination`); nothing else. Fermix's own first boot, started by the command
the Fermix app's Always On screen shows, installs Fermix and makes the server the primary. The
enrollment code and a Tailscale key never reach the user data, Terraform's variables or its state:
you type them at the first boot's prompt, in a Session Manager shell, and the prompt does not echo
them. Nothing here plans or applies from CI: CI runs the static checks only, with no AWS
credentials.

## Cost

us-east-1, on-demand, per month:

| Item | About |
|---|---|
| t4g.small, all month | $12.30 |
| Public IPv4 | $3.65 |
| 20 GB gp3 | $1.60 |
| Two KMS keys (state, server) | $2.00 |
| EBS snapshots, 7 daily (incremental) | about $1 |
| S3, CloudWatch alarm, SNS | under $1 |
| The trail (`enable_cloudtrail`): its KMS key; its logs' S3 and KMS requests | about $1.10 |
| The security alert topic's KMS key | $1 |
| **Total** | **about $23** |
| With metrics on (`enable_cloudwatch_agent`), two custom metrics | about $1 more |
| With GuardDuty (`enable_guardduty`), after its 30-day trial: Runtime Monitoring at $1.50 per vCPU (two), and CloudTrail, VPC flow and DNS log analysis by volume | about $3 to $4 more |

Data sent out stays far inside AWS's free 100 GB a month: a link carries messages, and the server's
downloads are its own updates. Prices differ by region; check AWS's pricing pages for yours.

## Prerequisites

- **An AWS account**, and a sign-in to it for the one-time bootstrap that may create IAM roles and
  policies, KMS keys, S3 buckets, SNS topics, EventBridge rules, a CloudTrail trail and, with
  `enable_guardduty`, a GuardDuty detector: an administrator role or IAM user. After the
  bootstrap, `server/` runs as the deploy role it made, assumed from that same sign-in.
- **The AWS CLI v2**, signed in as that role or user. The commands below use a named profile,
  `fermix-admin` here; use your own:
  ```sh
  aws login --profile fermix-admin
  export AWS_PROFILE=fermix-admin
  ```
- **AWS's [Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)**
  for the AWS CLI, to open a shell on the server.
- **Terraform 1.10 or later, before 2.0** (`required_version` in each `versions.tf`; 1.10 brought
  S3's native lock file). CI uses 1.16.6. Run it on macOS or Linux: the destroy guard is a shell
  command.
- **The Fermix app**, whose Always On screen shows the command that makes the server the primary.

## Step by step

All commands run from the repository's root.

### Step 1: copy the example files

```sh
cp bootstrap/terraform.tfvars.example bootstrap/terraform.tfvars
cp server/terraform.tfvars.example    server/terraform.tfvars
```

The two `backend.s3.tfbackend.example` files show what the real `backend.s3.tfbackend` files hold.
Do not copy or edit them by hand: bootstrap's outputs write both, in steps 3 and 4, with your
account's values. Every real file (`*.tfvars`, `*.tfbackend`) is gitignored.

### Step 2: fill in your values

Every place to look at is marked `CHANGE ME`.

| File | Setting | What to put |
|---|---|---|
| `bootstrap/terraform.tfvars` | `region` | Your AWS region, for example `us-east-1`. There is no default in either stack. |
| `bootstrap/terraform.tfvars` | `admin_role_arn` | The full ARN of the role (or IAM user) you sign in with, path included (below). The deploy role trusts it alone. |
| `bootstrap/terraform.tfvars` | `alert_emails` | Optional: your email address(es) for the security alerts ("The session email"). Empty, they reach no one. |
| `bootstrap/terraform.tfvars` | `require_session_mfa` | Optional, off by default: read "Sessions with MFA" before turning it on. |
| `bootstrap/terraform.tfvars` | `enable_cloudtrail` | On by default. Set `false` if a trail already logs this region's write management events. |
| `bootstrap/terraform.tfvars` | `enable_guardduty` | Optional, off by default ("GuardDuty"). Leave it off if the region already has a detector. |
| `server/terraform.tfvars` | `region` | The same region as `bootstrap/`. |
| `server/terraform.tfvars` | `deploy_role_arn` | bootstrap's `deploy_role_arn` output, after step 3. |
| `server/terraform.tfvars` | `alert_emails`, `monthly_budget_usd` | Optional: your email address(es) for the status-check alarm and a monthly budget (default 30 USD, the whole account's cost). Without an address there is no topic and no budget. |
| `server/terraform.tfvars` | `instance_type`, `root_volume_gb` | Optional: default `t4g.small` (Graviton only) and 20 GB. |
| `server/terraform.tfvars` | `enable_cloudwatch_agent`, `enable_ebs_snapshots`, `ebs_snapshot_time_utc`, `enable_s3_backups` | Optional: defaults off, on, `03:00`, on. |
| `bootstrap/backend.s3.tfbackend` | `bucket`, `region`, `kms_key_id` | Nothing by hand: written by `terraform -chdir=bootstrap output -raw bootstrap_backend` in step 3. |
| `server/backend.s3.tfbackend` | `bucket`, `region`, `kms_key_id`, `assume_role` | Nothing by hand: written by `terraform -chdir=bootstrap output -raw server_backend` in step 4. |

**`admin_role_arn`, the role you sign in with, by its full ARN.** `aws sts get-caller-identity`
prints a session, `arn:aws:sts::<account>:assumed-role/<RoleName>/<session>`, which a trust
policy cannot name, and which leaves out the role's path. Take `<RoleName>` from it and ask IAM
for the role's own ARN:

```sh
aws sts get-caller-identity --query Arn --output text
aws iam get-role --role-name <RoleName> --query Role.Arn --output text
# arn:aws:iam::<account>:role/<path/><RoleName>
```

An IAM user's own ARN (`arn:aws:iam::<account>:user/<name>`) works the same way.

`bootstrap/` also has `ami_owner_id`, the AWS account that publishes the server's image:
`136693071363`, the account Debian publishes its AMIs from, unless you change it. The deploy role
launches no other account's image.

### Step 3: apply bootstrap/

With your own sign-in (`AWS_PROFILE` from the prerequisites). bootstrap's own state lives in the
state bucket it makes, under `bootstrap/terraform.tfstate`. The bucket does not exist before the
first apply, so that one apply runs on local state through a gitignored override, and the state
then moves in:

```sh
printf 'terraform {\n  backend "local" {}\n}\n' > bootstrap/backend_override.tf
terraform -chdir=bootstrap init
terraform -chdir=bootstrap apply
terraform -chdir=bootstrap output -raw bootstrap_backend > bootstrap/backend.s3.tfbackend
rm bootstrap/backend_override.tf
terraform -chdir=bootstrap init -migrate-state -backend-config=backend.s3.tfbackend
terraform -chdir=bootstrap plan        # No changes, against the state in the bucket
rm -f bootstrap/terraform.tfstate bootstrap/terraform.tfstate.backup
```

`init -migrate-state` asks whether to copy the local state to the new backend: answer `yes`. From
then on every `bootstrap/` command reads its state from the bucket (in a fresh clone, run
`terraform -chdir=bootstrap init -backend-config=backend.s3.tfbackend` first). The deploy role
cannot read or write it: its rights on the bucket stop at `server/terraform.tfstate`.

With `alert_emails`, AWS emails each address a confirmation link for the security alert topic:
confirm it, or nothing is sent there.

### Step 4: apply server/

Give `server/` bootstrap's outputs, then apply. Every plan and apply, and the state's reads and
writes, run as the deploy role `fermix-server-deploy`, assumed from your sign-in:

```sh
terraform -chdir=bootstrap output -raw deploy_role_arn       # deploy_role_arn in server/terraform.tfvars
terraform -chdir=bootstrap output -raw server_backend > server/backend.s3.tfbackend
terraform -chdir=server init -backend-config=backend.s3.tfbackend
terraform -chdir=server apply
```

The apply prints `instance_id`, `region`, `session_command` and, with `enable_s3_backups`,
`snapshot_bucket` and `snapshot_bucket_region`. With `alert_emails`, confirm the subscription email
AWS sends for the server's alert topic too.

### Step 5: open a shell on the server

```sh
terraform -chdir=server output -raw session_command
# aws ssm start-session --target <instance id> --region <region>
```

Run the command it prints, then `sudo -i`. It runs with your own sign-in, not the deploy role, and
needs the Session Manager plugin. The SSM agent registers a minute or two after the instance
starts; until it has, `start-session` answers `TargetNotConnected`, and
`aws ssm describe-instance-information --region <region>` lists the server once it has.
RUNBOOK.md, "Getting onto the server", shows how to read the first boot's own log meanwhile.

### Step 6: make it your Fermix's primary

1. On your Mac, open the Fermix app's Always On screen, choose to use your own Linux server, and
   copy the command it shows.
2. In the root shell from step 5, paste the command and type the enrollment code at its prompt.
   With `--tailscale`, type the Tailscale key there too. The prompt does not echo either.
3. Review the server and move to it from the Mac, as for any server.

With `enable_s3_backups`, the first boot finds the bucket in `/etc/fermix/snapshot-destination`:
the command needs no `--snapshot-bucket`.

## Backups

The Fermix home lives on the server's encrypted root volume. Three things keep copies of it.

### EBS snapshots (`enable_ebs_snapshots`, on by default)

Data Lifecycle Manager snapshots the root volume every day, starting within an hour of
`ebs_snapshot_time_utc` (default `03:00` UTC), and keeps 7. Each snapshot is encrypted with the
server's key and carries the server stack's tag. A snapshot is the whole disk as it was that
night; RUNBOOK.md, "Reading the DLM snapshots", lists them and puts one back. DLM's snapshots
outlive their policy, so removing the server deletes them by hand ("Removing the server").

### Fermix's snapshots in S3 (`enable_s3_backups`, on by default)

Fermix keeps its own encrypted snapshots of the home in the snapshot bucket,
`fermix-server-snapshots-<account>-<region>`, each one file, `fermix/<profile>/<UTC>-e<epoch>.fxsnap`.
Fermix's first boot installs a credentials helper, a root timer that every 15 minutes assumes
bootstrap's snapshot writer role with the instance role and hands Fermix's account that session
alone (it never reaches the metadata service itself), and the server's settings say to sign with
it. The session lasts an hour, can only add files, and is held to a bucket of your own account;
no access key exists anywhere (DESIGN.md, "S3 backups sign with a bucket-only role"). The bucket
is versioned, keeps an object's noncurrent versions `snapshot_noncurrent_days` (default 30), and
takes uploads encrypted with the server's key alone.

Your own sign-in reads them; RUNBOOK.md, "Fermix's snapshots in the bucket", downloads one. A
snapshot opens only with the recovery passphrase it was written under. With `enable_s3_backups`
off there is no bucket and no grant, and your Mac's backups of the home cover it.

### Your Mac's backups

Whatever the server keeps, the Mac's own backups of the home go on as for any Always On server.

## Alerts

### The status-check alarm and the budget

`fermix-server-instance-status` fires when EC2's instance status check fails for three minutes
running, so the operating system does not answer (RUNBOOK.md, "The status-check alarm"). A failed
system check is AWS hardware, which EC2's automatic recovery handles by itself. With
`alert_emails` in `server/`, the alarm notifies an encrypted SNS topic, `fermix-server-alerts`,
which emails each address, and a monthly budget, `fermix-server-monthly`, emails them at 50, 80
and 100% of `monthly_budget_usd`. The budget counts the whole account's cost, before credits.
Without an address there is no topic and no budget, and the alarm exists without a notification.

### The session email

With `alert_emails` set in `bootstrap/`, every Session Manager session that starts or resumes in
the account's region, every Run Command command sent there, every EC2 instance attribute changed
there (or a change refused), and every write that can widen who reaches the snapshot or state
bucket (or such a write refused), sends an email to each address through bootstrap's security
alert topic, `fermix-owner-security-alerts`:

```
fermix-server: a Session Manager StartSession.
Who: arn:aws:sts::<account>:assumed-role/<RoleName>/<session>
Request: {target:i-0123456789abcdef0}
Session: <session>-0a1b2c3d4e5f6a7b8
When: <time>, from <address>
```

A non-interactive session's request also names its document and command; a resume's names only
the session, which its start's email tied to an instance. A command's email (`fermix-server: a Run
Command SendCommand.`, rule `fermix-server-commands`) names the instances or targets, the document
and the command id; CloudTrail hides the commands themselves. An instance attribute's email
(`fermix-server: an EC2 ModifyInstanceAttribute.`, rule `fermix-server-instance-attributes`) names
the instance and the attribute (CloudTrail hides user data) and, when refused, the error code: a
new user data is code the instance runs at its next boot without a session, which the deploy role
is denied, and `server/`'s own applies send one each time `allow_destroy` or `instance_type`
changes. A bucket access email (`fermix-server: an S3 PutBucketPolicy on the snapshot or state
bucket.`, rule `fermix-server-bucket-access`) names the bucket and the setting written and, when
refused, the error code. It matches CloudTrail's `PutBucketPolicy`, `DeleteBucketPolicy`,
`PutBucketPublicAccessBlock`, `DeleteBucketPublicAccessBlock`, `PutBucketAcl`,
`PutBucketOwnershipControls`, `DeleteBucketOwnershipControls` and `PutBucketReplication` on those
two buckets alone, by name. The deploy role writes the snapshot bucket's ownership controls and its
policy, which can open it to another account ("What the deploy role can reach"), and `server/`'s
own applies send one for each such write when they make, change or remove the bucket. Only an
administrator, your own sign-in among them, can write the rest: the deploy role is denied the
snapshot bucket's public access block, ACL and replication, and reaches only its state object in
the state bucket. bootstrap's EventBridge rule `fermix-server-sessions` matches CloudTrail's
`StartSession` and `ResumeSession` and sends to the security alert topic, which takes messages
from bootstrap's five rules alone, by their ARNs. bootstrap does not know the instance id, so the
session, command and instance attribute rules match every session, command and instance in the
account and region, and the email names the instance. SNS emails only a confirmed subscription.
RUNBOOK.md, "A session email you did not expect", says what to do with one.

The topic is bootstrap's, not the server's `fermix-server-alerts`, because the deploy role manages
that one and could unsubscribe you or delete it, silencing the alerts that watch it. Its name is
outside the deploy role's `fermix-server-*` scope, and its KMS key
(`alias/fermix-owner-security-alerts`) is tagged `bootstrap`, which the role's tag-held KMS rights
never reach. The key's policy lets `admin_role_arn` administer it, by its ARN, and EventBridge
publish with it, and no one else. The server's `alert_emails` stays for the status-check alarm and
the budget; set the same addresses in both stacks to get everything.

EventBridge sees these calls only while a trail logs the region's management events. With
`enable_cloudtrail` (bootstrap, on by default), bootstrap makes the least such trail: write
management events, this region, logs validated, its own KMS key, a private bucket that keeps them
90 days. It costs about $1 a month, the key's; the first copy of management events is free. If a
trail already logs this region's write management events
(`aws cloudtrail describe-trails --include-shadow-trails`), set `enable_cloudtrail = false`: a
second copy costs $2 per 100,000 events. Turned off later, the apply refuses to delete the bucket
while it holds logs; empty it, every version, first.

### GuardDuty

With `enable_guardduty` (bootstrap, off by default), bootstrap makes a GuardDuty detector in the
region, with Runtime Monitoring for EC2 and its agent managed by GuardDuty. An account has one
detector per region, so it is bootstrap's, made with your sign-in, never the deploy role's. What it
does to the server:

- GuardDuty installs its security agent on every SSM-managed instance in the account and region,
  the server included, through an SSM association, and keeps it updated. The agent takes at most
  10% of the vCPUs and, under 8 GB of memory, 128 MB. GuardDuty leaves out only an instance tagged
  `GuardDutyManaged = false` before this is turned on, and it reads that tag from the instance's
  metadata; the server keeps its tags out of metadata (`instance_metadata_tags = "disabled"`), so
  the server always gets the agent.
- The agent reaches GuardDuty over a link-local address. In a Region without that, GuardDuty puts a
  `guardduty-data` VPC endpoint and its security group in the server's VPC, which the deploy role
  cannot remove; "Removing the server" deletes them first.

A detector already in the region, the account's own or one your organization's GuardDuty
administrator manages, is not fought: `aws guardduty list-detectors --region <region>` lists it,
and with this on the apply stops at AWS's "a detector already exists" before it changes anything.
Leave `enable_guardduty` off and turn on Runtime Monitoring for EC2 in that detector. If an
organization's administrator takes the account over later, hand the detector to it:
`terraform -chdir=bootstrap state rm 'aws_guardduty_detector_feature.runtime_monitoring[0]'
'aws_guardduty_detector.this[0]'`, then set `enable_guardduty = false`.

Findings reach the security alert topic whichever detector runs. bootstrap's rule
`fermix-server-guardduty` sends every finding in the account's region, with its severity, title,
type, resource and a link. Only Runtime Monitoring is set here. GuardDuty turns its other
protection plans on by default for a new detector (S3, EKS audit logs, RDS, Lambda, Malware
Protection for EC2); each bills only by what it watches or scans.

## Updating

Change a setting in `server/terraform.tfvars` and run `terraform -chdir=server apply` again, or in
`bootstrap/terraform.tfvars` and `terraform -chdir=bootstrap apply` with your own sign-in. Some
things are read once, at the server's create, so that no apply ever replaces the server and the
home on it by itself (DESIGN.md, "The AMI and the user data are read once"):

- **The AMI.** A newer Debian 13 image never replaces the server. RUNBOOK.md, "Replacing the AMI
  deliberately", moves to one on purpose.
- **The user data.** `enable_cloudwatch_agent` and `enable_s3_backups` change the roles' policies
  at the next apply, but what the server installed at its first boot stays, and every plan warns
  until the two agree. RUNBOOK.md, "Turning metrics on or off later" and "Turning S3 backups on or
  off later".
- **The availability zone.** With `availability_zone` unset, the first zone in name order that
  offers the instance type, kept from then on.

A newer copy of this repository works the same way: its user data reaches only servers created
after it. When your sign-in role changes, RUNBOOK.md, "Rotating the deploy role's trust", points
the deploy role at the new one.

## Tearing down

### Removing the server

Keep the server's id and region first; the outputs are gone once the server is:

```sh
id=$(terraform -chdir=server output -raw instance_id)
region=$(terraform -chdir=server output -raw region)
```

1. **Move Fermix back to the Mac first.** The server's root volume holds the Fermix home: on the
   Mac, open Always On and move back to this Mac, and wait for the move to finish. Destroying a
   server that is still the primary destroys the home on it.
2. Set `allow_destroy = true` in `server/terraform.tfvars` and run `terraform -chdir=server apply`.
   That lifts termination protection, lets Terraform empty the versioned snapshot bucket (every
   version of Fermix's snapshots in it: download any you want to keep first, RUNBOOK.md,
   "Fermix's snapshots in the bucket"), and lets the destroy guard pass. Until that apply,
   `terraform destroy` refuses before it removes anything.
3. Run `terraform -chdir=server destroy`. Before it, if GuardDuty's Runtime Monitoring
   ("GuardDuty") runs in a Region where its agent connects through a VPC endpoint rather than a
   link-local address, GuardDuty has put a `guardduty-data` endpoint and its security group, tagged
   `GuardDutyManaged = true`, in the server's VPC. The deploy role cannot delete them, and the VPC
   cannot go while they stay, so delete them first with your own sign-in (each list is empty when
   GuardDuty made none):
   ```sh
   vpc=$(aws ec2 describe-instances --region "$region" --instance-ids "$id" --query 'Reservations[0].Instances[0].VpcId' --output text)
   aws ec2 describe-vpc-endpoints --region "$region" \
     --filters Name=vpc-id,Values="$vpc" Name=tag:GuardDutyManaged,Values=true --query 'VpcEndpoints[].VpcEndpointId'
   aws ec2 delete-vpc-endpoints --region "$region" --vpc-endpoint-ids <each id>
   aws ec2 describe-security-groups --region "$region" \
     --filters Name=vpc-id,Values="$vpc" Name=tag:GuardDutyManaged,Values=true --query 'SecurityGroups[].GroupId'
   aws ec2 delete-security-group --region "$region" --group-id <each id>
   ```
4. Delete the snapshots DLM took, which outlive their policy:
   ```sh
   for s in $(aws ec2 describe-snapshots --region "$region" --owner-ids self \
       --filters Name=tag:fermix-server-stack,Values=server --query 'Snapshots[].SnapshotId' --output text); do
     aws ec2 delete-snapshot --region "$region" --snapshot-id "$s"
   done
   ```
5. Check that nothing carrying the server stack's tag remains:
   ```sh
   aws resourcegroupstaggingapi get-resources --region "$region" \
     --tag-filters Key=fermix-server-stack,Values=server --query 'ResourceTagMappingList[].ResourceARN'
   aws budgets describe-budgets --account-id <account> --query 'Budgets[?starts_with(BudgetName, `fermix-server`)]'
   ```
   The tagging index lags: for up to about an hour it still lists what was just removed, a
   terminated instance, a root volume still `deleting`, a deleted snapshot. Check each ARN it lists
   (`aws ec2 describe-instances`, `describe-volumes`, `describe-snapshots`). What stays is the
   server's KMS key: destroy schedules its deletion with a 30-day window, during which
   `aws kms cancel-key-deletion` can still bring it back; `aws kms describe-key --key-id <arn>`
   says `PendingDeletion`.

`bootstrap/` (the state bucket, its key, the deploy role, the two server roles, the snapshot writer
and the security alerts) stays; a new `server/` apply builds a new server on it.

### Removing bootstrap/, last

Only once the server is gone. bootstrap guards its state bucket and key with `prevent_destroy`,
and its own state lives in that bucket, so its removal takes a few steps by hand, all with your
own sign-in:

1. Move bootstrap's state back to your computer (in a fresh clone, run
   `terraform -chdir=bootstrap init -backend-config=backend.s3.tfbackend` first):
   ```sh
   printf 'terraform {\n  backend "local" {}\n}\n' > bootstrap/backend_override.tf
   terraform -chdir=bootstrap init -migrate-state
   ```
   Answer `yes` to copying the state to the local backend.
2. In `bootstrap/state.tf`, delete the two `lifecycle { prevent_destroy = true }` blocks, on
   `aws_kms_key.state` and `aws_s3_bucket.state`: Terraform refuses to plan their destroy while
   they are there.
3. Empty the state bucket, `fermix-server-state-<account>-<region>`, and with `enable_cloudtrail`
   the trail's bucket, `fermix-server-trail-<account>-<region>`, of every object version and
   delete marker: both are versioned, and S3 deletes no bucket that holds any. The S3 console's
   **Empty** does it; `aws s3 rm --recursive` alone leaves the old versions.
4. `terraform -chdir=bootstrap destroy`. If it stops at the trail's bucket with `BucketNotEmpty`
   (CloudTrail can deliver a last log file after you emptied it), empty that bucket again and run
   the destroy again.
5. `rm -f bootstrap/backend_override.tf bootstrap/terraform.tfstate bootstrap/terraform.tfstate.backup`.

The destroy schedules bootstrap's KMS keys (the state's, the security alert topic's and the
trail's) for deletion with a 30-day window, deletes the GuardDuty detector if `enable_guardduty`
made one, and removes the `require_session_mfa` policy from your sign-in role if you turned it
on.

## Security notes

### No SSH, no inbound rule, no keys

- The security group has no inbound rule, and any rule added by hand is removed by the next apply.
  There is no key pair, and the first boot turns sshd off (DESIGN.md, "The user data turns sshd
  off"). Session Manager, opened from the inside by the SSM agent, is the only way in.
- All outbound traffic is allowed: Fermix's links reach addresses no list can know
  (DESIGN.md, "All outbound traffic is allowed").
- The instance requires IMDSv2, with a hop limit of 1 and its tags kept out of metadata, and has
  termination protection until `allow_destroy`.
- No access key exists anywhere. `server/` runs as a role assumed from your sign-in; Fermix's S3
  uploads use an hour-long session of a role that can only add files to one bucket.
- The root volume, its snapshots, the snapshot bucket, both alert topics, the trail's logs and the
  state are encrypted with their own KMS keys, each rotated yearly. Every bucket blocks public
  access and refuses requests without TLS.
- The enrollment code and the Tailscale key are typed at the first boot's prompt, never stored by
  Terraform.

### Who can open a session

Any principal in the account whose own policies allow `ssm:StartSession` on the server can open a
session on it, and this repository cannot change that. Session Manager has no resource policy on
an instance: IAM decides from the caller's identity policies, its permissions boundary and, in an
organization's member account, service control policies, and none of those is this repository's
to write for another principal. What it does:

- no role it makes opens a session or runs a command: the deploy role, the two server roles and
  the snapshot writer hold no `ssm:StartSession`, `ssm:ResumeSession` or `ssm:SendCommand`
  (`bootstrap/tests/bootstrap.tftest.hcl`);
- every session that starts or resumes in the account's region sends an email that names who
  ("The session email");
- the deploy role cannot change the server's user data, which runs code at boot with no session
  or command, and every change of an instance attribute in the region, or a refused one, emails
  too ("The session email");
- with `require_session_mfa`, `admin_role_arn`'s own sessions need MFA ("Sessions with MFA").

The server's side was tried and does not hold. Session Manager tags each session with the user id
of whoever started it, but a deny on the instance role's `ssmmessages:OpenDataChannel` for any
other tag let a session through even when it named another principal (DESIGN.md, "Other notes").

In an organization's member account, a service control policy holds against the account's own
administrators: one that denies `ssm:StartSession`, `ssm:ResumeSession` and `ssm:SendCommand` on
the server to everyone but `admin_role_arn`. Service control policies never apply in the
organization's management account itself, so there nothing does: owner-only sessions need the
server in a member account under such a policy. Even then, a principal that may stop the instance
or snapshot its volume, with EC2 and KMS rights, can read the disk.

### Sessions with MFA

With `require_session_mfa` (bootstrap, off by default), bootstrap writes one inline policy,
`fermix-server-sessions-need-mfa`, on `admin_role_arn` itself, or on the IAM user it names. Unless
the credentials making the call carry `aws:MultiFactorAuthPresent`, it denies every Systems Manager
action that can run code on the server. A session (`ssm:StartSession`) and Run Command
(`ssm:SendCommand`) are denied on the server's instance, by its tag. Resuming a session, an
automation or change request, a State Manager association and a maintenance window's task or
targets are denied in the whole region: their requests never name the instance, which bootstrap
does not know (`bootstrap/POLICY.md` lists each action and why). IAM checks MFA on each call,
against the caller's own policies, so this is the one place it can hold. It holds your own
credentials to MFA, and no one else's ("Who can open a session"). It writes on your own sign-in
role: a role another system owns may refuse the write (an IAM Identity Center role does), and then
the apply fails on that policy.

Whether a sign-in carries MFA is AWS's to say. STS sets `aws:MultiFactorAuthPresent` on
credentials it issued after an MFA check: an IAM user's console session, and `GetSessionToken` or
`AssumeRole` called with an MFA code. IAM never sets it for a federated sign-in (SAML, OIDC, IAM
Identity Center), whatever your identity provider checked. `aws login` hands the CLI the
credentials of the console session you pick, so they carry MFA only as that session does. A
federated role never does, and AWS does not document whether `aws login`'s refreshed credentials
keep an IAM user's. So `aws login` console-access sessions may not carry MFA: before turning this
on, check what you sign in as (`aws sts get-caller-identity`; an `assumed-role` ARN from a
federated or service sign-in carries none), or try a test deny on a harmless action first.

**Turning this on with a sign-in that carries no MFA refuses every session and command on the
server**, and every automation, association and maintenance-window change in the region
(`AccessDeniedException`, "explicit deny in an identity-based policy"); the deny's `BoolIfExists`
refuses credentials that cannot carry MFA too. Open a session right after the apply. If it is
refused, set `require_session_mfa = false` and apply again: the policy goes, and sessions open
again.

The module configures no Session Manager logging: that is an account-wide setting, outside this
repository. The first boot's prompt does not echo, so even a session log would not hold the code or
the key.

### What the deploy role can reach

The role's own policy (`bootstrap/permissions.tf`, inline: it is longer than a managed policy may
be) names every action `server/` uses; its permissions boundary (`bootstrap/boundary.tf`) is the
ceiling over that policy and anything attached later, and holds the denies, with
`bootstrap/denies.tf`, a managed policy of denies attached to the role, for those the boundary has
no room for. [`bootstrap/POLICY.md`](bootstrap/POLICY.md) lists every action, resource type and
condition in all three. In short:

- `server/terraform.tfstate` and its lock in the state bucket, through the state key; nothing else
  on the key or the bucket.
- EC2 and VPC in the chosen region, on what `server/` makes: each resource created only carrying
  the server stack's tag and changed only while it carries it; a subnet, route table or security
  group only in a tagged VPC; a launch only of Debian's image (`ami_owner_id`), only into a tagged
  subnet and security group, never with an existing interface, and with no key pair, launch
  template or any resource but the seven it uses. No snapshot is ever shared. Of the instance's
  attributes it changes termination protection and the type alone: never its user data, kernel or
  RAM disk, which would run code at the next boot with no session or command to see it.
- KMS keys, SNS topics, DLM policies, the alarm and the budget, each created only with the tag and
  managed only while they carry it; no other key or DLM policy can be given the tag, and no key
  policy is written past KMS's lockout safety check.
- The snapshot bucket, by its exact name (DESIGN.md, "The snapshot bucket is scoped by name, not by
  a tag"): reading its settings, the writes its resources make, each named (tags, ownership,
  versioning, encryption, lifecycle, policy), and deleting its objects to empty it on destroy.
  Every other action on it or its objects is denied: no public access block, ACL, replication,
  website, logging, notification, inventory or Object Lock, and no object read or write. The bucket
  keeps the public access block S3 gives every new bucket, all four settings on, and the role can
  neither change nor delete it.
- The two server roles and the instance profile `bootstrap/` made: read them, pass each to its one
  service, attach `CloudWatchAgentServerPolicy` to the instance role (`enable_cloudwatch_agent`),
  and write an inline policy on the instance role alone (the grant to assume the snapshot writer,
  `enable_s3_backups`). It creates, deletes or retrusts no role or instance profile, changes no
  boundary, and cannot touch the snapshot writer.
- Reading SSM public parameters (the AMI id).

It opens no session on the server: `aws ssm start-session` runs with your own sign-in. It sits at
the IAM root path, outside `/fermix-server/`, so it cannot change itself, and it can neither detach
nor edit its denies.

**What this holds, and what it does not.** Only `admin_role_arn` can assume the role, and
`server/`'s AWS provider assumes it from your own sign-in, so a provider or plugin that misbehaves
holds your credentials, not the role's: these limits contain a mistake in `server/`, or a module
acting through the role, not a malicious binary in the Terraform run. Within the server stack the
role still stops, starts and, once it lifts termination protection (which `allow_destroy` needs),
terminates the server and the home on it. It writes the snapshot bucket's policy and the server
key's policy, and IAM has no condition on a policy's contents, so it could grant another account
Fermix's snapshots in the bucket (each also encrypted with the recovery passphrase). It cannot make
the bucket public: the public access block stays on, out of its reach. Each policy write on the
bucket, made or refused, emails you (rule `fermix-server-bucket-access`, "The session email"): it
is seen, not prevented. The boundary keeps the role to the server stack's resources; it does not
keep it away from the data in them. A security review found no way left for
it to run code on the server or read its disk: it launches only Debian's image and snapshot, makes
no volume from the server's snapshots, attaches none, opens no session, and cannot change the user
data.

### Tags

Both stacks tag everything that takes a tag with `fermix-server-stack`: `bootstrap` on the state
bucket and key, the deploy role, the two server roles and the snapshot writer; `server` on
everything `server/` makes, the root volume and its snapshots included. The deploy role changes an
EC2 resource, a KMS key, an SNS topic, a DLM policy, the alarm or the budget only while it carries
`fermix-server-stack = server`, and after a destroy nothing carrying it remains.

### The agents' signatures

`modules/server/user_data/keys/` holds AWS's two public signing keys for its agents, exactly as AWS
publishes them, and the user data pins each by fingerprint. The first boot downloads each package
and its detached signature over HTTPS from AWS's buckets in the server's region, checks it with
`gpgv` against a keyring holding that one key, requires the signature's primary key to be the
pinned one, and installs nothing on any failure. These are public keys, used only to verify
downloads; no private key is in this repository.

| Agent | Where AWS publishes the key | Fingerprint |
|---|---|---|
| SSM agent (`amazon-ssm-agent.asc`, user id `SSM Agent`), RSA 4096, expires 2027-11-25 | [Verifying the signature of SSM Agent](https://docs.aws.amazon.com/systems-manager/latest/userguide/verify-agent-signature.html) | `1C5B 395C BE5E 74E2 F1CA 2159 2784 DBF3 88D1 9D46` |
| CloudWatch agent (`amazon-cloudwatch-agent.asc`, user id `Amazon CloudWatch Agent`) | `https://amazoncloudwatch-agent.s3.amazonaws.com/assets/amazon-cloudwatch-agent.gpg` | `9376 16F3 450B 7D80 6CBD 9725 D581 6730 3B78 9C72` |

To check them yourself, print each file's fingerprint and compare it with the table, with the
fingerprint the user data pins (`modules/server/user_data/main.tf`), and with the key AWS serves
from the place above:

```sh
gpg --show-keys --with-fingerprint modules/server/user_data/keys/amazon-ssm-agent.asc
gpg --show-keys --with-fingerprint modules/server/user_data/keys/amazon-cloudwatch-agent.asc
curl -fsSL https://amazoncloudwatch-agent.s3.amazonaws.com/assets/amazon-cloudwatch-agent.gpg | gpg --show-keys --with-fingerprint
```

AWS's page above shows the SSM agent's public key: save it to a file and run the same
`gpg --show-keys` on it. The Debian 13 AMI carries no SSM agent, so every first boot installs it
(DESIGN.md, "Other notes"). When AWS publishes the SSM agent's next key, replace
`keys/amazon-ssm-agent.asc` and its fingerprint in `user_data/main.tf` together. The user data is
read once, so existing servers are not touched.

### What CI checks

`.github/workflows/ci.yml` runs on every pull request and push to `main`, with no AWS credentials
and no plan or apply against an account:

- `terraform fmt -check -recursive`;
- `terraform init -backend=false`, `validate` and `test` for `bootstrap/`, `modules/server/` and
  `server/`; the tests use mocked providers, and `bootstrap/tests/sizes.tftest.hcl` a real one with
  fake keys that renders the deploy role's policies locally against IAM's size limits; none makes
  an AWS call;
- the user data a server boots with, rendered with and without the CloudWatch agent, through
  `shellcheck`;
- `tflint` (the recommended Terraform preset and the AWS ruleset, `.tflint.hcl`), failing on any
  notice;
- `trivy config`, failing on any high or critical finding. The one suppression and the accepted
  lower findings are in DESIGN.md.

CI pins what it downloads: the actions by commit, Terraform by version, tflint and trivy by
version and sha256, and tflint's AWS ruleset by version.

## Make it your own

### Safe to change

The variables, in `server/terraform.tfvars` and `bootstrap/terraform.tfvars`:

- `region`: any region where Debian publishes `/aws/service/debian/release/13/latest/arm64` and a
  zone offers your instance type. Use the same one in both stacks. A long region name takes some of
  the deploy role's little remaining policy room (DESIGN.md, "The deploy role's policy is inline,
  under a boundary").
- `instance_type` (a Graviton type: `t4g`, `m7g`, `c7g`, `r7g`, `m8g`, `c8g` or `r8g`),
  `root_volume_gb` (8 to 1024), `availability_zone`, `vpc_cidr` (a `/24` or larger; the subnet is
  its first `/24`). Choose them before the first apply: they shape the instance that holds the
  home.
- `alert_emails` (both stacks), `monthly_budget_usd`, `ebs_snapshot_time_utc`,
  `snapshot_noncurrent_days`.
- The switches: `enable_cloudwatch_agent`, `enable_ebs_snapshots`, `enable_s3_backups` in
  `server/`; `enable_cloudtrail`, `enable_guardduty`, `require_session_mfa` in `bootstrap/`. The
  first and third take effect on a running server only as "Updating" says.

### Change with care

- **Names.** The `fermix-server` prefix, the bucket names, the IAM path `/fermix-server/` and the
  `fermix-server-stack` tag are written in both stacks, scope the deploy role's policy and boundary,
  and are pinned by both stacks' tests. Change them in `bootstrap/locals.tf` and
  `modules/server/locals.tf` together, and the tests with them. The bucket names already carry your
  account id and region; change one only if S3 says it is taken.
- **The deploy role's policy and boundary** are close to IAM's size limits. Find room before adding
  a statement, and run the tests: `bootstrap/tests/` holds each statement by its shape, and
  `sizes.tftest.hcl` fails when a document passes its limit.
- **The user data** runs once, at a server's first boot; a change reaches only servers created
  after it.
- **The image.** `ami_owner_id` and the parameter in `modules/server/instance.tf` move together:
  the deploy role launches only `ami_owner_id`'s images.

### Layout

```
bootstrap/                  once, with your sign-in: state bucket and key, the deploy role,
                            the server roles; its own state in that bucket
  state.tf                  the bucket (versioned, KMS, TLS only, public access blocked) and its key
  permissions.tf            the deploy role's own policy: every action server/ uses, tag-scoped
  boundary.tf               its permissions boundary: the ceiling, and the denies
  denies.tf                 the denies the boundary has no room for, a managed policy on the role
  POLICY.md                 all three, action by action, resource by resource
  roles.tf                  fermix-server-deploy, trusted by admin_role_arn alone
  server_roles.tf           the instance role and profile, DLM's role and the snapshot writer, with fixed trusts
  workload.tf               the boundary on the instance and DLM roles
  sessions.tf               require_session_mfa: the deny on admin_role_arn's sessions without MFA
  trail.tf                  enable_cloudtrail: the least trail that lets EventBridge see API calls
  alerts.tf                 the security alert topic and its key; its rules: sessions, commands,
                            instance attributes, bucket access
  guardduty.tf              enable_guardduty: the region's detector, and its findings to that topic
  tests/                    terraform test, mocked provider; sizes.tftest.hcl renders the policies
                            with the real one, offline, against IAM's size limits
modules/server/             one server
  network.tf                its own VPC, one public subnet, an internet gateway, no NAT gateway
  security_group.tf         nothing in, everything out
  instance.tf               the instance, read once; the destroy guard
  user_data/                the first boot's script (no provider), the agents' keys
  iam.tf                    reads bootstrap's roles; the CloudWatch agent's policy and the snapshot writer grant
  kms.tf storage.tf         the server's key and, with enable_s3_backups, the snapshot bucket
  snapshots.tf              daily EBS snapshots, 7 kept
  alarms.tf                 the status-check alarm; with alert_emails, an SNS topic and a budget
  tests/                    terraform test, mocked provider
server/                     the stack you apply: providers (as the deploy role), the module
.github/workflows/ci.yml    fmt, validate, test, the rendered user data's shellcheck, tflint, trivy
```

### Checking a change locally

None of these needs AWS credentials:

```sh
terraform fmt -check -recursive
for d in bootstrap modules/server server; do
  terraform -chdir=$d init -backend=false && terraform -chdir=$d validate && terraform -chdir=$d test
done
tflint --init && tflint --recursive --config "$PWD/.tflint.hcl" --minimum-failure-severity=notice
trivy config --exit-code 1 --severity HIGH,CRITICAL .
# the user data a server boots with, rendered and linted
terraform -chdir=modules/server/user_data init
for agent in false true; do
  terraform -chdir=modules/server/user_data apply -auto-approve -var region=us-east-1 -var cloudwatch_agent=$agent
  terraform -chdir=modules/server/user_data output -raw script | shellcheck -s sh -
done
```

The user data's `apply` writes a local `terraform.tfstate` in `modules/server/user_data/`, which
`.gitignore` keeps out of the repository.

## License

MIT; see [`LICENSE`](LICENSE).
