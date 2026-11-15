# Design notes

Why this repository does some things the way it does, for anyone who wants to change it. Each note
says what the code does and why. Where AWS behaves in a way its documentation does not make
obvious, the note says what was observed.

## The snapshot bucket is scoped by name, not by a tag

The deploy role reaches KMS keys, SNS topics and DLM policies only while they carry the server
stack's tag. An S3 bucket cannot be held that way. A tag on a general purpose bucket authorizes
nothing until attribute-based access control is turned on for that bucket (`PutBucketAbac`), from
then on its tags are managed with `TagResource` rather than `PutBucketTagging`, and the call that
turns it on cannot itself be held to the bucket's tag. Until it runs, every `aws:ResourceTag`
condition on a new bucket fails.

So the deploy role reaches one bucket, by its exact name, `fermix-server-snapshots-<account>-<region>`,
which `bootstrap/` and `modules/server/` both build and both stacks' tests pin; the state bucket's
name, `fermix-server-state-<account>-<region>`, does not match it. On it the role may read the
bucket's settings, make the writes `modules/server/storage.tf` makes, each named by IAM's action
for what the pinned provider calls (a wildcard such as `s3:PutBucket*` would let it add an ACL, a
website or any other setting), and delete objects (to empty it on destroy); `bootstrap/denies.tf`
denies every other action on the bucket and its objects, so no public access block, ACL,
replication, website, logging, notification, inventory or Object Lock, and no object read or write.

The module writes no public access block: S3 turns all four settings on for every new general
purpose bucket, made by the API, the CLI, an SDK or CloudFormation as by the console (AWS News
Blog, "Heads-Up: Amazon S3 Security Changes Are Coming in April of 2023"; done in every Region in
April 2023), so the role, denied writing or deleting it (both `s3:PutBucketPublicAccessBlock`),
cannot make the bucket public. A bucket made by an earlier version of this module keeps its block:
`storage.tf`'s `removed` block forgets the resource without deleting it, and `server/`'s next plan
says so ("will no longer be managed by Terraform, but will not be destroyed"). trivy, finding no
`aws_s3_bucket_public_access_block`, reports its four checks as missing (AWS-0086, AWS-0087,
AWS-0091, AWS-0093, high); they are ignored on the bucket alone (`#trivy:ignore`,
`modules/server/storage.tf`), as AWS-0104 is on the egress rule.

## All outbound traffic is allowed

The security group allows all outbound traffic, with no allowlist: iroh's direct paths go to
addresses no list can know, and they are reached with no inbound rule. trivy reports such a rule as
AWS-0104 ("Security group rule allows unrestricted egress to any IP address"), critical, so
`#trivy:ignore:AWS-0104` sits on that one egress block alone (`modules/server/security_group.tf`).
Without it, `trivy config` reports exactly this one critical finding; with it, none high or
critical. Every other check runs.

## The AMI and the user data are read once

The instance carries `lifecycle { ignore_changes = [ami, user_data] }`. A newer Debian 13 image
would otherwise replace the server, and the Fermix home on its root volume with it. AWS stops and
starts an instance to change its user data, and cloud-init runs the script only at the first boot,
so a change after create would restart the primary and install nothing. A change to the script in
this repository (AWS's next SSM agent key, before the current one expires on 2027-11-25) would
restart every existing server on its next apply.

`enable_cloudwatch_agent` and `enable_s3_backups` still move the instance role's policies at every
apply. A `check` warns on every plan when the server booted with the other value, and RUNBOOK.md
says how to change a running server ("Turning metrics on or off later", "Turning S3 backups on or
off later"). `modules/server/tests/read_once.tftest.hcl` proves that a newer AMI and a changed user
data replace nothing.

**And the deploy role cannot write it.** A user data with a boot-time part (`#cloud-boothook`,
`bootcmd`, a per-boot script) runs code at every boot, and a stop, a change and a start put it
there with no Session Manager or Run Command call, which neither the session email nor
`require_session_mfa` sees. `bootstrap/denies.tf` denies `ModifyInstanceAttribute` unless the call
sets termination protection (`allow_destroy`) or the type (`instance_type`), the only attributes
`server/` changes: never the user data, kernel or RAM disk, in either of the API's two forms
(`ec2:Attribute`, the request's attribute name, and `ec2:Attribute/<Name>`, its own field, which
is how the provider calls it). An attribute it does not name is refused too, so a `server/` change
that needs one fails at apply, explicitly denied. Every change of an instance attribute in the
region, or a refused one, sends a security alert email (`fermix-server-instance-attributes`;
README.md, "The session email").

## bootstrap makes the server's roles

IAM cannot hold a trust policy's contents to a condition, so a deploy role that may create a role
may create one that trusts anyone, and pass it on.

So `bootstrap/server_roles.tf` makes `fermix-server-instance` (trusting `ec2.amazonaws.com`, with
`AmazonSSMManagedInstanceCore` and the instance profile) and `fermix-server-dlm` (trusting
`dlm.amazonaws.com` for this account, with `AWSDataLifecycleManagerServiceRole`), both under
`/fermix-server/`, both carrying the server roles' boundary (`bootstrap/workload.tf`). `server/`
reads them by name. The deploy role passes each to its one service, attaches only
`CloudWatchAgentServerPolicy` to the instance role (with `enable_cloudwatch_agent`), and may write
an inline policy on the instance role alone (the grant `enable_s3_backups` needs, which the server
roles' boundary caps). It creates, deletes or retrusts no role and changes no boundary. The roles
stay with `bootstrap/` when the server is destroyed and carry the bootstrap stack's tag.

## The deploy role's policy is inline, under a boundary

A managed policy, and so a permissions boundary, holds at most 6,144 characters. The policy that
names every action `server/` uses, each held to the server stack's tag, is about 10,000. So there
are two documents, both in `bootstrap/`:

- `permissions.tf`: the role's own policy, inline (10,240 characters at most), naming every
  action: EC2 creates only with the tag, EC2 changes only on resources that carry it, reads in the
  region.
- `boundary.tf`: the boundary, a ceiling held by denies that do not depend on what is attached: EC2
  only on resources in the chosen region, and no change to one without the tag (creates and reads
  aside); a launch only of `ami_owner_id`'s image and snapshot, of the seven kinds of resource a
  launch here uses, into a tagged subnet and security group and no existing interface; a tag only
  on create or on what carries the tag; KMS keys, SNS topics, DLM policies, the alarm and the
  budget only with the tag; no other key or DLM policy given the tag; the state key and bucket
  never managed; no snapshot shared; no role or instance profile created, deleted or retrusted and
  no boundary changed; no managed policy but the CloudWatch agent's; no inline policy but on the
  instance role; no role passed beyond EC2 and DLM. Its statements carry no `Sid`, which buys the
  room.

`bootstrap/POLICY.md` lists every action, resource type and condition in both, and
`bootstrap/tests/findings.tftest.hcl` holds each gap a security review of the boundary found on
the boundary's own document.

**Little room is left.** In us-east-1 the boundary is 5,985 of its 6,144 characters and the
policy 9,984 of its 10,240. Both name the region, the boundary 20 times and the policy 31, so a
14-character region (`ap-southeast-2`) in place of `us-east-1` adds about 5 characters each time:
6,085 and 10,139. Anything added to either needs room found first.
`bootstrap/tests/sizes.tftest.hcl` renders every document offline, in us-east-1 and
`ap-southeast-2`, and fails past a limit, before an apply would.

**The denies the boundary has no room for.** Three more denies do not fit: the boundary with them,
without `Sid`s, would be about 7,000 characters in us-east-1. They are a third document,
`bootstrap/denies.tf`, a managed policy of denies alone, which bootstrap attaches to the role
(1,192 characters; 1,202 in `ap-southeast-2`): the snapshot bucket's other actions, a key policy
written past KMS's lockout safety check (`kms:BypassPolicyLockoutSafetyCheck`), and every instance
attribute but termination protection and the type. An explicit deny in any of a role's policies
refuses the request whatever another allows, so they hold over anything attached later as the
boundary's do; the role cannot detach the policy (the boundary denies detaching any policy but the
CloudWatch agent's) or edit it (its IAM rights stop at the two server roles and the instance
profile).

## The VPC's default security group is left alone

AWS creates the default security group with the VPC, without the VPC's tags, and the deploy role
changes only EC2 resources carrying the server stack's tag. So it is left as AWS makes it. Its rules
admit traffic only from its own members, and nothing is one: the instance is in the server's own
security group alone, which has no inbound rule.

## terraform destroy refuses before it removes anything

Termination protection refuses only the instance's termination. Terraform would first destroy the
alarm (which depends on the instance) and, in parallel, everything that does not: the budget, the
DLM policy, the topic, the bucket. A refused destroy would leave the server half removed.

So `terraform_data.destroy_guard` depends on every resource in the stack, a destroy removes it
first, and its destroy-time `local-exec` exits 1 unless the last apply had `allow_destroy = true`.
That apply also lifts termination protection and sets the bucket's `force_destroy`. The guard is a
shell command, so Terraform runs on macOS or Linux.

## The deploy role trusts a role by its full ARN

A session's ARN, `arn:aws:sts::<account>:assumed-role/<RoleName>/<session>`, leaves out the role's
path. When the role you sign in with has one (`arn:aws:iam::<account>:role/<path>/<RoleName>`), a
trust policy naming `role/<RoleName>` names a role that does not exist, and IAM refuses it.

So the README takes `<RoleName>` from the session and the role's own ARN from
`aws iam get-role --role-name <RoleName> --query Role.Arn`, and `admin_role_arn`'s validation
refuses a session ARN.

## The launch's network interface is allowed without a tag

RunInstances authorizes the primary network interface it creates as `network-interface/*` with no
request tags: the instance's tags are not the interface's, and `aws_instance` cannot tag it. A
refused launch's decoded authorization message shows exactly that context
(`aws:Resource network-interface/*`, no `aws:RequestTag`).

So the interface RunInstances creates is allowed on its own, in a subnet and security group held
to the tag. An explicit deny, in the role's policy and in its boundary, refuses a launch into any
existing interface (`network-interface/eni-*`), subnet or security group that does not carry the
tag. `StringNotEqualsIfExists` on `network-interface/*` would not do: IAM evaluates an
`...IfExists` condition as true when the key is absent, so that deny would also refuse the new
interface, which has no tags. The ARN pattern tells the two apart instead: the new interface is
`network-interface/*` in the request, which `network-interface/eni-*` does not match.

## A launch is held to the image's account, not to `ec2:Owner`

For Debian's public images `ec2:Owner` is `amazon`, not Debian's account. A launch held to
`ec2:Owner = 136693071363` is refused by the boundary's deny, and the decoded refusal reads, for
the image, `ec2:Owner: amazon`, `ec2:Public: true`, and the image's account `136693071363`.
`amazon` would also match every image Amazon itself publishes.

So the image and its snapshot are held to `aws:ResourceAccount = ami_owner_id` (a variable in
`bootstrap/`, default `136693071363`, the account Debian publishes its AMIs from), in the role's
policy (allow) and in the boundary (deny for any other account).

## The user data turns sshd off

Debian's image runs `ssh.service`, listening on port 22. Nothing outside reaches it (no inbound
rule, no key pair), but anything inside the VPC could, and Session Manager is meant to be the only
way in.

So the first boot stops and disables `ssh.service`, and masks `ssh.socket` where the image ships
one, before anything else, and logs that it did. `modules/server/tests/server.tftest.hcl`
(`user_data_turns_sshd_off`) holds it; on the server, `ss -ltn` lists nothing on 22.

## S3 backups sign with a bucket-only role

Fermix's first boot lets only root reach the instance metadata service, and the instance role also
carries the SSM agent's rights, so Fermix's own account on the server must never hold the instance
role's credentials. A grant on the instance role itself would put the bucket's rights in every root
process's hands (the SSM, CloudWatch and GuardDuty agents), and a helper would have to assume the
instance role with a session policy, which its fixed trust (EC2 alone) does not allow.

So bootstrap makes a third role, `fermix-server-snapshot-writer` (`server_roles.tf`). Its one
policy puts objects into the snapshot bucket and uses the server key only through S3 for that
bucket. Its trust names the account, held to the instance role by `aws:PrincipalArn`, so a caller
needs a grant of its own. `server/` writes that grant, `sts:AssumeRole` on the writer, as the
instance role's inline policy, with `enable_s3_backups` (on unless set). The helper Fermix's first
boot installs (a root timer, every 15 minutes) assumes the writer with the instance role's
credentials and hands Fermix's account that session alone, which lasts an hour (role chaining caps
it there) and can neither read, list nor delete an object.

Its puts are held to a bucket of your own account (`s3:ResourceAccount`), and Fermix names that
account as the bucket's expected owner on every upload: the bucket's name is predictable and S3's
names are global, so while your bucket does not exist another account could make one of that name.
The server roles' boundary allows `sts:AssumeRole` on the writer and no S3 or KMS right, so the
instance role can never hold the bucket's rights itself. The deploy role's boundary needs nothing
more for this: it already may write the instance role's inline policy, and it cannot touch the
writer.

## Other notes

- **bootstrap's own state lives in its state bucket**, under `bootstrap/terraform.tfstate`. The
  first apply runs on local state through a gitignored `backend_override.tf`, then
  `init -migrate-state` moves the state into the bucket that apply made (README.md, "Step 3: apply
  bootstrap/"). The deploy role cannot reach it.
- **The Debian 13 AMI carries no SSM agent**, so every first boot installs it: the console output
  says `the image has no SSM agent; installing AWS's package`. The image lacks `gpgv` too, and
  carries `curl` and its CA certificates.
- **DLM works within the server roles' boundary as scoped**: a scheduled snapshot of the tagged
  root volume, encrypted with the server key and carrying the stack's tag, is taken by the DLM
  role, whose boundary allows a snapshot only of a tagged volume into a tagged snapshot. DLM may
  begin it well after the scheduled time (37 minutes was seen).
- **The agents' signatures are checked with `gpgv`, not Debian 13's `sqv`.** `sqv` (Sequoia, what
  apt uses on Debian 13) refuses the SSM agent's key: its self-signature uses SHA-1 ("Policy
  rejected non-revocation signature (PositiveCertification) requiring second pre-image resistance;
  SHA1 is not considered secure since 2023-02-01"), seen in a `debian:trixie-slim` container. The
  package signature itself is SHA-256 over RSA 4096. The CloudWatch agent's package signature is
  SHA-1 over RSA 2048 (AWS's 2017 key, fingerprint `9376 16F3 450B 7D80 6CBD 9725 D581 6730 3B78
  9C72`), which `gpgv` 2.4.7 accepts; it is what AWS publishes. The user data installs `gpgv`,
  `curl` and `ca-certificates` from Debian's own signed archive when the image lacks them, and
  requires the signature's primary key to be the pinned fingerprint.
- **The snapshot bucket's KMS rule** refuses an upload that names another encryption, SSE-KMS
  with another key or none, or a key of its own (SSE-C); one that names no encryption gets the
  bucket's default, the server key, and passes. Fermix's uploads name none: its S3 target sends no
  encryption header. A first form of the rule refused that upload too (`AccessDenied ... explicit
  deny in a resource-based policy`): `StringNotEqualsIfExists` is true when the header is absent,
  as with the network interface above. Each deny now also requires its header to be present
  (`Null`, `false`). An SSE-C upload sets no `x-amz-server-side-encryption` header, so it is
  refused on its own header (`...-customer-algorithm`) and by the bucket's encryption rule
  (`blocked_encryption_types = ["SSE-C"]`). S3 already blocks SSE-C on a new bucket, and refuses
  such an upload ("this bucket has blocked upload requests that specify ... SSE-C"); the module
  states the block so the rule holds whatever S3's default. Checked against S3: a header-less
  upload passed and took the server key; AES256, SSE-KMS without a key and SSE-KMS with `aws/s3`
  were refused with the policy's explicit deny.
- **What the deploy role's limits hold.** Only `admin_role_arn` assumes the role, and `server/`'s
  provider assumes it from your own credentials, so its boundary and denies contain a mistake or a
  module acting through the role, not a malicious provider, which holds your credentials. They keep
  the role to the server stack's resources, not away from their data: it still terminates the
  server and the home on it, and writes the bucket's policy and the server key's policy, either of
  which can open the bucket to another account (IAM has no condition on a policy's contents). It
  cannot write the public access block, so it cannot make the bucket public, and each policy write
  on the bucket, made or refused, emails you (`fermix-server-bucket-access`). It cannot change the
  user data, and no way is known for it to run code on the server or read its disk: it launches
  only Debian's image and snapshot, makes no volume from the server's snapshots and attaches none.
  Moving the bucket's and the key's policies into `bootstrap/` would close the other account's way
  in; it is not done here.
- **DLM tags only the stack's snapshots.** `ec2:CreateTags` on every snapshot in the region would
  let the DLM role give any snapshot the server tag and, with it, `DeleteSnapshot` and the snapshot
  removal in README.md, "Removing the server". So the server roles' boundary lets it tag a snapshot
  only in the create that takes it (`ec2:CreateAction` `CreateSnapshot` or `CreateSnapshots`) or
  one already carrying the tag: DLM's tags reach a new snapshot in `CreateSnapshot`'s request (a
  scheduled snapshot passes the boundary's `aws:RequestTag` condition, which only a request's tags
  set) and any it adds later reach a snapshot that has the tag, so the daily snapshot works
  whichever way DLM tags. The policy's `tags_to_add` and `copy_tags` carry only the volume's tags
  and the stack's.
- **bootstrap makes a minimal CloudTrail trail** (`enable_cloudtrail`, on by default): EventBridge
  receives `AWS API Call via CloudTrail` events only while a trail logs them (EventBridge User
  Guide, "AWS service events delivered via AWS CloudTrail"), and the session email needs
  `StartSession`. Without a trail, `StartSession` calls show in CloudTrail's event history and
  trigger the rule no times; with the trail, the next session triggers it within the minute.
- **Only `admin_role_arn`'s sessions cannot be enforced in one account**, so nothing here claims
  to. Session Manager has no resource policy on an instance, and a service control policy never
  applies in an organization's management account. The server's side was tried: the server roles'
  boundary denied `ssmmessages:OpenDataChannel` unless `ssm:resourceTag/aws:ssmmessages:session-id`
  (the tag Session Manager gives a session, the starter's user id) was like the owner role's
  `<unique id>:*`. The owner's session opened; with the pin set to an id that is nobody's, it opened
  too, 45 seconds and again 3 minutes after the change. The agent's data channel is not checked
  against the tag, so the deny guarded nothing and was removed; the session email is the control
  that holds.
- **The session email's rule lives in bootstrap, not server/,** with GuardDuty's, and both match
  the whole account and region. The deploy role's boundary has no room for EventBridge (tag-scoped
  rule rights need 240 characters or more), so what cannot fit moved into bootstrap rather than
  widening the role. bootstrap does not know the instance id, so it cannot filter on it; the email
  names the instance. They send to bootstrap's own topic, `fermix-owner-security-alerts`, which
  takes messages from those rules alone, by their ARNs. Not to server/'s `fermix-server-alerts`:
  the deploy role manages that topic and could unsubscribe you or delete it, silencing the alerts
  that watch it. The security topic is named outside the deploy role's `fermix-server-*` scope and
  encrypted with its own key, tagged `bootstrap`; both stacks' tests hold that the role reaches
  neither.
- **`alert_emails` is one list for both** the status-check alarm's topic and the budget, in
  `server/`; bootstrap's `alert_emails` is the security alerts' own.
- **The budget counts the whole account**, before credits, at 50, 80 and 100%: a budget on the
  server's resources alone needs a cost allocation tag turned on in the payer account, outside this
  repository.
- **The status-check alarm watches `StatusCheckFailed_Instance`** and notifies, nothing more: a
  failed system check is automatic recovery's (`maintenance_options { auto_recovery = "default" }`).
- **`ebs_snapshot_time_utc`** (default `03:00`, before Fermix's nightly update at 04:00 UTC) is a
  variable.
- **The availability zone is read once**: with `availability_zone` unset, the first zone in name
  order that offers the instance type, kept by `ignore_changes` so a change in offerings never moves
  the subnet.
- **DLM snapshots carry the stack's tag twice over**: copied from the volume and added by the
  policy (`tags_to_add`), the tag the DLM role must find to delete one.
- **Lower trivy findings, accepted:**
  - AWS-0089 (low), on both buckets: no server access logging. The state bucket is reached only by
    Terraform and the snapshot bucket by the snapshot writer's puts; access logs need a third
    bucket, and CloudTrail already records who changed either.
  - AWS-0094 (low), on the snapshot bucket: no `aws_s3_bucket_public_access_block`. It keeps S3's
    own, all four settings on ("The snapshot bucket is scoped by name, not by a tag").
  - AWS-0178 (medium): no VPC flow logs. The VPC holds one instance with no inbound rule; flow logs
    cost a log group or a bucket for traffic that is all the server's own outbound.
  - On the trail (`bootstrap/trail.tf`): AWS-0014 (medium), a single-region trail; AWS-0162 (low),
    no CloudWatch Logs; AWS-0089 (low), no access logging on its bucket. The trail exists so that
    EventBridge sees this region's Session Manager calls, and keeps its logs 90 days, as
    CloudTrail's own event history does; every other region, a log group and a fourth bucket would
    cost more for nothing the server uses.
- **Terraform 1.16.6's test output crashes** ("value has marks, so it cannot be serialized as
  JSON") when it prints a failing assertion that iterates a splat or a whole resource; the tests
  name attributes one by one.
