# What the deploy role may do, action by action

`fermix-server-deploy` holds one inline policy, `permissions.tf`, under one permissions boundary,
`boundary.tf`, and one managed policy of denies alone, `denies.tf`, for the denies the boundary has
no room for. Its rights are the policy's and the boundary's intersection: an action must be
allowed by both and denied by none of the three. The policy names each action and its condition;
the boundary is the ceiling, and its denies and `denies.tf`'s hold whatever else is ever attached
to the role (an explicit deny in any of a role's policies refuses the request whatever another
allows, and the role can neither detach nor edit `denies.tf`'s policy). `tests/bootstrap.tftest.hcl`
holds every row by the policies' shape (a mocked plan cannot evaluate IAM), and each of those
assertions was first seen to fail on a policy that broke it.

`tag` is `fermix-server-stack = server`, the server stack's tag. "Request tag" is
`aws:RequestTag/fermix-server-stack = server` on the request that creates the resource; "resource
tag" is `aws:ResourceTag/fermix-server-stack = server` on a resource that exists. `<region>` is
`var.region`; `<account>` is the account `admin_role_arn` names.

Size: IAM allows 6,144 characters for a managed policy and 10,240 for a role's inline policies,
counted without whitespace. In us-east-1 the boundary is 5,985 (its statements carry no `Sid` to
keep room), the policy 9,984, the denies 1,192 and the server roles' boundary 3,405; in a
14-character region (`ap-southeast-2`) 6,085, 10,139, 1,202 and 3,455. `tests/sizes.tftest.hcl`
renders all four, offline, in both regions and fails past a limit. DESIGN.md, "The deploy role's
policy is inline, under a boundary", says what a longer region name costs.

Each gap a security review of the boundary found is held on the boundary's document itself by
`tests/findings.tftest.hcl`, which numbers and names them, one assertion per closing statement:
undoing any one fails it. A later review's four (the snapshot bucket's writes, the lockout check,
DLM's tags, the user data) are held there too, on the documents that close them.

"Tag keys" is `ForAllValues:StringEquals aws:TagKeys`: a request may write the stack's tag key
alone (and `Name` on EC2). The boundary holds it on every statement that creates or tags.
A change that passes either limit fails `bootstrap/` loudly at apply.

## `ec2:RunInstances`, by the resource types it authorizes

| Resource type | Role's policy | Boundary | Why |
|---|---|---|---|
| `instance` | request tag, tag keys `fermix-server-stack` and `Name` only | allowed type | the instance is created carrying the tag |
| `volume` | request tag, same keys | allowed type | `volume_tags` tag the root volume in RunInstances itself |
| `network-interface` (created) | allowed, no condition | allowed type | EC2 gives the request no tags for the interface it creates, and `aws_instance` cannot tag it |
| `network-interface` (existing) | denied without the resource tag (`network-interface/eni-*`) | denied the same | a launch never takes another workload's interface; the created one is `network-interface/*` in the request, which `eni-*` does not match |
| `subnet` | resource tag; denied without it | allowed type; denied without it | the server's own subnet |
| `security-group` | resource tag; denied without it | allowed type; denied without it | the server's own security group |
| `image` | `aws:ResourceAccount = ami_owner_id` (Debian, `136693071363`) | denied for any other account (`arn:aws:ec2:*::*`) | only the AMI publisher's image launches (`ec2:Owner` reads `amazon` for Debian's images: DESIGN.md, "A launch is held to the image's account, not to `ec2:Owner`") |
| `snapshot` (the image's) | `aws:ResourceAccount = ami_owner_id` | denied for any other account | the root volume is made only from that image's snapshot |
| `key-pair` | not allowed | denied (not one of the seven types) | no SSH, no key pair |
| `launch-template` | not allowed | denied | unused |
| `placement-group`, `group` | not allowed | denied | unused |
| `capacity-reservation` | not allowed | denied | unused |
| `elastic-gpu`, `elastic-inference` | not allowed | denied | unused |
| `license-configuration` | not allowed | denied | unused |
| `spot-instances-request` | not allowed | denied | on-demand only |
| `secondary-interface`, `secondary-subnet` | not allowed | denied | unused |

The boundary's deny lists the seven types a launch here uses as `NotResource`, so a type AWS adds
later is denied too.

## Every other action

| Service | Actions | Resource | Role's policy | Boundary | Why |
|---|---|---|---|---|---|
| S3 | `ListBucket`; `GetObject`, `PutObject`, `DeleteObject` | the state bucket; `server/terraform.tfstate` and its `.tflock` | exact ARNs | `server/terraform.tfstate*`; everything else on the bucket and its objects denied | server/'s state, and nothing of the bucket's own settings |
| S3 | any | `bootstrap/terraform.tfstate*`, bootstrap's own state and lock in the same bucket | not allowed | denied | bootstrap's state is the owner's alone |
| KMS | `Decrypt`, `Encrypt`, `GenerateDataKey` | the state key | exact ARN | the same; everything else on the key denied | the state's encryption |
| EC2 | `Describe*` | `*` | `aws:RequestedRegion = <region>` | allowed | reads |
| EC2 | `CreateVpc` | `vpc/*` | request tag, tag keys | not denied by the untagged-change deny (it creates) | a tagged VPC |
| EC2 | `CreateSubnet`, `CreateRouteTable`, `CreateSecurityGroup` | the new subnet, route table, security group | request tag, tag keys | the same | created carrying the tag |
| EC2 | the same | the VPC they go into | resource tag; denied without it (`vpc/vpc-*`) | denied without it | never into another VPC |
| EC2 | `CreateInternetGateway` | `internet-gateway/*` | request tag, tag keys | the same | |
| EC2 | `CreateTags` | any EC2 resource in `<region>` | only with `ec2:CreateAction` one of the six creates, or on a resource with the resource tag (tag keys `fermix-server-stack`, `Name`; the stack tag's value never changed) | denied without the resource tag unless `ec2:CreateAction` is set | no other resource can be given the tag |
| EC2 | `ModifyVpcAttribute`, `DeleteVpc`, `ModifySubnetAttribute`, `DeleteSubnet`, `Attach`/`Detach`/`DeleteInternetGateway`, `CreateRoute`, `ReplaceRoute`, `DeleteRoute`, `AssociateRouteTable`, `DisassociateRouteTable`, `DeleteRouteTable`, `AuthorizeSecurityGroupEgress`, `RevokeSecurityGroupEgress`, `RevokeSecurityGroupIngress`, `DeleteSecurityGroup`, `Start`/`Stop`/`TerminateInstances`, `ModifyInstanceMetadataOptions`, `ModifyInstanceMaintenanceOptions`, `ModifyVolume`, `DeleteTags` | any EC2 resource in `<region>` | resource tag | every EC2 action but the reads and the creates denied on a resource without the tag | changes only what server/ made |
| EC2 | `ModifyInstanceAttribute` | the instance | resource tag (with the changes above) | denied without the tag; `denies.tf` denies it unless the call sets termination protection or the type (`ec2:Attribute/DisableApiTermination` or `ec2:Attribute/InstanceType` present, or `ec2:Attribute` one of `disableApiTermination`, `instanceType`), so never the user data, kernel or RAM disk | `allow_destroy` and `instance_type`; the user data is read once (DESIGN.md, "The AMI and the user data are read once") and runs code at the next boot with no session or command to see it |
| EC2 | any other action | | not allowed | allowed only on `<region>` resources with tag keys, and denied on any without the tag, so a create of any other kind (snapshot, image, key pair, launch template) is denied too; nothing that authorizes on no resource (an account's EC2 settings) | |
| EC2 | `ModifySnapshotAttribute` | `*` | not allowed | denied (and in the server roles' boundary) | no snapshot is ever shared or made public |
| KMS | `CreateKey`, `TagResource` | `*` (a key is tagged at create only through a statement on no particular key) | request tag, tag keys, `aws:RequestedRegion` | request tag, tag keys, region | a key is created carrying the tag |
| KMS | `TagResource`, `UntagResource` | any existing key | resource tag | denied on any key without it, in any region | no key, the state key included, can be given the tag |
| KMS | `DescribeKey`, `GetKeyPolicy`, `GetKeyRotationStatus`, `ListResourceTags`, `PutKeyPolicy`, `EnableKeyRotation`, `UpdateKeyDescription`, `ScheduleKeyDeletion`, `GenerateDataKeyWithoutPlaintext`, `Decrypt`, `ReEncryptFrom`, `ReEncryptTo` | keys in `<region>` | resource tag | `kms:*` with the resource tag and tag keys | the server key, through its life |
| KMS | `CreateKey`, `PutKeyPolicy` with `kms:BypassPolicyLockoutSafetyCheck` true | `*` | allowed by the rows above | `denies.tf` denies it | no key policy skips KMS's lockout safety check; server/ never sets `bypass_policy_lockout_safety_check`. IAM has no condition on a key policy's contents (README.md, "What the deploy role can reach") |
| KMS | `CreateGrant` | keys in `<region>` | resource tag and `kms:GrantIsForAWSResource` | resource tag | EC2's grant on the encrypted root volume |
| KMS | `CreateAlias`, `DeleteAlias`, `UpdateAlias` | `alias/fermix-server` | exact alias | the same alias only (and authorized on the key it names, which is held to the tag) | the server key's name |
| KMS | `ListAliases` | `*` | its own statement | its own statement | reading the aliases |
| S3 | the snapshot bucket: `CreateBucket`, `DeleteBucket`, `ListBucket`, `ListBucketVersions`, `GetBucket*`, `Get*Configuration`; the writes, one per resource in `modules/server/storage.tf`: `PutBucketTagging` (the bucket's tags), `PutBucketOwnershipControls`, `PutBucketPublicAccessBlock`, `PutBucketVersioning`, `PutEncryptionConfiguration`, `PutLifecycleConfiguration`, `PutBucketPolicy`, `DeleteBucketPolicy` (each resource's delete is its write's action) | `fermix-server-snapshots-<account>-<region>` | exact name | the same name | by name, not tag (DESIGN.md, "The snapshot bucket is scoped by name, not by a tag"); what the pinned provider calls |
| S3 | `DeleteObject`, `DeleteObjectVersion` | its objects | exact name | `DeleteObject*` there | emptying it on destroy (`allow_destroy`) |
| S3 | any other action: `PutBucketAcl`, `PutReplicationConfiguration`, `PutBucketWebsite`, `PutBucketCORS`, `PutBucketLogging`, `PutBucketNotification`, `PutInventoryConfiguration`, `PutBucketObjectLockConfiguration`, `PutBucketAbac`, `PutAccelerateConfiguration`, `PutObject`, `GetObject`, ... | the bucket and its objects | not allowed | `denies.tf` denies everything but the two rows above (`NotAction`), and `ListTagsForResource`, `TagResource`, `UntagResource`, which nothing allows | no ACL, replication, website or other bucket write nothing here uses, and no object read or write. The provider tries the last three first and, refused, falls back to `GetBucketTagging` and `PutBucketTagging`; they stay unallowed rather than denied, the refusal it has always had |
| IAM | `GetRole`, `GetInstanceProfile`, `ListAttachedRolePolicies`, `ListRolePolicies` | the two server roles and the instance profile | exact ARNs | `Get*`, `List*` there | server/ reads them by name |
| IAM | `PassRole` | the instance role; the DLM role | to `ec2.amazonaws.com`; to `dlm.amazonaws.com` | to EC2 or DLM only | each role to its one service |
| IAM | `AttachRolePolicy`, `DetachRolePolicy` | the instance role | `iam:PolicyARN = CloudWatchAgentServerPolicy` | denied for any other policy | the CloudWatch agent (`enable_cloudwatch_agent`) |
| IAM | `PutRolePolicy`, `GetRolePolicy`, `DeleteRolePolicy` | the instance role | exact ARN | denied on any other role | the grant to assume the snapshot writer (`enable_s3_backups`); the server roles' boundary caps whatever it says |
| IAM | `CreateRole`, `DeleteRole`, `Update*Role*` (`UpdateRole`, `UpdateRoleDescription`, `UpdateAssumeRolePolicy`), `CreateInstanceProfile`, `DeleteInstanceProfile`, `*RoleToInstanceProfile`, `*RoleFromInstanceProfile`, `*RolePermissionsBoundary` | | not allowed | denied on `*` | bootstrap makes the roles with fixed trusts (DESIGN.md, "bootstrap makes the server's roles"); IAM cannot hold a trust policy's contents to a condition |
| IAM | any policy write (`CreatePolicy`, `CreatePolicyVersion`, ...) | | not allowed | not allowed (IAM reaches the three ARNs only) | |
| SNS | `CreateTopic`, `TagResource` | `fermix-server-*` | request tag | request tag, tag keys, on `fermix-server-*` only | the alert topic is created carrying the tag (tried live: a tagged create passes the deny below) |
| SNS | `TagResource`, `UntagResource` | any existing topic | resource tag | denied on any topic without it | no other topic can be given the tag (tried live: the role cannot even read a `fermix-server-*` topic the owner made without it) |
| SNS | `GetTopicAttributes`, `SetTopicAttributes`, `DeleteTopic`, `ListTagsForResource`, `TagResource`, `UntagResource`, `Subscribe` | `fermix-server-*` | resource tag | `sns:*` with the resource tag and tag keys | |
| SNS | `GetSubscriptionAttributes`, `SetSubscriptionAttributes`, `Unsubscribe` | `fermix-server-*` | name | name | a subscription has no tags of its own; its ARN is its topic's and an id |
| DLM | `CreateLifecyclePolicy`, `TagResource` | policies in `<region>` | request tag, tag keys | request tag, tag keys, region | created carrying the tag |
| DLM | `TagResource`, `UntagResource` | any existing policy | resource tag | denied on any policy without it (`policy/policy-*`) | no other DLM policy can be given the tag |
| DLM | `GetLifecyclePolicy`, `UpdateLifecyclePolicy`, `DeleteLifecyclePolicy`, `ListTagsForResource` | policies in `<region>` | resource tag | `dlm:*` with the resource tag and tag keys | |
| CloudWatch | `PutMetricAlarm`, `TagResource` | alarms `fermix-server-*` | request tag, tag keys (create) or resource tag (change) | the same, tag keys on both | the status-check alarm |
| CloudWatch | `DescribeAlarms`, `DeleteAlarms`, `ListTagsForResource`, `UntagResource` | alarms `fermix-server-*` | resource tag | `cloudwatch:*` with the resource tag | |
| Budgets | `ModifyBudget`, `TagResource` | budgets `fermix-server-*` | request tag, tag keys (create) or resource tag (change) | the same, tag keys on both | the monthly budget |
| Budgets | `ViewBudget`, `ListTagsForResource`, `UntagResource` | budgets `fermix-server-*` | resource tag | `budgets:*` with the resource tag | |
| SSM | `GetParameter`, `GetParameters` | `parameter/aws/service/*` in `<region>` | exact path | the same | the AMI id; the role opens no session and sends no command |
| CloudTrail, EventBridge, GuardDuty | any | | not allowed | not allowed (no statement names them) | the trail, the rules and the detector are bootstrap's, the owner's (`trail.tf`, `alerts.tf`, `guardduty.tf`) |
| SNS, KMS | the security alert topic `fermix-owner-security-alerts` and its key | | no SNS grant matches the topic; every KMS grant that matches the key needs the server tag, which it never carries | the same | the alerts that watch the deploy role cannot be silenced by it (`tests/bootstrap.tftest.hcl`, by ARN match) |

## What the server roles may do (`workload.tf`)

The boundary on `fermix-server-instance` and `fermix-server-dlm`, whatever either is given.

| Actions | Resource | Condition | Why |
|---|---|---|---|
| the 25 actions of `AmazonSSMManagedInstanceCore` | `*` | | Session Manager's agent |
| `cloudwatch:PutMetricData` | `*` | `cloudwatch:namespace = CWAgent` | the CloudWatch agent's metrics |
| `ec2:DescribeVolumes`, `ec2:DescribeTags`; DLM's `Describe*` reads | `*` | `aws:RequestedRegion` for DLM's | reads |
| `ec2:CreateSnapshot`, `ec2:CreateSnapshots` | volumes and instances in `<region>` | resource tag | DLM snapshots only the server stack's volume |
| the same | `snapshot/*` | request tag | into a snapshot carrying the tag (copied and added by the policy) |
| `ec2:DeleteSnapshot` | `snapshot/*` | resource tag | DLM expires only the snapshots it took |
| `ec2:CreateTags` | `snapshot/*` in `<region>` | `ec2:CreateAction` `CreateSnapshot` or `CreateSnapshots`; or, its own statement, resource tag | DLM tags a snapshot while it takes it or once it carries the tag, whichever way it tags; no other snapshot is ever tagged into the stack, and so into `DeleteSnapshot` above or the snapshot removal in README.md, "Removing the server" |
| `events:*Rule*`, `*Targets*` | `rule/AwsDataLifecycleRule.managed-cwe.*` | | DLM's own rules |
| KMS use through EC2 | keys in `<region>` | `kms:ViaService = ec2.<region>.amazonaws.com` | the encrypted volume's snapshots; the server key's policy names the DLM role |
| `sts:AssumeRole` | `fermix-server-snapshot-writer` | | the instance role's grant, written by server/ with `enable_s3_backups`; no S3 or KMS right on the bucket is ever here |
| `ec2:ModifySnapshotAttribute` | `*` | denied | no snapshot is ever shared |

## The snapshot writer (`server_roles.tf`)

`fermix-server-snapshot-writer`, no boundary (bootstrap alone writes it; the deploy role's boundary
refuses every IAM write on it). Its trust: the account, `sts:AssumeRole`, only where
`aws:PrincipalArn` is the instance role, so the instance role needs its own grant too (server/'s,
with `enable_s3_backups`). Sessions last an hour at most, as role chaining does anyway.

| Actions | Resource | Condition | Why |
|---|---|---|---|
| `s3:PutObject` | `fermix-server-snapshots-<account>-<region>/*` | `s3:ResourceAccount = <account>` | Fermix's snapshots; no read, list or delete. The name is predictable and global, so a bucket of that name in another account takes nothing |
| `kms:GenerateDataKey` | keys in `<region>` | `kms:ViaService = s3.<region>.amazonaws.com`, `kms:EncryptionContext:aws:s3:arn` the bucket or an object in it | the bucket's default encryption, the server key |

## On `admin_role_arn` (`sessions.tf`, with `require_session_mfa`)

One inline policy, `fermix-server-sessions-need-mfa`, on the owner's own role (or IAM user): every
Systems Manager action that can run code on the server, denied unless the call's credentials carry
MFA (`BoolIfExists aws:MultiFactorAuthPresent = false`, so credentials that cannot carry it are
refused too). Where the request names the instance, the deny holds on it by its tag; where it names
none, in the whole region, since bootstrap does not know the instance id.

| Action | Authorized on (Service Authorization Reference) | Deny's resource and condition | Why |
|---|---|---|---|
| `ssm:StartSession` | the instance, the session document | `instance/*` in `<region>`, `ssm:resourceTag/fermix-server-stack = server` | a shell on the server |
| `ssm:SendCommand` | the document, each instance (one reached through `Targets` too: its results say `AccessDenied`) | the same | Run Command runs as root |
| `ssm:ResumeSession` | the session | `*`, `aws:RequestedRegion = <region>` | reconnects to an open session |
| `ssm:StartAutomationExecution` | the automation document and execution | the same | an automation's steps run commands on targets they name |
| `ssm:StartChangeRequestExecution` | the change template and execution | the same | a change request runs an automation |
| `ssm:CreateAssociation`, `ssm:CreateAssociationBatch` | the document, the instance when named (`Targets` names a tag) | the same | State Manager runs the document on its targets |
| `ssm:UpdateAssociation` | the association, its document and instance | the same | changes what an association runs and where, and runs it |
| `ssm:StartAssociationsOnce` | the association | the same | runs an association now |
| `ssm:RegisterTaskWithMaintenanceWindow`, `ssm:UpdateMaintenanceWindowTask` | the maintenance window, its task | the same | a window's task runs a command or an automation |
| `ssm:RegisterTargetWithMaintenanceWindow`, `ssm:UpdateMaintenanceWindowTarget` | the maintenance window | the same | points a window's tasks at the server |

Not covered, since they are not Systems Manager: EC2 actions that read or replace the disk, or
change the user data and restart the instance (README.md, "Who can open a session").
