# Mixed Infrastructure Lifecycle Acceptance

This Maintainer Workflow Tests A Dedicated Private VPC, Two Indexed Subnets, Route Table Associations, Security Group, EC2 Instance, IAM Role And Instance Profile, And Random-Named S3 Bucket. It Does Not Test Public Gateways Or Arbitrary Terraform Configurations. AWS Provider 6.73.0 Is Pinned. EC2 And Storage Can Incur Charges Until Cleanup.

Use A Disposable AWS Account, A Read-Capable Planner With Access Analyzer Permissions, A Separate IAM Auditor, And A Dedicated Assumable Applier Role. The Applier Must Have No Extra Identity Grants. An Administrator Must Review And Replace Its Policies With The Exact Phase Bundle Before Each Apply. Account-Level SCPs, Boundaries And Session Policies Still Apply. No Automatic IAM Attachment Or Administrator Fallback Is Provided.

From A Clean Checkout Of This Branch:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[aws,test]'
export ACCOUNT=$(aws sts get-caller-identity --profile tfiam-planner --query Account --output text)
export FIXTURE="$HOME/tfiam-mixed-$(date +%s)"
python scripts/accept-mixed.py prepare "$FIXTURE" --account "$ACCOUNT" --region us-east-1
```

For Each Phase (Create, Then Update, Then Destroy), Prepare A Plan:

```bash
export PHASE=create
python scripts/accept-mixed.py plan "$FIXTURE" --account "$ACCOUNT" --phase "$PHASE" --planner-profile tfiam-planner --confirm-isolated-aws-account
```

Review The JSON Documents In `$FIXTURE/$PHASE-policies`. An Administrator Must Replace The Dedicated Applier Role's Existing Identity Policies With Exactly This Bundle (Do Not Attach The Manifest Or Validation Reports). Stop If Planning Or Validation Fails.

```bash
python scripts/accept-mixed.py apply "$FIXTURE" --account "$ACCOUNT" --phase "$PHASE" --test-profile tfiam-applier --audit-profile tfiam-auditor --role-name tfiam-mixed-applier --confirm-isolated-aws-account
```

Repeat The Plan And Apply Commands With `PHASE=update`, Then `PHASE=destroy`. The Runner Rejects Unexpected Operations And Checks The Exact Identity Grant Union Before And After Apply. Update Must Include At Least One Real In-Place Change; Destroy Must Leave Empty Terraform State.

The Private `fixture.json` Records Phase Outcomes, Plan Hashes And Session Identity. Logs, Plans And State Are Sensitive; Do Not Commit Or Upload Them. If A Phase Fails, Preserve State And Logs, Review The Failure And Arrange Authorized Cleanup. Do Not Delete The Fixture Directory Until Cleanup Is Independently Confirmed. The Runner Does Not Automatically Retry Failed Plans Or Apply With Elevated Credentials.

A Successful Offline Test Is Not Live Acceptance. Only A Completed Run With All Three Phases Passed And Verified Empty State Demonstrates This Fixture's Lifecycle Under The Reviewed Grants. Empty State Alone Does Not Establish That Every AWS Resource Was Removed.


## Alternative: Storage And Messaging Suite

If EC2 Is Not Approved In Your Testing Account, Use The Separate Storage And Messaging Fixture In A New Directory. Obtain Normal Organization Approval For S3, SQS And DynamoDB; This Is Not A Workaround For Denied Operations.

```bash
export OLD_FIXTURE="$FIXTURE"
export FIXTURE="$HOME/tfiam-storage-$(date +%s)"
python scripts/accept-mixed.py prepare "$FIXTURE" --account "$ACCOUNT" --region us-east-1 --suite storage-messaging
```

Use The Same Plan, Reviewed Policy Attachment And Apply Commands For Each Phase. The Suite Creates A Private Random-Named Versioned S3 Bucket, An Encrypted SQS Queue And An On-Demand DynamoDB Table. Update Changes The Queue Visibility Timeout And Resource Tags. No EC2, VPC Or IAM Workload Role Is Created. No Objects, Messages Or Table Items Are Inserted. Charges May Still Apply.

Preserve The Old Fixture And Arrange Authorized Cleanup Of Its Partially Created Resources. Never Repoint The New Fixture At Existing State Or Treat This Suite As EC2 Acceptance Evidence.
