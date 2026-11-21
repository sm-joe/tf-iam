"""Conservative starter catalog. Each rule is a candidate, not verified API coverage."""
def rule(provider, read, write='', delete=''):
    return provider, read.split(), write.split(), delete.split()
RULES = {
 'aws_s3_bucket': rule('aws','s3:ListBucket s3:GetBucketLocation s3:GetBucketTagging s3:GetBucketVersioning s3:GetBucketAcl s3:GetBucketPolicy s3:GetBucketPublicAccessBlock s3:GetEncryptionConfiguration s3:GetBucketOwnershipControls s3:GetBucketLogging s3:GetLifecycleConfiguration s3:GetReplicationConfiguration s3:GetBucketCORS s3:GetBucketWebsite s3:GetBucketRequestPayment s3:GetAccelerateConfiguration s3:GetBucketObjectLockConfiguration','s3:CreateBucket s3:PutBucketTagging','s3:DeleteBucket'),
 'aws_s3_bucket_versioning': rule('aws','s3:GetBucketVersioning','s3:PutBucketVersioning','s3:PutBucketVersioning'),
 'aws_s3_bucket_public_access_block': rule('aws','s3:GetBucketPublicAccessBlock','s3:PutBucketPublicAccessBlock','s3:PutBucketPublicAccessBlock'),
 'aws_s3_bucket_server_side_encryption_configuration': rule('aws','s3:GetEncryptionConfiguration','s3:PutEncryptionConfiguration','s3:PutEncryptionConfiguration'),
 'aws_s3_object': rule('aws','s3:GetObject s3:GetObjectTagging','s3:PutObject s3:PutObjectTagging','s3:DeleteObject'),
 'aws_sqs_queue': rule('aws','sqs:GetQueueAttributes sqs:GetQueueUrl sqs:ListQueueTags','sqs:CreateQueue sqs:SetQueueAttributes sqs:TagQueue sqs:UntagQueue','sqs:DeleteQueue'),
 'aws_dynamodb_table': rule('aws','dynamodb:DescribeTable dynamodb:ListTagsOfResource dynamodb:DescribeTimeToLive dynamodb:DescribeContinuousBackups','dynamodb:CreateTable dynamodb:UpdateTable dynamodb:TagResource dynamodb:UntagResource dynamodb:UpdateTimeToLive dynamodb:UpdateContinuousBackups','dynamodb:DeleteTable'),
 'aws_vpc': rule('aws','ec2:DescribeVpcs ec2:DescribeVpcAttribute ec2:DescribeTags','ec2:CreateVpc ec2:ModifyVpcAttribute ec2:CreateTags ec2:DeleteTags','ec2:DeleteVpc'),
 'aws_subnet': rule('aws','ec2:DescribeSubnets ec2:DescribeVpcs ec2:DescribeTags','ec2:CreateSubnet ec2:ModifySubnetAttribute ec2:CreateTags ec2:DeleteTags','ec2:DeleteSubnet'),
 'aws_instance': rule('aws','ec2:DescribeInstances ec2:DescribeInstanceAttribute ec2:DescribeVolumes ec2:DescribeTags ec2:DescribeInstanceStatus ec2:DescribeImages ec2:DescribeSubnets ec2:DescribeSecurityGroups','ec2:RunInstances ec2:ModifyInstanceAttribute ec2:CreateTags ec2:DeleteTags ec2:StartInstances ec2:StopInstances','ec2:TerminateInstances'),
 'aws_iam_role': rule('aws','iam:GetRole iam:ListRoleTags iam:ListAttachedRolePolicies iam:ListRolePolicies','iam:CreateRole iam:UpdateRole iam:UpdateAssumeRolePolicy iam:TagRole iam:UntagRole','iam:DeleteRole'),
 'aws_iam_policy': rule('aws','iam:GetPolicy iam:GetPolicyVersion iam:ListPolicyVersions iam:ListPolicyTags','iam:CreatePolicy iam:CreatePolicyVersion iam:DeletePolicyVersion iam:TagPolicy iam:UntagPolicy','iam:DeletePolicy iam:DeletePolicyVersion'),
 'aws_iam_role_policy_attachment': rule('aws','iam:ListAttachedRolePolicies','iam:AttachRolePolicy','iam:DetachRolePolicy'),
 'aws_caller_identity': rule('aws','sts:GetCallerIdentity'),
 'aws_ami': rule('aws','ec2:DescribeImages'),
 'google_storage_bucket': rule('gcp','storage.buckets.get','storage.buckets.create storage.buckets.update','storage.buckets.delete'),
 'google_storage_bucket_object': rule('gcp','storage.objects.get','storage.objects.create storage.objects.update','storage.objects.delete'),
 'google_compute_network': rule('gcp','compute.networks.get compute.globalOperations.get','compute.networks.create compute.networks.update compute.networks.patch','compute.networks.delete'),
 'google_compute_subnetwork': rule('gcp','compute.subnetworks.get compute.regionOperations.get','compute.subnetworks.create compute.subnetworks.update','compute.subnetworks.delete'),
 'google_compute_instance': rule('gcp','compute.instances.get compute.zoneOperations.get compute.disks.get compute.machineTypes.get','compute.instances.create compute.instances.setMetadata compute.instances.setLabels compute.instances.setTags compute.instances.setServiceAccount compute.instances.setMachineType compute.instances.start compute.instances.stop compute.disks.create compute.disks.use compute.subnetworks.use compute.subnetworks.useExternalIp compute.images.useReadOnly','compute.instances.delete compute.disks.delete'),
 'google_service_account': rule('gcp','iam.serviceAccounts.get','iam.serviceAccounts.create iam.serviceAccounts.update','iam.serviceAccounts.delete'),
 'google_project': rule('gcp','resourcemanager.projects.get'),
}
for kind, path in {
 'resource_group':'Microsoft.Resources/subscriptions/resourceGroups',
 'virtual_network':'Microsoft.Network/virtualNetworks',
 'subnet':'Microsoft.Network/virtualNetworks/subnets',
 'network_security_group':'Microsoft.Network/networkSecurityGroups',
 'network_interface':'Microsoft.Network/networkInterfaces',
 'public_ip':'Microsoft.Network/publicIPAddresses',
 'storage_account':'Microsoft.Storage/storageAccounts',
 'linux_virtual_machine':'Microsoft.Compute/virtualMachines',
 'windows_virtual_machine':'Microsoft.Compute/virtualMachines',
 'managed_disk':'Microsoft.Compute/disks',
 'user_assigned_identity':'Microsoft.ManagedIdentity/userAssignedIdentities',
 'key_vault':'Microsoft.KeyVault/vaults',
}.items():
    RULES['azurerm_'+kind] = rule('azure',path+'/read',path+'/write',path+'/delete')
EXTRA = {
 'aws_instance': ('iam:PassRole','ec2:RunInstances requires dependency-specific resources; instance profile may require PassRole.'),
 'google_compute_instance': ('iam.serviceAccounts.actAs','Service account and image/network permissions depend on instance configuration.'),
 'azurerm_linux_virtual_machine': ('','Network, disk, identity join and provider registration permissions require review.'),
 'azurerm_windows_virtual_machine': ('','Network, disk, identity join and provider registration permissions require review.'),
 'azurerm_network_interface': ('','Subnet and public IP join permissions require review.'),
 'aws_iam_role_policy_attachment': ('','Restrict attachable policies with IAM conditions; privilege escalation risk.'),
 'aws_iam_role': ('','Require a permissions boundary and review trust policies; privilege escalation risk.'),
 'aws_iam_policy': ('','Policy creation and version changes can enable privilege escalation.'),
}

RULES.update({
 'aws_eks_cluster': rule('aws','eks:DescribeCluster','eks:CreateCluster eks:UpdateClusterConfig eks:UpdateClusterVersion eks:DescribeUpdate eks:TagResource eks:UntagResource','eks:DeleteCluster'),
 'aws_eks_node_group': rule('aws','eks:DescribeNodegroup','eks:CreateNodegroup eks:UpdateNodegroupConfig eks:UpdateNodegroupVersion eks:DescribeUpdate eks:TagResource eks:UntagResource','eks:DeleteNodegroup'),
 'aws_eks_addon': rule('aws','eks:DescribeAddon','eks:CreateAddon eks:UpdateAddon eks:DescribeUpdate eks:TagResource eks:UntagResource','eks:DeleteAddon'),
 'aws_eks_pod_identity_association': rule('aws','eks:DescribePodIdentityAssociation','eks:CreatePodIdentityAssociation eks:UpdatePodIdentityAssociation eks:TagResource eks:UntagResource','eks:DeletePodIdentityAssociation'),
})
