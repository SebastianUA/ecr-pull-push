module "DockerRegistryRole" {
  source = "git@github.com:SebastianUA/terraform.git//aws/modules/iam_role?ref=master"

  name        = "test"
  environment = local.environment

  # Using IAM role
  enable_iam_role             = true
  iam_role_name               = "DockerRegistryRole"
  iam_role_description        = "Role for Docker Registry"
  iam_role_assume_role_policy = file("additional_files/iam/assume_role_policy.json")

  iam_role_force_detach_policies = true
  iam_role_path                  = "/"
  iam_role_max_session_duration  = 3600

  # Using IAM role policy attachment
  enable_iam_role_policy_attachment = true
  iam_role_policy_attachment_policy_arns = [
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/ECRFullAccess",
    "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
  ]

  # Using IAM instance profile
  enable_iam_instance_profile = true
  iam_instance_profile_name   = "DockerRegistryRole"

  tags = local.tags
}