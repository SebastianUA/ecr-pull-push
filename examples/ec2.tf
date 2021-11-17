module "DockerRegistryEC2" {
  source = "git@github.com:SebastianUA/terraform.git//aws/modules/ec2?ref=dev"

  name        = "DockerRegistry"
  region      = local.region
  environment = local.environment

  enable_instance = true
  instance_type   = "t3.small"

  ami = {
    us-east-1 = "ami-0bb43378fb0d23c6f"
  }

  instance_associate_public_ip_address = false
  instance_disk_size                   = 8
  instance_tenancy                     = "default"
  instance_iam_instance_profile        = module.DockerRegistryRole.instance_profile_name
  instance_subnet_id                   = "subnet-0dee889c36614e335"
  instance_vpc_security_group_ids = [
    "sg-021967bf804f8fa70",
    module.DockerRegistrySG.security_group_id
  ]
  instance_key_name = module.DockerRegistryEC2KeyPair.aws_key_name


  instance_monitoring = true

  tags = tomap({
    "Environment"   = local.environment,
    "Createdby"     = "Vitalii Natarov",
    "Orchestration" = "Terraform"
  })

  depends_on = [
    module.DockerRegistryRole,
    module.DockerRegistryEC2KeyPair,
    module.DockerRegistrySG
  ]
}