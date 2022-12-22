module "DockerRegistrySG" {
  source = "git@github.com:SebastianUA/terraform.git//aws/modules/sg?ref=master"

  name = "DockerRegistry"

  enable_security_group = true
  security_group_name   = "DockerRegistry-sg-${local.environment}"
  security_group_vpc_id = "vpc-0df458ebc8f78adf8"


  security_group_ingress = [
    {
      from_port = 22
      to_port   = 22
      protocol  = "tcp"

      cidr_blocks = [
        "93.72.109.140/32"
      ]
      ipv6_cidr_blocks = null
      prefix_list_ids  = null
      description      = "SSH from VPC"
      security_groups  = null
      self             = null
    },
    {
      from_port = 443
      to_port   = 443
      protocol  = "tcp"

      cidr_blocks      = null
      ipv6_cidr_blocks = null
      prefix_list_ids  = null
      description      = "TLS from VPC"
      security_groups  = null
      self             = null
    },
    {
      from_port = 80
      to_port   = 80
      protocol  = "http"

      cidr_blocks      = null
      ipv6_cidr_blocks = null
      prefix_list_ids  = null
      description      = "HTTP from VPC"
      security_groups  = null
      self             = null
    }
  ]

  security_group_egress = [
    {
      from_port = 22
      to_port   = 22
      protocol  = "tcp"

      cidr_blocks = [
        "93.72.109.140/32"
      ]
      ipv6_cidr_blocks = null
      prefix_list_ids  = null
      description      = "SSH to VPC"
      security_groups  = null
      self             = null
    },
    {
      from_port = 443
      to_port   = 443
      protocol  = "tcp"

      cidr_blocks      = null
      ipv6_cidr_blocks = null
      prefix_list_ids  = null
      description      = "TLS to VPC"
      security_groups  = null
      self             = null
    },
    {
      from_port = 80
      to_port   = 80
      protocol  = "http"

      cidr_blocks      = null
      ipv6_cidr_blocks = null
      prefix_list_ids  = null
      description      = "HTTP from VPC"
      security_groups  = null
      self             = null
    }
  ]

  tags = tomap({
    "Environment"   = local.environment,
    "Createdby"     = "Vitaliy Natarov",
    "Orchestration" = "Terraform"
  })
}