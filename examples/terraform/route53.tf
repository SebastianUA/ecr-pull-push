module "DockerRegistryRoute53" {
  source = "git@github.com:SebastianUA/terraform.git//aws/modules/route53?ref=master"

  name        = "DockerRegistryRoute53"
  environment = local.environment

  # Route53 record
  enable_route53_record         = true
  route53_record_parent_zone_id = local.route53_zone_id
  route53_record_type           = local.route53_record_type
  route53_record_name           = local.route53_record_name
  route53_record_ttl            = 300
  route53_record_records = [
    "${data.aws_caller_identity.current.account_id}.dkr.ecr.${local.region}.amazonaws.com"
  ]

  tags = local.tags

}