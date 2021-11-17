locals {
  region      = "us-east-1"
  environment = "dev"

  route53_zone_id     = "Z66BZRIWWZ5MH9"
  route53_record_type = "CNAME"
  route53_record_name = "docker-ecr.internal.natarov.io"
}