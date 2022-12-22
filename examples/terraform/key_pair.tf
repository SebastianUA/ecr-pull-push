module "DockerRegistryEC2KeyPair" {
  source = "git@github.com:SebastianUA/terraform.git//aws/modules/key_pair?ref=master"

  enable_key_pair          = true
  key_pair_key_name        = "DockerRegistryEC2KeyPair"
  key_pair_key_name_prefix = null
  key_pair_public_key      = file("~/.ssh/id_rsa.pub")

  tags = local.tags
}