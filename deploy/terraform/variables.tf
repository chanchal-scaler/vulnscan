variable "region" {
  description = "AWS region to deploy into."
  type        = string
}

variable "vpc_id" {
  description = "Existing VPC to deploy into. It must have an internet gateway attached and should hold nothing else."
  type        = string
}

variable "subnet_cidr" {
  description = "Unused CIDR inside vpc_id for vulnscan's own subnet."
  type        = string
}

variable "github_org" {
  description = "GitHub orgs whose repos may be scanned, comma-separated (VULNSCAN_GITHUB_ORG)."
  type        = string
}

variable "source_repo" {
  description = "GitHub repo holding the vulnscan code, as org/name. The instance clones it to build the image."
  type        = string
}

variable "source_ref" {
  description = "Branch or tag of source_repo to build."
  type        = string
  default     = "main"
}

variable "name" {
  description = "Name used for every resource."
  type        = string
  default     = "vulnscan"
}

variable "instance_type" {
  description = "EC2 instance type. Graviton (t4g) is cheapest; x86 types also work."
  type        = string
  default     = "t4g.large"
}

variable "root_volume_gb" {
  description = "Root volume size: OS, Docker image (~2 GB) and clones during a scan. Can be grown later."
  type        = number
  default     = 20
}

variable "data_volume_gb" {
  description = "Size of the separate volume that holds the reports (~1 MB per scan). Can be grown later."
  type        = number
  default     = 5
}

variable "ssm_prefix" {
  description = "Parameter Store path for the tokens. The instance can read nothing outside it."
  type        = string
  default     = "/vulnscan"
}
