variable "vpc-cidr" {
  default = "10.0.0.0/16"
}

variable "pubsub01-cidr" {
  default = "10.0.1.0/24"
}
variable "pubsub02-cidr" {
  default = "10.0.2.0/24"

}
variable "prvtsub01-cidr" {
  default = "10.0.3.0/24"
}
variable "prvtsub02-cidr" {
  default = "10.0.4.0/24"
}
variable "all-cidr" {
  default = "0.0.0.0/0"
}
variable "az1" {
  default = "eu-west-3a"
}
variable "az2" {
  default = "eu-west-3b"
}
variable "ami_SQ" {
  default = "ami-05b5a865c3579bbc4"
}
variable "instance_type" {
  default = "t2.medium"
}
variable "path_public_key" {
  default     = "~/keypair/et1pacujp1_rsa.pub"
  description = "path to my public key"
}
variable "path_private_key" {
  default     = "~/keypair/et1pacujp1_rsa"
  description = "path to my private key"
}
variable "keyname" {
  default = "et1pacujp1_rsa"
}
variable "port_ssh" {
  default     = "22"
  description = "ssh port"
}

variable "port_proxy" {
  default     = "8080"
  description = "port for docker proxy"
}

variable "port_http" {
  default     = "80"
  description = "http port"
}

variable "port_https" {
  default     = "443"
  description = "https port"
}

variable "port_sonar" {
  default     = "9000"
  description = "Sonarqube port"
}

variable "port_nexus" {
  default     = "8081"
  description = "port nexus"
}

variable "port_mysql" {
  default     = "3306"
  description = "Mysql port"
}

variable "ami" {
  default = "ami-0d767e966f3458eb5"
}

variable "database_username" {
  default     = "admin"
  description = "database"
}
variable "database_password" {
  default     = "admin123"
  description = "database"
}

variable "db_name" {
  default = "ET1PACUJP1_name"
}

variable "db_identifier" {
  default = "et1pacujp1-name"
}

# variable "newrelicfile" {
#   default = ""
#   description = "Path to the new relicfile"
# }