variable "ami" {
  default = "ami-0baa9e2e64f3c00db"
}

variable "instance-type" {
  default = "t3.micro"
}

variable "set16-key" {
  default     = "~/keypair/Keypair2.pub"
  description = "path to my keypairs"
}

variable "keyname" {
  default = "set16-key"
}

variable "EC2-Image" {
  default = "ami-023ebd00acac08ef0"
}

variable "database_name" {
  default     = "set16db"
  description = "Database name"
}

variable "database_identifier" {
  default = "set16-db-id"

}

variable "database_username" {
  default     = "admin"
  description = "Database username"
}

variable "database_password" {
  default     = "Admin123"
  description = "Database password"
}

variable "emails" {
  default     = ["victor.adepoju@cloudhight.com", "tunde.afodunrinbi@cloudhight.com", "solomon.ajisafe@cloudhight.com" , "delaz.muz@cloudhight.com" ,"emeka.eze@cloudhight.com" , "rosemary.omokehinde@cloudhight.com" ]
  description = "email address"
}

variable "alarm_name1" {
  default = "asg-cw-alarm"
}

variable "comparison_operator" {
  default = "GreaterThanOrEqualToThreshold"
}

variable "metric_name1" {
  default = "CPUUtilization" 
}

variable "namespace" {
  default = "AWS/EC2"
}

variable "AutoScalingGroupName" {
  default = "set16asg"
}

variable "alarm_name" {
  default = "ec2-cw-alarm"
}

variable "metric_name" {
  default = "CPUUtilization"
}

variable "alarm_description" {
  default = "This metric monitors ec2 cpu utilization"
}

# #variable "alarm_actions" {
#   default = [aws_sns_topic.user_updates.arn]
# }
