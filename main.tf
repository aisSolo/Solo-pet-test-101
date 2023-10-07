resource "aws_vpc" "set16vpc" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "set16vpc"
  }
}

resource "aws_subnet" "publicsubnet1" {
  vpc_id     = aws_vpc.set16vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone ="eu-north-1a"

  tags = {
    Name = "publicsubnet1"
  }
}

resource "aws_subnet" "publicsubnet2" {
  vpc_id     = aws_vpc.set16vpc.id
  cidr_block = "10.0.2.0/24"
  availability_zone ="eu-north-1b"

  tags = {
    Name = "publicsubnet2"
  }
}

resource "aws_subnet" "privatesubnet1" {
  vpc_id     = aws_vpc.set16vpc.id
  cidr_block = "10.0.3.0/24"
  availability_zone ="eu-north-1a"

  tags = {
    Name = "privatesubnet1"
  }
}

resource "aws_subnet" "privatesubnet2" {
  vpc_id     = aws_vpc.set16vpc.id
  cidr_block = "10.0.4.0/24"
  availability_zone ="eu-north-1b"

  tags = {
    Name = "privatesubnet2"
  }
}

# Creating Internet gateway and atttaching to VPC
resource "aws_internet_gateway" "set16-IGW" {
  vpc_id = aws_vpc.set16vpc.id

  tags = {
    Name = "set16-IGW"
  } 
}

#Creating Elastic IP
resource "aws_eip" "set16-eip" {
  domain = "vpc"
  depends_on = [ aws_internet_gateway.set16-IGW ]
  
}

#Creating NAT gateway
resource "aws_nat_gateway" "set16-NGW" {
  subnet_id = aws_subnet.publicsubnet1.id
  connectivity_type = "public"
  allocation_id = aws_eip.set16-eip.id

  tags = {
    Name = "set16-NGW"
  }
depends_on = [ aws_internet_gateway.set16-IGW ]
}

# Creating Public Route-table 
resource "aws_route_table" "set16_pubRT" {
  vpc_id = aws_vpc.set16vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.set16-IGW.id
}

  tags = {
    Name = "set16_pubRT"
  }
}

# Creating Private Route-table
resource "aws_route_table" "set16_privRT" {
  vpc_id = aws_vpc.set16vpc.id

  route {
    cidr_block = "0.0.0.0/0"
   nat_gateway_id = aws_nat_gateway.set16-NGW.id
  }

  tags = {
    Name = "set16_privRT"
  }
}

#Creating Route table Association - Public Subnet
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.publicsubnet1.id
  route_table_id = aws_route_table.set16_pubRT.id
}

resource "aws_route_table_association" "public2" {
  subnet_id      = aws_subnet.publicsubnet2.id
  route_table_id = aws_route_table.set16_pubRT.id
}

#Creating Route table Association - Private Subnet
resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.privatesubnet1.id
  route_table_id = aws_route_table.set16_pubRT.id
}

resource "aws_route_table_association" "private2" {
  subnet_id      = aws_subnet.privatesubnet2.id
  route_table_id = aws_route_table.set16_pubRT.id
}

# FRONTEND SECURITY GROUP
resource "aws_security_group" "set16_SG" {
  name        = "set16_SG"
  description = "set16_SG"
  vpc_id      = aws_vpc.set16vpc.id

# Inbound Rules
  ingress { 
    description      = "http"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

# HTTPS access from anywhere
  ingress { 
    description      = "https"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

# SSH access from anywhere
  ingress {
    description      = "ssh"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
   }

# Outbound Rules
# Internet access to anywhere
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
 }
 
 tags = {
    Name = "set16-sg-fe"
  }
}

#BACKEND SECURITY GROUP
resource "aws_security_group" "mysql_SG" {
  name        = "mysql_SG"
  description = "allow mysgl_SG"
  vpc_id      = aws_vpc.set16vpc.id

#Inbound Rules
# mysql access from anywhere"
  ingress {
    description      = "mysql"
    from_port        = 3306
    to_port          = 3306
    protocol         = "tcp"
    cidr_blocks = ["10.0.1.0/24", "10.0.2.0/24"]
  }

# SSH access from anywhere
  ingress {
    description      = "ssh"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks = ["10.0.1.0/24", "10.0.2.0/24"]
  }

# Outbound Rules
# Internet access to anywhere
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
   }

   tags = {
    Name = "set16-sg-be"
  }
}

#Create Subnet group
 resource "aws_db_subnet_group" "set16_dbsubnet" {
  name       = "set16_dbsubnet"
  subnet_ids = [aws_subnet.privatesubnet1.id,aws_subnet.privatesubnet2.id]

  tags = {
    Name = "set16_dbsubnet"
  }
} 

# Creating RDS
resource "aws_db_instance" "set16_db" {
  allocated_storage    = 10
  db_name              = var.database_name
  engine               = "mysql"
  engine_version         = "8.0.28"
  instance_class       = "db.t3.micro"
  username             = var.database_username
  password             = var.database_password
  parameter_group_name = "default.mysql8.0"
  apply_immediately      = true
  db_subnet_group_name   = aws_db_subnet_group.set16_dbsubnet.id
  max_allocated_storage  = 100
  #multi_az               = true
  port                   = 3306
  vpc_security_group_ids = [aws_security_group.mysql_SG.id]
  skip_final_snapshot  = true
}

#Creating S3 media bucket
resource "aws_s3_bucket" "capmedia" {
    bucket = "capmedia"
    tags = {
        Name = "cap-media"
    }  
}

#Creating Media Bucket Ownership Control
resource "aws_s3_bucket_ownership_controls" "capmedia-ct" {
    bucket = aws_s3_bucket.capmedia.id
    rule {
      object_ownership = "BucketOwnerPreferred"
    }
    depends_on = [ aws_s3_bucket_public_access_block.capmedia-pab ] 
}

#Creating Media Bucket Public Access
resource "aws_s3_bucket_public_access_block" "capmedia-pab" {
    bucket = aws_s3_bucket.capmedia.id
    block_public_acls = false
    block_public_policy = false
    ignore_public_acls = false
    restrict_public_buckets = false    
}

#Creating Media Bucket ACL
resource "aws_s3_bucket_acl" "cap-media-acl" {
    bucket = aws_s3_bucket.capmedia.id
    depends_on = [ aws_s3_bucket_ownership_controls.capmedia-ct]
    acl = "public-read"
}

#Creating Media Bucket policy
resource "aws_s3_bucket_policy" "cap-media-policy" {
    bucket = aws_s3_bucket.capmedia.id
    policy = data.aws_iam_policy_document.cap-media.json
}

data "aws_iam_policy_document" "cap-media" {
    
    statement   {
        principals {
            type = "*"
            identifiers = ["*"]

        }
        actions = [
            "s3:GetObject"
        ]
    

        resources = [
            aws_s3_bucket.capmedia.arn,
            "${aws_s3_bucket.capmedia.arn}/*",
        ]
    }
  depends_on = [ aws_s3_bucket_public_access_block.capmedia-pab ]
}

# #Creating Log Bucket
# resource "aws_s3_bucket" "bucket-log123" {
#   bucket = "bucket-log123"

#    tags = {
#     Name        = "Set16Bucketlog"
#   }
# }

# #Creating Log bucket Ownership Control
# resource "aws_s3_bucket_ownership_controls" "bucketcontrol1" {
#   bucket = aws_s3_bucket.bucket-log123.id

#   rule {
#     object_ownership = "BucketOwnerEnforced"
#   }
# }

# #Creating Log Bucket ACL
# resource "aws_s3_bucket_acl" "bucketlogacl" {
#   depends_on = [aws_s3_bucket_ownership_controls.bucketcontrol1]  
#   bucket = aws_s3_bucket.bucket-log123.id
#   acl    = "private"
# }

# #Creating Log Bucket policy
# resource "aws_s3_bucket_policy" "log-bucket-policy" {
#     bucket = aws_s3_bucket.bucket-log123.id
#     policy = data.aws_iam_policy_document.cap-log.json
# }

# data "aws_iam_policy_document" "cap-log" {
    
#     statement   {
#         principals {
#             type = "*"
#             identifiers = ["*"]

#         }
#         actions = [
#             "s3:GetObject", "s3:GetObjectversion", "s3:PutObject"
#         ]
#         resources = [
#             aws_s3_bucket.bucket-log123.arn,
#             "${aws_s3_bucket.bucket-log123.arn}/*",
#         ]
#     }
# }

# Creating Code Bucket
resource "aws_s3_bucket" "set16-sb-code" {
  bucket        = "set16-sb-code"
  force_destroy = true
  tags = {
    Name = "set16-sb-code"
  }
}

#Creating Code Bucket Ownership Control
resource "aws_s3_bucket_ownership_controls" "set16_pub_acc_code" {
  bucket = aws_s3_bucket.set16-sb-code.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

#Creating Code Bucket ACL
resource "aws_s3_bucket_acl" "set16-sba-code" {
  depends_on = [aws_s3_bucket_ownership_controls.set16_pub_acc_code]
  bucket = aws_s3_bucket.set16-sb-code.id
  acl    = "private"
}

#Creating IAM Role 
resource "aws_iam_role" "cap-S3IAM" {
    name = "cap-S3IAM"
    assume_role_policy = data.aws_iam_policy_document.cap-S3IAM-rol.json
}

data "aws_iam_policy_document" "cap-S3IAM-rol" {
    statement {
      effect = "Allow"

      principals {
        type = "Service"
        identifiers = ["ec2.amazonaws.com"]

      }
      actions = ["sts:AssumeRole"]
    }
}

#Creating IAM Policy
resource "aws_iam_policy" "cap-S3IAM" {
    name = "cap-S3IAM"
    description = "Access to Ec2 instnace and S3 bucket"
    policy = data.aws_iam_policy_document.cap-S3IAM-pol.json
  
}
data "aws_iam_policy_document" "cap-S3IAM-pol" {
    statement {
      effect = "Allow"
      actions = ["s3:*"]
      resources = ["*"]
    }
  
}

#Creating IAM Policy Attachment 
resource "aws_iam_role_policy_attachment" "cap-S3IAM" {
    role = aws_iam_role.cap-S3IAM.name
    policy_arn = aws_iam_policy.cap-S3IAM.arn
}

#Creating Instance Profile
resource "aws_iam_instance_profile" "cap-S3IAM" {
  name = "cap-S3IAM"
  role = aws_iam_role.cap-S3IAM.name
}

# Create a keypair
resource "aws_key_pair" "set16-key" {
  key_name   = var.keyname
  public_key = file(var.set16-key)

}

#EC2 instance 
resource "aws_instance" "web_server" {
    ami           = var.ami
    subnet_id     = aws_subnet.publicsubnet1.id
    vpc_security_group_ids = [aws_security_group.set16_SG.id]
    instance_type = var.instance-type
    associate_public_ip_address = true
    availability_zone           = "eu-north-1a"
    iam_instance_profile        = aws_iam_instance_profile.cap-S3IAM.id
    key_name                    = var.keyname
    user_data                   = templatefile("../user-data/wordpress.sh", {
    database_name = var.database_name,
    database_username = var.database_username,
    database_password = var.database_password,
    db_endpoint = aws_db_instance.set16_db.endpoint,
    cloud_front_name =  data.aws_cloudfront_distribution.set16-cloudfront.domain_name,
    REQUEST_FILENAME = "{REQUEST_FILENAME}"
    })

    tags = {
    Name = "set16-webserver"
  }
}

# Creation of Cloudfront Distribution
locals {
  s3_origin_id = aws_s3_bucket.capmedia.bucket
}

resource "aws_cloudfront_distribution" "set16-cd" {
  origin {
    domain_name = aws_s3_bucket.capmedia.bucket_regional_domain_name
    origin_id   = local.s3_origin_id
  }
  enabled = true
  #default_root_object = "indextest.html"
  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id
    forwarded_values {
      query_string = true
      cookies {
        forward = "none"
      }
    }
    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 600
  }

  price_class = "PriceClass_All"
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

#Exporting Cloudfront Endpoint
data "aws_cloudfront_distribution" "set16-cloudfront" {
  id = aws_cloudfront_distribution.set16-cd.id
}

#Creating AMI
resource "aws_ami_from_instance" "webserver_ami1"{
  name = "webserver_ami1"
  source_instance_id = aws_instance.web_server.id
  snapshot_without_reboot = true
  depends_on = [aws_instance.web_server,time_sleep.EC2_wait_time]
}

#Creating launch configuration
resource "aws_launch_configuration" "cap-asg-lc" {
    name = "cap-asg-lc"
    image_id = aws_ami_from_instance.webserver_ami1.id
    instance_type = var.instance-type
    iam_instance_profile = aws_iam_instance_profile.cap-S3IAM.arn
    associate_public_ip_address = true
    security_groups = [aws_security_group.set16_SG.id]
    key_name = var.keyname

    lifecycle {
      create_before_destroy = true
    }
    depends_on = [ aws_ami_from_instance.webserver_ami1]
}

#### Time sleep resource delay the creation of the AMI by waiting for the completion of the EC2 instance [Webserver] ####
resource "time_sleep" "EC2_wait_time" {
  depends_on = [aws_instance.web_server]
  create_duration = "300s"
}

#this is the Autoscaling group #
resource "aws_autoscaling_group" "set16asg" {
  name = "set16asg"
  max_size = 4
  min_size = 1
  health_check_grace_period = 300
  health_check_type = "EC2"
  desired_capacity = 2
  force_delete = true
  launch_configuration = aws_launch_configuration.cap-asg-lc.name
  vpc_zone_identifier = [aws_subnet.publicsubnet1.id, aws_subnet.publicsubnet2.id]
  target_group_arns = ["${aws_lb_target_group.target_group.arn}"]
  tag {
    key = "set16asg"
    value = "asg"
    propagate_at_launch = true
  }
}

#This is the Auto-scaling Group policy ####
resource "aws_autoscaling_policy" "ASG_policy" {
  autoscaling_group_name = aws_autoscaling_group.set16asg.name
  name = "ASG_policy"
  adjustment_type = "ChangeInCapacity"
  policy_type = "TargetTrackingScaling"
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 70.0
  }
}


#create hosted zone
# data "aws_route53_zone" "project_zone" {
#   name         = "soloaji.net"
#   private_zone = true
# }

#Create A record resource "aws_route53_record" "greatminds.sbs"
resource "aws_route53_record" "stage" { 
  zone_id = data.aws_route53_zone.set16hostedzone.zone_id 
   name    = "greatminds.sbs"  
   type    = "A"
  alias {
   name = aws_lb.albset16.dns_name 
   zone_id = aws_lb.albset16.zone_id 
   evaluate_target_health = true  
   }
}

#create acm certificate
# resource "aws_acm_certificate" "acm_certificate" {
#   domain_name       = "soloaji.net"
#   subject_alternative_names = ["*.soloaji.net"]
#   validation_method = "DNS"
#   lifecycle {
#     create_before_destroy = true
#   }
# }

#create route53 validation record
# resource "aws_route53_record" "wordpress" {
#   for_each = {
#     for dvo in aws_acm_certificate.acm_certificate.domain_validation_options : dvo.domain_name => {
#       name   = dvo.resource_record_name
#       record = dvo.resource_record_value
#       type   = dvo.resource_record_type
#     }
#   }

#   allow_overwrite = true
#   name            = each.value.name
#   records         = [each.value.record]
#   ttl             = 60
#   type            = each.value.type
#   zone_id         = data.aws_route53_zone.project_zone.zone_id
# }

#create acm certificate validition
#resource "aws_acm_certificate_validation" "acm_certificate_validation" {
  #certificate_arn         = aws_acm_certificate.acm_certificate.arn
  #validation_record_fqdns = [for record in aws_route53_record.wordpress : record.fqdn]
#}
#### Creating Target group ####
resource "aws_lb_target_group" "target_group" {
  name = "target-group"
  port = 80
  protocol = "HTTP"
  vpc_id = aws_vpc.set16vpc.id
  health_check {
    healthy_threshold = 5
    unhealthy_threshold = 6
    interval = 90
    timeout = 60
    path = "/indextest.html"
  }
}

#### Target group attachment ####
resource "aws_lb_target_group_attachment" "target_group_att" {
  target_group_arn = aws_lb_target_group.target_group.arn
  target_id = aws_instance.web_server.id
  port = 80
}

#Monitoring
#Create SNS topic and subscription
  resource "aws_sns_topic" "cap-update" {
  name    = "cap-update-topic"
  delivery_policy = <<EOF
{
  "http": {
    "defaultHealthyRetryPolicy": {
      "minDelayTarget": 20,
      "maxDelayTarget": 20,
      "numRetries": 3,
      "numMaxDelayRetries": 0,
      "numNoDelayRetries": 0,
      "numMinDelayRetries": 0,
      "backoffFunction": "linear"
    },
    "disableSubscriptionOverrides": false,
    "defaultThrottlePolicy": {
      "maxReceivesPerSecond": 1
    }
  }
}
EOF
}
locals {
emails = var.emails
}

#SNS subcription
resource "aws_sns_topic_subscription" "cap-sns-sub" {
  count = length(local.emails)
  topic_arn = aws_sns_topic.cap-update.arn
  protocol = "email"
  endpoint = local.emails[count.index]
} 

#### Create a CloudWatch dashboard that displays the average CPU utilization of our EC2 instance [webserver]. ####
resource "aws_cloudwatch_dashboard" "inst_cpu_utilization_dashboard" {
  dashboard_name = "instancecpuutilizationdashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "InstanceId", "${aws_instance.web_server.id}", { "label": "Average CPU Utilization" }]
          ]
          period = 300
          view = "timeSeries"
          stat   = "Average"
          stacked = false
          region = "eu-north-1"
          title  = "Average CPU Utilization"
          yAxis = {
            left = {
              label = "Percentage"
              showUnits = true
            }
          }
        }
      },  
    ]
  })
}

#### Create a CloudWatch dashboard that displays the average CPU utilization of our Auto-scaled instances. ####
resource "aws_cloudwatch_dashboard" "asg_cpu_utilization_dashboard" {
  dashboard_name = "asgcpuutilizationdashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", "${aws_autoscaling_group.set16asg.id}", { "label": "Average CPU Utilization" }]
          ]
          period = 300
          view = "timeSeries"
          stat   = "Average"
          stacked = false
          region = "eu-north-1"
          title  = "Average CPU Utilization"
          yAxis = {
            left = {
              label = "Percentage"
              showUnits = true
            }
          }
        }
      },  
    ]
  })
}

#Importing Route 53
data "aws_route53_zone" "set16hostedzone" {
  name         = "greatminds.sbs"
  private_zone = false
}


#### Creating load balancer listener ####
resource "aws_lb_listener" "set16lb_listener1" {
  load_balancer_arn = aws_lb.albset16.arn
  port              = "80"
  protocol          = "HTTP"
default_action {
  type              = "forward"
  target_group_arn = aws_lb_target_group.target_group.arn
  }
}

# #### Create load balance listener for https access ####
# resource "aws_lb_listener" "set16lb-listener2" {
#   load_balancer_arn = aws_lb.albset16.arn
#   port              = "443"
#   protocol          = "HTTPS"
#   #ssl_policy = "ELBSecurityPolicy-2016-08"
#   #certificate_arn = "${aws_acm_certificate.team1-certificate.arn}"
#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.target_group.arn
#   }
# }

#### Creating Application load balancer ####
resource "aws_lb" "albset16" {
  name = "alb"
  internal = false
  load_balancer_type = "application"
  security_groups = [aws_security_group.set16_SG.id]
  subnets = [aws_subnet.publicsubnet1.id, aws_subnet.publicsubnet2.id]
  enable_deletion_protection = false
  # access_logs {
  #   bucket = aws_s3_bucket.bucket-log123.bucket
  #   prefix = "lb-logs"
  #   enabled = true
  # }
   tags = {
     name = "alb"
  }
}



#Creating Cloudwatch metric Alarm for ASG
resource "aws_cloudwatch_metric_alarm" "asg-cw-alarm" {
  alarm_name          = var.alarm_name1
  comparison_operator = var.comparison_operator
  evaluation_periods  = "2"
  metric_name         = var.metric_name1
  namespace           = var.namespace
  period              = "120"
  statistic           = "Average"
  threshold           = "80"

  dimensions = {
    AutoScalingGroupName = var.AutoScalingGroupName
  }

  alarm_description = "This metric monitors asg cpu utilization"
  alarm_actions     = [aws_sns_topic.cap-update.arn]
}

#Creating Cloudwatch metric Alarm for Ec2 instance
resource "aws_cloudwatch_metric_alarm" "ec2-cw-alarm" {
  alarm_name          = var.alarm_name
  comparison_operator = var.comparison_operator
  evaluation_periods  = "2"
  metric_name         = var.metric_name
  namespace           = var.namespace
  period              = "120"
  statistic           = "Average"
  threshold           = "80"


  dimensions = {
    InstanceId = "{aws_instance.web_server.id}"
  }

  alarm_description = var.alarm_description
  alarm_actions     = [aws_sns_topic.cap-update.arn]
}

