# create VPC
resource "aws_vpc" "vpc" {
  cidr_block = var.vpc-cidr
  tags = {
    Name = "${local.name}-vpc"
  }
}
# create pub subnet 1
resource "aws_subnet" "pubsub01" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.pubsub01-cidr
  availability_zone = var.az1
  tags = {
    Name = "${local.name}-pubsub01"
  }
}

# create pub subnet 2
resource "aws_subnet" "pubsub02" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.pubsub02-cidr
  availability_zone = var.az2
  tags = {
    Name = "${local.name}-pubsub02"
  }
}

# create prv subnet 1
resource "aws_subnet" "prvtsub01" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.prvtsub01-cidr
  availability_zone = var.az1
  tags = {
    Name = "${local.name}-prvtsub01"
  }
}

# create prv subnet 2
resource "aws_subnet" "prvtsub02" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.prvtsub02-cidr
  availability_zone = var.az2
  tags = {
    Name = "${local.name}-prvtsub02"
  }
}
# create an IGW
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${local.name}-igw"
  }
}
# create a public route table
resource "aws_route_table" "public-subnet-RT" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
    Name = "${local.name}-public-subnet-RT"
  }
}
# assiociation of route table to public subnet 1
resource "aws_route_table_association" "Public-RT-ass" {
  subnet_id      = aws_subnet.pubsub01.id
  route_table_id = aws_route_table.public-subnet-RT.id
}

# assiociation of route table to public subnet 2
resource "aws_route_table_association" "Public-RT-ass-2" {
  subnet_id      = aws_subnet.pubsub02.id
  route_table_id = aws_route_table.public-subnet-RT.id
}

# Allocate Elastic IP Address (EIP )
# terraform aws allocate elastic ip
resource "aws_eip" "eip-for-nat-gateway" {
  domain = "vpc"

  tags = {
    Name = "${local.name}-EIP"
  }
}

# Create Nat Gateway  in Public Subnet 1
# terraform create aws nat gateway
resource "aws_nat_gateway" "nat-gateway" {
  allocation_id = aws_eip.eip-for-nat-gateway.id
  subnet_id     = aws_subnet.pubsub01.id

  tags = {
    Name = "${local.name}-nat-gateway"
  }
}

# Create Private Route Table  and Add Route Through Nat Gateway 
# terraform aws create route table
resource "aws_route_table" "private-route-table" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block     = var.all-cidr
    nat_gateway_id = aws_nat_gateway.nat-gateway.id
  }

  tags = {
    Name = "${local.name}-private-route-table"
  }
}

# Associate Private Subnet 1 with "Private Route Table "
# terraform aws associate subnet with route table
resource "aws_route_table_association" "private-subnet-1-route-table-association" {
  subnet_id      = aws_subnet.prvtsub01.id
  route_table_id = aws_route_table.private-route-table.id
}

# Associate Private Subnet 2 with "Private Route Table "
# terraform aws associate subnet with route table
resource "aws_route_table_association" "private-subnet-2-route-table-association" {
  subnet_id      = aws_subnet.prvtsub02.id
  route_table_id = aws_route_table.private-route-table.id
}

# Create Keypair 
resource "aws_key_pair" "keypair" {
  key_name   = var.keyname
  public_key = file(var.path_public_key)
}

#Security Group for SonarQube Server
resource "aws_security_group" "Sonarqube_SG" {
  name        = "Sonarqube_SG"
  description = "Sonarqube_SG"
  vpc_id      = aws_vpc.vpc.id

  # Inbound Rules
  ingress {
    description = "ssh access"
    from_port   = var.port_ssh
    to_port     = var.port_ssh
    protocol    = "tcp"
    cidr_blocks = [var.all-cidr]
  }

  ingress {
    description = "SonarQube port"
    from_port   = var.port_sonar
    to_port     = var.port_sonar
    protocol    = "tcp"
    cidr_blocks = [var.all-cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.all-cidr]
  }
  tags = {
    Name = "${local.name}-Sonarqube_SG"
  }
}

# Bastion and ansible security_groups
resource "aws_security_group" "bastion-ansible" {
  name        = "bastion-ansible-SG"
  description = "Bastion and Ansible Security Group"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "bastion-ansible ssh port"
    from_port   = var.port_ssh
    to_port     = var.port_ssh
    protocol    = "tcp"
    cidr_blocks = [var.all-cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.all-cidr]
  }
  tags = {
    Name = "${local.name}-Bastion-Ansible-sg"
  }
}

#Docker security_groups
resource "aws_security_group" "docker-SG" {
  name        = "docker-SG"
  description = "Docker Security Group"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "docker ssh port"
    from_port   = var.port_ssh
    to_port     = var.port_ssh
    protocol    = "tcp"
    cidr_blocks = [var.all-cidr]
  }

  ingress {
    description = "docker port proxy"
    from_port   = var.port_proxy
    to_port     = var.port_proxy
    protocol    = "tcp"
    cidr_blocks = [var.all-cidr]
  }

  ingress {
    description = "http port"
    from_port   = var.port_http
    to_port     = var.port_http
    protocol    = "tcp"
    cidr_blocks = [var.all-cidr]
  }

  ingress {
    description = "https port"
    from_port   = var.port_https
    to_port     = var.port_https
    protocol    = "tcp"
    cidr_blocks = [var.all-cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.all-cidr]
  }
  tags = {
    Name = "${local.name}-Docker-sg"
  }
}

#Nexus port
resource "aws_security_group" "nexus-SG" {
  name        = "nexus-SG"
  description = "Nexus Security Group"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "ssh port"
    from_port   = var.port_ssh
    to_port     = var.port_ssh
    protocol    = "tcp"
    cidr_blocks = [var.all-cidr]
  }

  ingress {
    description = "nexus port"
    from_port   = var.port_nexus
    to_port     = var.port_nexus
    protocol    = "tcp"
    cidr_blocks = [var.all-cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.all-cidr]
  }
  tags = {
    Name = "${local.name}-Nexus-sg"
  }
}

#Mysql port
resource "aws_security_group" "mysql-SG" {
  name        = "mysql-SG"
  description = "Mysql Security Group"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "mysql port"
    from_port   = var.port_mysql
    to_port     = var.port_mysql
    protocol    = "tcp"
    cidr_blocks = [var.all-cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.all-cidr]
  }
  tags = {
    Name = "${local.name}-Mysql-sg"
  }
}

#Security group for jenkins
resource "aws_security_group" "Jenkins-sg" {
  name        = "frontend-sg"
  description = "Allow Jenkins traffic"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "Port traffic"
    from_port   = var.port_proxy
    to_port     = var.port_proxy
    protocol    = "tcp"
    cidr_blocks = [var.all-cidr]
  }
  ingress {
    description = "Allow ssh traffic"
    from_port   = var.port_ssh
    to_port     = var.port_ssh
    protocol    = "tcp"
    cidr_blocks = [var.all-cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.all-cidr]
  }

  tags = {
    Name = "${local.name}-Jenkins-sg"
  }
}

#Creating SonarQube Server within an EC2 Instance
resource "aws_instance" "SonarQube_Server" {
  ami                         = var.ami_SQ
  instance_type               = var.instance_type
  key_name                    = aws_key_pair.keypair.key_name
  vpc_security_group_ids      = [aws_security_group.Sonarqube_SG.id]
  subnet_id                   = aws_subnet.pubsub01.id
  associate_public_ip_address = true
  user_data                   = local.sonarqube_user_data

  tags = {
    Name = "${local.name}-SonarQube_Server"
  }
}

#Instance and Installing Jenkins
resource "aws_instance" "Jenkins_Server" {
  ami                         = var.ami
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.pubsub01.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.Jenkins-sg.id]
  key_name                    = aws_key_pair.keypair.key_name
  user_data                   = local.jenkins_user_data
  tags = {
    Name = "${local.name}-Jenkins_Server"
  }
}

# create bastions_host
resource "aws_instance" "bastion" {
  ami                         = var.ami
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.pubsub02.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.bastion-ansible.id]
  key_name                    = aws_key_pair.keypair.key_name
  user_data                   = <<-EOF
#!/bin/bash
echo "${var.path_private_key}" >> /home/ec2-user/ET1PACUJP1
chmod 400 /home/ec2-user/ET1PACUJP1
sudo hostnamectl set-hostname bastion
EOF
  tags = {
    Name = "${local.name}-bastion"
  }
}
# Creating Nexus server 
resource "aws_instance" "nexus-server" {
  ami                         = var.ami
  instance_type               = var.instance_type
  key_name                    = aws_key_pair.keypair.key_name
  vpc_security_group_ids      = [aws_security_group.nexus-SG.id]
  subnet_id                   = aws_subnet.pubsub02.id
  associate_public_ip_address = true
  user_data                   = local.nexus_user_data
  tags = {
    Name = "${local.name}-nexus_Server"
  }
}

#Creating Instance for Ansible Server
resource "aws_instance" "ansible_Server" {
  ami                         = var.ami
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.pubsub01.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.bastion-ansible.id]
  key_name                    = aws_key_pair.keypair.key_name
  user_data                   = local.ansible_user_data

  tags = {
    Name = "${local.name}-Ansible_Server"
  }
}

# Database Subnet Group
resource "aws_db_subnet_group" "db_subnet" {
  name       = "db-subnet-group"
  subnet_ids = [aws_subnet.prvtsub01.id, aws_subnet.prvtsub02.id]
  tags = {
    Name = "${local.name}-db-subnet-group"
  }
}

# Create Database
resource "aws_db_instance" "mysql_database" {
  identifier             = var.db_identifier
  db_subnet_group_name   = aws_db_subnet_group.db_subnet.name
  vpc_security_group_ids = [aws_security_group.mysql-SG.id]
  multi_az               = true
  allocated_storage      = 10
  db_name                = var.db_name
  engine                 = "mySQL"
  engine_version         = "5.7"
  instance_class         = "db.t3.micro"
  username               = var.database_username
  password               = var.database_password
  parameter_group_name   = "default.mysql5.7"
  skip_final_snapshot    = true
  publicly_accessible    = false
  storage_type           = "gp2"
}

#Creating Docker Instance
resource "aws_instance" "docker_Server" {
  ami                         = var.ami
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.prvtsub01.id
  vpc_security_group_ids      = [aws_security_group.docker-SG.id]
  key_name                    = aws_key_pair.keypair.key_name
  user_data                   = local.docker_user_data
  tags = {
    Name = "${local.name}-Docker_Server"
  }
}

#Creating Target Group
resource "aws_lb_target_group" "target-group" {
  name     = "${local.name}-target-group"
  port     = var.port_proxy
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 5
    interval            = 30
    timeout             = 5
  }
}

#Creating Target Group Association
resource "aws_lb_target_group_attachment" "target-group-attach" {
  target_group_arn = aws_lb_target_group.target-group.arn
  target_id        = aws_instance.docker_Server.id
  port             = var.port_proxy
}

#Creating Load Balancer Listner for https
resource "aws_lb_listener" "LB-listener" {
  #load_balancer_arn = 
  port              = var.port_https
  protocol          = "HTTPS"
  #ssl_policy        = "ELBSecurityPolicy-2016-08"
  #certificate_arn   = 

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.target-group.arn
  }
}

#Creating Load Balancer Listner for http
resource "aws_lb_listener" "LB-listener_2" {
  #load_balancer_arn = 
  port              = var.port_http
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.target-group.arn
  }
}

#Creating AMI
resource "aws_ami_from_instance" "ami-docker-server" {
  name = "ami-docker-server"
  source_instance_id = aws_instance.docker_Server.id
  snapshot_without_reboot = true
  depends_on = [ aws_instance.docker_Server, time_sleep.docker-server-wait-time ]
}

#Creating Time sleep resources
resource "time_sleep" "docker-server-wait-time" {
  depends_on = [ aws_instance.docker_Server ]
  create_duration = "480s"
}

#Creating launch configuration
resource "aws_launch_configuration" "ASG-LC" {
  name = "ASG-LC"
  image_id = aws_ami_from_instance.ami-docker-server.id
  instance_type = var.instance_type
  associate_public_ip_address = true
  security_groups = [aws_security_group.docker-SG]
  key_name = var.keyname

  lifecycle {
    create_before_destroy = true
  }
  depends_on = [ aws_ami_from_instance.ami-docker-server ]
}
  
#  create ACM certificate
resource "aws_acm_certificate" "acm_certificate" {
  domain_name       = "greatminds.sbs"
  validation_method = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}

#create route53 validation record
resource "aws_route53_record" "validation_record" {
  for_each = {
    for dvo in aws_acm_certificate.acm_certificate.domain_validation_options : dvo.greatminds.sbs => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.vault.zone_id
}

#create acm certificate validition
resource "aws_acm_certificate_validation" "acm_certificate_validation" {
  certificate_arn         = aws_acm_certificate.acm_certificate.arn
  validation_record_fqdns = [for record in aws_route53_record.validation_record : record.fqdn]
}

#Auto scaling group  
resource "aws_autoscaling_group" "ASG" {
  name = "ASG"
  max_size = 4
  min_size = 1
  health_check_grace_period = 300
  health_check_type = "EC2"
  desired_capacity = 2
  force_delete = true
  launch_configuration = aws_launch_configuration.ASG-LC.name
  vpc_zone_identifier = [aws_subnet.pubsub01, aws_subnet.pubsub02]
  target_group_arns = ["${aws_lb_target_group.target-group.arn}"]
  tag {
    key = "ASG"
    value = "asg"
    propagate_at_launch = true
  }
}

#Auto-scaling Group policy 
resource "aws_autoscaling_policy" "ASG_policy" {
  autoscaling_group_name = aws_autoscaling_group.ASG
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