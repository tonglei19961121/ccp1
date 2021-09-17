###########################################################################
# Template for P2 AWS Autoscaling Test                                  #
# Do not edit the first section                                           #
# Only edit the second section to configure appropriate scaling policies  #
###########################################################################

############################
# FIRST SECTION BEGINS     #
# DO NOT EDIT THIS SECTION #
############################
locals {
  common_tags = {
    Project = "vm-scaling"
  }
  asg_tags = [
    {
      key                 = "Project"
      value               = "vm-scaling"
      propagate_at_launch = true
    }
  ]
}

provider "aws" {
  region = "us-east-1"
}


resource "aws_security_group" "lg" {
  # HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_security_group" "elb_asg" {
  # HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

######################
# FIRST SECTION ENDS #
######################

############################
# SECOND SECTION BEGINS    #
# PLEASE EDIT THIS SECTION #
############################

# Step 1:
# TODO: Add missing values below
# ================================
resource "aws_launch_configuration" "lc" {
  image_id        = "ami-080f51c25cd41977c"
  instance_type   = "m5.large"
  security_groups = [aws_security_group.elb_asg.id]
  tags            = local.asg_tags
}

# Create an auto scaling group with appropriate parameters
# TODO: fill the missing values per the placeholders
resource "aws_autoscaling_group" "asg" {
availability_zones        = ["us-east-1a","us-east-1b"]
max_size                  = 5
min_size                  = 1
desired_capacity          = 1
default_cooldown          = 100
health_check_grace_period = 10
health_check_type         = "EC2"
force_delete              = true
launch_configuration      = aws_launch_configuration.lc.name
target_group_arns         = [aws_lb_target_group.tg.arn]
tags                      = local.asg_tags
}

# TODO: Create a Load Generator AWS instance with proper tags

resource "aws_instance" "lg" {
  ami           = "ami-0f766e6dbff04c89c"
  instance_type = "t2.micro"
  tags = local.asg_tags
  key_name = "ray"
}

# Step 2:
# TODO: Create an Application Load Balancer with appropriate listeners and target groups
# The lb_listener documentation demonstrates how to connect these resources
# Create and attach your subnet to the Application Load Balancer 
#
# https://www.terraform.io/docs/providers/aws/r/lb.html

resource "aws_lb" "elb" {
  name               = "load-balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.elb_asg.id]
  subnets            = aws_subnet.main.*.id
  tags = local.asg_tags
  ip_address_type = "ipv4"
}

# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet

resource "aws_vpc" "main" {
  cidr_block       ="0.0.0.0/0"
}

resource "aws_subnet" "main" {
  vpc_id     = aws_vpc.main.id
  cidr_block       ="0.0.0.0/0"
}

# https://www.terraform.io/docs/providers/aws/r/lb_listener.html

resource "aws_lb_listener" "lb_listener" {
  load_balancer_arn = aws_lb.elb.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
  tags = local.asg_tags
}

# https://www.terraform.io/docs/providers/aws/r/lb_target_group.html

resource "aws_lb_target_group" "tg" {
  name     = "target-group"
  port     = 80
  protocol = "HTTP"
  target_type = "instance"
  vpc_id   = aws_vpc.main.id
  tags = local.asg_tags
}

# Step 3:
# TODO: Create 2 policies: 1 for scaling out and another for scaling in
# Link it to the autoscaling group you created above
# https://www.terraform.io/docs/providers/aws/r/autoscaling_policy.html 

resource "aws_autoscaling_policy" "in" {
  name                   = "in-action"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 100
  estimated_instance_warmup = 100
  autoscaling_group_name = aws_autoscaling_group.asg.name
}

resource "aws_autoscaling_policy" "out" {
  name                   = "out-action"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 100
  estimated_instance_warmup = 100
  autoscaling_group_name = aws_autoscaling_group.asg.name
}

# Step 4:
# TODO: Create 2 cloudwatch alarms: 1 for scaling out and another for scaling in
# Link it to the autoscaling group you created above
# Don't forget to trigger the appropriate policy you created above when alarm is raised
# https://www.terraform.io/docs/providers/aws/r/cloudwatch_metric_alarm.html

resource "aws_cloudwatch_metric_alarm" "in" {
  alarm_name          = "in-policy"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "20"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg.name
  }

  alarm_description = "This metric monitors ec2 cpu utilization"
  alarm_actions     = [aws_autoscaling_policy.in.arn]
}

resource "aws_cloudwatch_metric_alarm" "out" {
  alarm_name          = "out-policy"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg.name
  }

  alarm_description = "This metric monitors ec2 cpu utilization"
  alarm_actions     = [aws_autoscaling_policy.out.arn]
}

######################################
# SECOND SECTION ENDS                #
# MAKE SURE YOU COMPLETE ALL 4 STEPS #
######################################
