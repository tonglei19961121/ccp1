
import boto3
import botocore
from botocore.exceptions import ClientError
import os
import requests
import time
import json
import re

########################################
# Constants
########################################
with open('auto-scaling-config.json') as file:
    configuration = json.load(file)

LOAD_GENERATOR_AMI = configuration['load_generator_ami']
WEB_SERVICE_AMI = configuration['web_service_ami']
INSTANCE_TYPE = configuration['instance_type']
LAUNCH_CONFIGURATION_NAME = configuration['launch_configuration_name']
TARGET_GROUP_NAME = configuration['target_group_name']
LOAD_BALANCER_NAME = configuration['load_balancer_name']
AUTO_SCALING_GROUP_NAME = configuration['auto_scaling_group_name']
ASG_MAX_SIZE = configuration['asg_max_size']
ASG_MIN_SIZE = configuration['asg_min_size']
HEALTH_CHECK_GRACE_PERIOD = configuration['health_check_grace_period']
COOL_DOWN_PERIOD_SCALE_IN = configuration['cool_down_period_scale_in']
COOL_DOWN_PERIOD_SCALE_OUT = configuration['cool_down_period_scale_out']
SCALE_OUT_ADJUSTMENT = configuration['scale_out_adjustment']
SCALE_IN_ADJUSTMENT = configuration['scale_in_adjustment']
ASG_DEFAULT_COOL_DOWN_PERIOD = configuration['asg_default_cool_down_period']
ALARM_PERIOD = configuration['alarm_period']
CPU_LOWER_THRESHOLD = configuration['cpu_lower_threshold']
CPU_UPPER_THRESHOLD = configuration['cpu_upper_threshold']
ALARM_EVALUATION_PERIODS_SCALE_OUT = configuration['alarm_evaluation_periods_scale_out']
ALARM_EVALUATION_PERIODS_SCALE_IN = configuration['alarm_evaluation_periods_scale_in']

SUBMISSION_USERNAME = os.environ['SUBMISSION_USERNAME']
SUBMISSION_PASSWORD = os.environ['SUBMISSION_PASSWORD']
KEY_NAME = os.getenv("KEY_NAME")
########################################
# Tags
########################################
tag_pairs = [
    ("Project", "vm-scaling"),
]
TAGS = [{'Key': k, 'Value': v} for k, v in tag_pairs]

TEST_NAME_REGEX = r'name=(.*log)'

########################################
# Utility functions
########################################

def create_security_group(group_name, sg_permissions,ec2_client):
    response = ec2_client.describe_vpcs()
    vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')
    data = None
    try:
        response = ec2_client.create_security_group(GroupName=group_name,
                                            Description='p1',
                                            VpcId=vpc_id)
        security_group_id = response['GroupId']
        print('Security Group Created %s in vpc %s.' % (security_group_id, vpc_id))

        data = ec2_client.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=sg_permissions)
        print('Ingress Successfully Set %s' % data)
    except ClientError as e:
        print(e)
    return data

def delete_security_group(GroupIds):
    client = boto3.client('ec2')
    try:
        for GroupId in GroupIds:
            response = client.delete_security_group(
                GroupId=GroupId,
            )
    except ClientError as e:
        print(e)
        return 
    return

def create_instance(ami, sg_name):
    """
    Given AMI, create and return an AWS EC2 instance object
    :param ami: AMI image name to launch the instance with
    :param sg_name: name of the security group to be attached to instance
    :return: instance object
    """
    instance = None
    ec2 = boto3.resource('ec2',region_name="us-east-1")
    # TODO: Create an EC2 instance
    # Wait for the instance to enter the running state
    # Reload the instance attributes

    try:
        instance = ec2.create_instances(
        ImageId=ami,
        InstanceType=INSTANCE_TYPE,
        KeyName=KEY_NAME,
        MaxCount=1,
        MinCount=1,
        SecurityGroupIds=[
            sg_name,
        ],
        TagSpecifications=[{
            'ResourceType': 'instance',
            'Tags': TAGS
        }, {
            'ResourceType': 'volume',
            'Tags': TAGS
        }]
        )[0]
        instance.wait_until_running()
        instance.reload()
        print(instance.state)
    except ClientError as e:
        print(e)

    return instance

def destory_instance(InstanceIds):
    """
    Given AMI, create and return an AWS EC2 instance object
    :param ami: AMI image name to launch the instance with
    :param sg_name: name of the security group to be attached to instance
    :return: instance object
    """
    client = boto3.client('ec2')
    # TODO: delete an EC2 instance
    # Wait for the instance to enter the running state
    # Reload the instance attributes

    try:
        response = client.terminate_instances(
            InstanceIds=InstanceIds,
            DryRun=False
        )
    except ClientError as e:
        print(e)

    return


def initialize_test(load_generator_dns, first_web_service_dns):
    """
    Start the auto scaling test
    :param lg_dns: Load Generator DNS
    :param first_web_service_dns: Web service DNS
    :return: Log file name
    """

    add_ws_string = 'http://{}/autoscaling?dns={}'.format(
        load_generator_dns, first_web_service_dns
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(add_ws_string, timeout = 10)
        except requests.exceptions.RequestException as e:
            print(e)
            time.sleep(1)
            pass 

    # TODO: return log File name
    return get_test_id(response)


def initialize_warmup(load_generator_dns, load_balancer_dns):
    """
    Start the warmup test
    :param lg_dns: Load Generator DNS
    :param load_balancer_dns: Load Balancer DNS
    :return: Log file name
    """

    add_ws_string = 'http://{}/warmup?dns={}'.format(
        load_generator_dns, load_balancer_dns
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(add_ws_string, timeout=10)
        except requests.exceptions.RequestException as e:
            print(e)
            time.sleep(1)
            pass  
    print(response)
    # TODO: return log File name
    return get_test_id(response)


def get_test_id(response):
    """
    Extracts the test id from the server response.
    :param response: the server response.
    :return: the test name (log file name).
    """
    response_text = response.text

    regexpr = re.compile(TEST_NAME_REGEX)

    return regexpr.findall(response_text)[0]


def destroy_resources(LoadBalancerArn, ListenerArn, TargetGroupArn):
    """
    Delete all resources created for this task
    :param msg: message
    :return: None
    """
    # TODO: implement this method
    destroy_ASG()
    destroy_ELB(LoadBalancerArn, ListenerArn, TargetGroupArn)
    pass

def destroy_ASG():
    client = boto3.client('autoscaling')
    response = None
    try : 
        response = client.delete_auto_scaling_group(
            AutoScalingGroupName=AUTO_SCALING_GROUP_NAME,
            ForceDelete=True,
        )
        response = client.delete_launch_configuration(
            LaunchConfigurationName=LAUNCH_CONFIGURATION_NAME
        )
    except ClientError as e:
        print(e)

    return response

def destroy_ELB(LoadBalancerArn, ListenerArn, TargetGroupArn):
    client = boto3.client('elbv2')
    response = None
    try : 
        response = client.delete_load_balancer(
            LoadBalancerArn=LoadBalancerArn
        )
        response = client.delete_listener(
            ListenerArn=ListenerArn
        )
        response = client.delete_target_group(
            TargetGroupArn=TargetGroupArn
        )
    except ClientError as e:
        print(e)

    return response
    
def print_section(msg):
    """
    Print a section separator including given message
    :param msg: message
    :return: None
    """
    print(('#' * 40) + '\n# ' + msg + '\n' + ('#' * 40))


def is_test_complete(lg_dns, log_name):
    """
    Check if the horizontal scaling test has finished
    :param lg_dns: load generator DNS
    :param log_name: name of the log file
    :return: True if Horizontal Scaling test is complete and False otherwise.
    """

    log_string = 'http://{}/log?name={}'.format(lg_dns, log_name)

    # creates a log file for submission and monitoring
    f = open(log_name + ".log", "w")
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(log_string, timeout = 5)
            log_text = response.text
        except requests.exceptions.RequestException as e:
            print(e)
            time.sleep(1)
            pass 
    f.write(log_text)
    f.close()

    return '[Test finished]' in log_text
#def is_test_complete(load_generator_dns, log_name):
#    """
#    Check if auto scaling test is complete
#    :param load_generator_dns: lg dns
#    :param log_name: log file name
#    :return: True if Auto Scaling test is complete and False otherwise.
#    """
#    log_string = 'http://{}/log?name={}'.format(load_generator_dns, log_name)
#
#    # creates a log file for submission and monitoring
#    f = open(log_name + ".log", "w")
#    log_text = requests.get(log_string).text
#    f.write(log_text)
#    f.close()
#
#    return '[Test finished]' in log_text


def authenticate(load_generator_dns, submission_password, submission_username):
    """
    Authentication on LG
    :param load_generator_dns: LG DNS
    :param submission_password: SUBMISSION_PASSWORD
    :param submission_username: SUBMISSION_USERNAME
    :return: None
    """
    authenticate_string = 'http://{}/password?passwd={}&username={}'.format(
        load_generator_dns, submission_password, submission_username
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(authenticate_string, timeout = 10)
            break
        except requests.exceptions.RequestException as e:
            print(e)
            pass

def create_launch_configuration(as_client, sg_name):
    """
    create launch configuration
    :param as_client: autoscaling client
    :param sg_name: name of the security group to be attached to instance
    :return: None
    """
    response = None
    try:
        response = as_client.create_launch_configuration(
        LaunchConfigurationName = LAUNCH_CONFIGURATION_NAME,
        ImageId = WEB_SERVICE_AMI,
        KeyName=KEY_NAME,
        SecurityGroups=[
            sg_name,
        ],
        InstanceType = INSTANCE_TYPE,
        InstanceMonitoring={
            'Enabled': True
        },
        )
    except ClientError as e:
        print(e)

    return response

def create_target_group(ec2_client):
    response = ec2_client.describe_vpcs()
    vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')

    client = boto3.client('elbv2')
    response = None
    try:
        response = client.create_target_group(
            Name= TARGET_GROUP_NAME,
            Protocol='HTTP',
            Port=80,
            VpcId=vpc_id,
            HealthCheckProtocol='HTTP',
            HealthCheckPort='80',
            HealthCheckEnabled=True,
            HealthCheckPath='/',
            HealthCheckIntervalSeconds=30,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            TargetType='instance',
            Tags=TAGS
        )
    except ClientError as e:
        print(e)

    return response

def test_create_target_group():
    ec2_client = boto3.client("ec2",
                            region_name="us-east-1")
    as_client = boto3.client("autoscaling",
                            region_name="us-east-1")
    print_section('4. Create TG (Target Group)')
    # TODO: create Target Group
    res = create_target_group(ec2_client).get('TargetGroups', [{}])[0]
    tg_arn = res.get('TargetGroupArn','')
    print(tg_arn)

def create_load_balancer(ec2_client,sg_name):

    #get subnet ids
    response = ec2_client.describe_subnets()
    target_subnets = ['us-east-1a','us-east-1b']
    subnet_infos = response.get('Subnets', [{}])
    subnet_ids = []
    for subnet_info in subnet_infos:
        subnet_ids.append(subnet_info.get('SubnetId', ''))

    #create new load balancer
    client = boto3.client('elbv2')
    try:
        response = client.create_load_balancer(
            Name=LOAD_BALANCER_NAME,
            Subnets=subnet_ids,
            SecurityGroups=[
                sg_name,
            ],
            Scheme='internet-facing',
            Tags=TAGS,
            Type='application',
            IpAddressType='ipv4',
        )
    except ClientError as e:
        print(e)

    return response

def test_create_load_balancer():
    ec2_client = boto3.client("ec2",
                            region_name="us-east-1")
    as_client = boto3.client("autoscaling",
                            region_name="us-east-1")
    print_section('5. Create ELB (Elastic/Application Load Balancer)')

    # TODO create Load Balancer
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html
    res = create_load_balancer(ec2_client,'sg-4a52a65b').get('LoadBalancers', [{}])[0]
    lb_arn = res.get('LoadBalancerArn')
    lb_dns = res.get('DNSName')
    print("lb started. ARN={}, DNS={}".format(lb_arn, lb_dns))
    
def create_listener(ec2_client, tg_arn, lb_arn, lb_dns):
    response = None
    client = boto3.client('elbv2')
    try:
        response = client.create_listener(
            LoadBalancerArn=lb_arn,
            Protocol='HTTP',
            Port=80,
            DefaultActions=[
                {
                    'Type': 'forward',
                    'TargetGroupArn': tg_arn,
                    'ForwardConfig': {
                        'TargetGroups': [
                            {
                                'TargetGroupArn': tg_arn,
                                'Weight': 999
                            },
                        ],
                    }
                },
            ],
            Tags=TAGS
        )
    except ClientError as e:
        print(e)
    return response

def test_create_listener():
    ec2_client = boto3.client("ec2",
                            region_name="us-east-1")
    as_client = boto3.client("autoscaling",
                            region_name="us-east-1")
    
    print_section('6. Associate ELB with target group')

    # TODO create Load Balancer
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html
    res = create_target_group(ec2_client).get('TargetGroups', [{}])[0]
    tg_arn = res.get('TargetGroupArn','')

    res = create_load_balancer(ec2_client,'sg-4a52a65b').get('LoadBalancers', [{}])[0]
    lb_arn = res.get('LoadBalancerArn')
    lb_dns = res.get('DNSName')

    res = create_listener(ec2_client, tg_arn, lb_arn, lb_dns).get('TargetGroups', [{}])[0]
    lsn_arn = res.get('ListenerArn','')
    print(lsn_arn)

def create_auto_scaling_group(ec2_client, tg_arn):
    #get subnet ids
    response = ec2_client.describe_subnets()
    target_subnets = ['us-east-1a','us-east-1b']
    subnet_infos = response.get('Subnets', [{}])
    subnet_ids = []
    for subnet_info in subnet_infos:
        subnet_ids.append(subnet_info.get('SubnetId', ''))
    subnet_ids = ",".join(subnet_ids)

    response = None
    client = boto3.client('autoscaling')
    try:
        response = client.create_auto_scaling_group(
            AutoScalingGroupName=AUTO_SCALING_GROUP_NAME,
            LaunchConfigurationName=LAUNCH_CONFIGURATION_NAME,
            MinSize=ASG_MIN_SIZE,
            MaxSize=ASG_MAX_SIZE,
            DesiredCapacity=1,
            DefaultCooldown=ASG_DEFAULT_COOL_DOWN_PERIOD,
            TargetGroupARNs=[
                tg_arn,
            ],
            HealthCheckType='ELB',
            HealthCheckGracePeriod=HEALTH_CHECK_GRACE_PERIOD,
            VPCZoneIdentifier=subnet_ids,
            Tags=TAGS,
        )
    except ClientError as e:
        print(e)
    return response

def test_create_auto_scaling_group():
    ec2_client = boto3.client("ec2",
                            region_name="us-east-1")
    as_client = boto3.client("autoscaling",
                            region_name="us-east-1")
    
    print_section('7. Create ASG (Auto Scaling Group)')

    create_launch_configuration(as_client, 'sg-4a52a65b')
    # TODO create Load Balancer
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html
    res = create_target_group(ec2_client).get('TargetGroups', [{}])[0]
    tg_arn = res.get('TargetGroupArn','')

    res = create_auto_scaling_group(ec2_client, tg_arn)
    print(res)

def put_scaling_out_policy():
    client = boto3.client('autoscaling')
    response = None
    try:
        response = client.put_scaling_policy(
            AutoScalingGroupName=AUTO_SCALING_GROUP_NAME,
            PolicyName='scale-out-policy',
            PolicyType='StepScaling',
            AdjustmentType='ChangeInCapacity',
            Cooldown=COOL_DOWN_PERIOD_SCALE_OUT,
            StepAdjustments=[
                {
                    'MetricIntervalLowerBound': 0.0,
                    'ScalingAdjustment': SCALE_OUT_ADJUSTMENT
                },
            ],
            EstimatedInstanceWarmup=100,
        )
    except ClientError as e:
        print(e)
    return response

def put_scaling_in_policy():
    client = boto3.client('autoscaling')
    response = None
    try:
        response = client.put_scaling_policy(
            AutoScalingGroupName=AUTO_SCALING_GROUP_NAME,
            PolicyName='scale-in-policy',
            PolicyType='StepScaling',
            AdjustmentType='ChangeInCapacity',
            Cooldown=COOL_DOWN_PERIOD_SCALE_IN,
            StepAdjustments=[
                {
                    'MetricIntervalUpperBound': 0.0,
                    'ScalingAdjustment': SCALE_IN_ADJUSTMENT
                },
            ],
            EstimatedInstanceWarmup=100,
        )
    except ClientError as e:
        print(e)
    return response
def test_put_scaling_policy():
    print_section('8. Create policy and attached to ASG')
    res = put_scaling_out_policy().get('PolicyARN', '')
    res = put_scaling_in_policy().get('PolicyARN', '')
    print(res)

def create_scale_out_alarm(policy_arn):
    client = boto3.client('cloudwatch')
    response = None
    try:
        response = client.put_metric_alarm(
            AlarmName='scale_out_alarm',
            AlarmDescription='scale_out_alarm',
            ActionsEnabled=True,
            AlarmActions=[
                policy_arn,
            ],
            MetricName='CPUUtilization',
            Namespace='AWS/EC2',
            Statistic='Average',
            Period=ALARM_PERIOD,
            EvaluationPeriods=ALARM_EVALUATION_PERIODS_SCALE_OUT,
            Threshold=CPU_UPPER_THRESHOLD,
            ComparisonOperator= 'GreaterThanOrEqualToThreshold', #'GreaterThanOrEqualToThreshold'|'GreaterThanThreshold'|'LessThanThreshold'|'LessThanOrEqualToThreshold'|'LessThanLowerOrGreaterThanUpperThreshold'|'LessThanLowerThreshold'|'GreaterThanUpperThreshold',
            TreatMissingData='ignore',
            Tags=TAGS,
        )
    except ClientError as e:
        print(e)
    return response
def create_scale_in_alarm(policy_arn):
    client = boto3.client('cloudwatch')
    response = None
    try:
        response = client.put_metric_alarm(
            AlarmName='scale_in_alarm',
            AlarmDescription='scale_in_alarm',
            ActionsEnabled=True,
            AlarmActions=[
                policy_arn,
            ],
            MetricName='CPUUtilization',
            Namespace='AWS/EC2',
            Statistic='Average',
            Period=ALARM_PERIOD,
            EvaluationPeriods=ALARM_EVALUATION_PERIODS_SCALE_IN,
            Threshold=CPU_LOWER_THRESHOLD,
            ComparisonOperator= 'LessThanOrEqualToThreshold', #'GreaterThanOrEqualToThreshold'|'GreaterThanThreshold'|'LessThanThreshold'|'LessThanOrEqualToThreshold'|'LessThanLowerOrGreaterThanUpperThreshold'|'LessThanLowerThreshold'|'GreaterThanUpperThreshold',
            TreatMissingData='ignore',
            Tags=TAGS,
        )
    except ClientError as e:
        print(e)
    return response
def test_create_alarm():
    policy_arn = put_scaling_in_policy().get('PolicyARN', '')
    create_scale_in_alarm(policy_arn)


########################################
# Main routine
########################################
def main():
    # BIG PICTURE TODO: Programmatically provision autoscaling resources
    #   - Create security groups for Load Generator and ASG, ELB
    #   - Provision a Load Generator
    #   - Generate a Launch Configuration
    #   - Create a Target Group
    #   - Provision a Load Balancer
    #   - Associate Target Group with Load Balancer
    #   - Create an Autoscaling Group
    #   - Initialize Warmup Test
    #   - Initialize Autoscaling Test
    #   - Terminate Resources

    ec2_client = boto3.client("ec2",
                            region_name="us-east-1")
    as_client = boto3.client("autoscaling",
                            region_name="us-east-1")

    print_section('1 - create two security groups')

    PERMISSIONS = [
        {'IpProtocol': 'tcp',
         'FromPort': 80,
         'ToPort': 80,
         'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
         'Ipv6Ranges': [{'CidrIpv6': '::/0'}],
         }
    ]

    # TODO: Create two separate security groups and obtain the group ids
    data1 = create_security_group("sg1"+str(time.time()), PERMISSIONS, ec2_client)
    sg1_id = data1['SecurityGroupRules'][0]['GroupId']  # Security group for Load Generator instances
    print("sg1_id : "+sg1_id)
    data2 = create_security_group("sg2"+str(time.time()), PERMISSIONS, ec2_client)
    sg2_id = data2['SecurityGroupRules'][0]['GroupId']  # Security group for Web Service instances

    print_section('2 - create LG')

    # TODO: Create Load Generator instance and obtain ID and DNS
    instance = create_instance(LOAD_GENERATOR_AMI, sg1_id)
    if instance == None:
        print("Fail to vreate LG instance, exit")
        return
    else:
        lg = instance
        lg_id = lg.id
        lg_dns = lg.public_dns_name
    print("Load Generator running: id={} dns={}".format(lg_id, lg_dns))

    print_section('3. Create LC (Launch Config)')
    # TODO: create launch configuration
    create_launch_configuration(as_client, sg2_id)
    print_section('4. Create TG (Target Group)')
    # TODO: create Target Group
    res = create_target_group(ec2_client).get('TargetGroups', [{}])[0]
    tg_arn = res.get('TargetGroupArn','fail to get')

    print_section('5. Create ELB (Elastic/Application Load Balancer)')

    # TODO create Load Balancer
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html
    res = create_load_balancer(ec2_client,sg1_id).get('LoadBalancers', [{}])[0]
    lb_arn = res.get('LoadBalancerArn','fail to get')
    lb_dns = res.get('DNSName','fail to get')
    print("lb started. ARN={}, DNS={}".format(lb_arn, lb_dns))

    print_section('6. Associate ELB with target group')
    # TODO Associate ELB with target group

    res = create_listener(ec2_client, tg_arn, lb_arn, lb_dns).get('TargetGroups', [{}])[0]
    lsn_arn = res.get('ListenerArn','')
    print("Associate success. ARN={}".format(lsn_arn))

    print_section('7. Create ASG (Auto Scaling Group)')
    # TODO create Autoscaling group
    res = create_auto_scaling_group(ec2_client, tg_arn)

    print_section('8. Create policy and attached to ASG')
    # TODO Create Simple Scaling Policies for ASG
    scale_in_arn = put_scaling_in_policy().get('PolicyARN', '')
    scale_out_arn = put_scaling_out_policy().get('PolicyARN', '')

    print_section('9. Create Cloud Watch alarm. Action is to invoke policy.')
    # TODO create CloudWatch Alarms and link Alarms to scaling policies
    create_scale_in_alarm(scale_in_arn)
    create_scale_out_alarm(scale_out_arn)

    print_section('10. Authenticate with the load generator')
    authenticate(lg_dns, SUBMISSION_PASSWORD, SUBMISSION_USERNAME)

    print_section('11. Submit ELB DNS to LG, starting warm up test.')
    warmup_log_name = initialize_warmup(lg_dns, lb_dns)
    while not is_test_complete(lg_dns, warmup_log_name):
        time.sleep(1)

    print_section('12. Submit ELB DNS to LG, starting auto scaling test.')
    # May take a few minutes to start actual test after warm up test finishes
    log_name = initialize_test(lg_dns, lb_dns)
    while not is_test_complete(lg_dns, log_name):
        time.sleep(1)

    #destroy_resources(lb_arn, lsn_arn, tg_arn)
    #destory_instance([lg_id])
    #delete_security_group([sg1_id, sg2_id])





if __name__ == "__main__":
    #test_create_target_group()
    #test_create_load_balancer()
    #test_create_listener()
    #test_create_auto_scaling_group()
    #test_put_scaling_policy()
    #test_create_alarm()
    main()