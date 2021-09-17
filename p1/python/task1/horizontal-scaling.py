
import boto3
import botocore
from botocore.exceptions import ClientError

import os
import requests
import time
import json
import configparser
import re
from dateutil.parser import parse


########################################
# Constants
########################################
with open('horizontal-scaling-config.json') as file:
    configuration = json.load(file)

LOAD_GENERATOR_AMI = configuration['load_generator_ami']
WEB_SERVICE_AMI = configuration['web_service_ami']
INSTANCE_TYPE = configuration['instance_type']
KEY_NAME = os.getenv("KEY_NAME")

# Credentials fetched from environment variables
SUBMISSION_USERNAME = os.environ['SUBMISSION_USERNAME']
SUBMISSION_PASSWORD = os.environ['SUBMISSION_PASSWORD']

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


def initialize_test(lg_dns, first_web_service_dns):
    """
    Start the horizontal scaling test
    :param lg_dns: Load Generator DNS
    :param first_web_service_dns: Web service DNS
    :return: Log file name
    """


    add_ws_string = 'http://{}/test/horizontal?dns={}'.format(
        lg_dns, first_web_service_dns
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(add_ws_string)
        except requests.exceptions.ConnectionError:
            time.sleep(1)
            pass 

    # TODO: return log File name
    return get_test_id(response)


def print_section(msg):
    """
    Print a section separator including given message
    :param msg: message
    :return: None
    """
    print(('#' * 40) + '\n# ' + msg + '\n' + ('#' * 40))


def get_test_id(response):
    """
    Extracts the test id from the server response.
    :param response: the server response.
    :return: the test name (log file name).
    """
    response_text = response.text

    regexpr = re.compile(TEST_NAME_REGEX)

    return regexpr.findall(response_text)[0]


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
            response = requests.get(log_string)
            log_text = response.text
        except requests.exceptions.ConnectionError:
            time.sleep(1)
            pass 
    f.write(log_text)
    f.close()

    return '[Test finished]' in log_text


def add_web_service_instance(lg_dns, sg2_id, log_name):
    """
    Launch a new WS (Web Server) instance and add to the test
    :param lg_dns: load generator DNS
    :param sg2_name: name of WS security group
    :param log_name: name of the log file
    """
    ins = create_instance(WEB_SERVICE_AMI, sg2_id)
    print("New WS launched. id={}, dns={}".format(
        ins.instance_id,
        ins.public_dns_name)
    )
    add_req = 'http://{}/test/horizontal/add?dns={}'.format(
        lg_dns,
        ins.public_dns_name
    )
    while True:
        try:
            if requests.get(add_req).status_code == 200:
                print("New WS submitted to LG.")
                break
            elif is_test_complete(lg_dns, log_name):
                print("New WS not submitted because test already completed.")
                break
        except requests.exceptions.ConnectionError:
            pass


def authenticate(lg_dns, submission_password, submission_username):
    """
    Authentication on LG
    :param lg_dns: LG DNS
    :param submission_password: SUBMISSION_PASSWORD
    :param submission_username: SUBMISSION_USERNAME
    :return: None
    """

    authenticate_string = 'http://{}/password?passwd={}&username={}'.format(
        lg_dns, submission_password, submission_username
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(authenticate_string)
            break
        except requests.exceptions.ConnectionError:
            pass


def get_rps(lg_dns, log_name):
    """
    Return the current RPS as a floating point number
    :param lg_dns: LG DNS
    :param log_name: name of log file
    :return: latest RPS value
    """

    log_string = 'http://{}/log?name={}'.format(lg_dns, log_name)
    config = configparser.ConfigParser(strict=False)
    config.read_string(requests.get(log_string).text)
    sections = config.sections()
    sections.reverse()
    rps = 0
    for sec in sections:
        print(sec)
        if 'Current rps=' in sec:
            rps = float(sec[len('Current rps='):])
            break
    return rps


def get_test_start_time(lg_dns, log_name):
    """
    Return the test start time in UTC
    :param lg_dns: LG DNS
    :param log_name: name of log file
    :return: datetime object of the start time in UTC
    """
    log_string = 'http://{}/log?name={}'.format(lg_dns, log_name)
    print("log_string : "+str(log_string))
    start_time = None
    while start_time is None:
        config = configparser.ConfigParser(strict=False)
        config.read_string(requests.get(log_string).text)
        # By default, options names in a section are converted
        # to lower case by configparser
        start_time = dict(config.items('Test')).get('starttime', None)
    return parse(start_time)

def get_security_groups(ec2_client):
    try:
        response = ec2_client.describe_security_groups()
        print(response)
    except ClientError as e:
        print(e)
    return

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



########################################
# Main routine
########################################
def main():
    # BIG PICTURE TODO: Provision resources to achieve horizontal scalability
    #   - Create security groups for Load Generator and Web Service
    #   - Provision a Load Generator instance
    #   - Provision a Web Service instance
    #   - Register Web Service DNS with Load Generator
    #   - Add Web Service instances to Load Generator
    #   - Terminate resources

    # Create an EC2 Client
    ec2_client = boto3.client("ec2",
                            region_name="us-east-1")
        
    print_section('1 - create two security groups')
    sg_permissions = [
        {'IpProtocol': 'tcp',
         'FromPort': 80,
         'ToPort': 80,
         'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
         'Ipv6Ranges': [{'CidrIpv6': '::/0'}],
         }
    ]
    
    # TODO: Create two separate security groups and obtain the group ids
    data1 = create_security_group("sg1"+str(time.time()), sg_permissions, ec2_client)
    sg1_id = data1['SecurityGroupRules'][0]['GroupId']  # Security group for Load Generator instances
    print("sg1_id : "+sg1_id)
    data2 = create_security_group("sg2"+str(time.time()), sg_permissions, ec2_client)
    sg2_id = data2['SecurityGroupRules'][0]['GroupId']  # Security group for Web Service instances

    print_section('2 - create LG')

    response = ec2_client.describe_instances()# current instance info
    print(response)

    # TODO: Create Load Generator instance and obtain ID and DNS
    
    instance = create_instance(LOAD_GENERATOR_AMI, sg1_id)
    print(instance)
    lg = instance
    lg_id = lg.id
    lg_dns = lg.public_dns_name
    print("Load Generator running: id={} dns={}".format(lg_id, lg_dns))

    print_section('3. Authenticate with the load generator')
    authenticate(lg_dns, SUBMISSION_PASSWORD, SUBMISSION_USERNAME)

    # TODO: Create First Web Service Instance and obtain the DNS
    instance = create_instance(WEB_SERVICE_AMI, sg2_id)
    web_service_dns = instance.public_dns_name
    last_time = time.time()
    print_section('4. Submit the first WS instance DNS to LG, starting test.')
    log_name = initialize_test(lg_dns, web_service_dns)
    print(log_name)
    last_launch_time = get_test_start_time(lg_dns, log_name)
    while not is_test_complete(lg_dns, log_name):
        # TODO: Check RPS and last launch time
        # TODO: Add New Web Service Instance if Required
        rps = get_rps(lg_dns, log_name)
        cur_time = time.time()
        if rps != 0:
            print("rps : " + str(rps))
        if cur_time - last_time > 100 and rps != 0 :
            if rps < 50:
                last_time = cur_time
                add_web_service_instance(lg_dns, sg2_id, log_name)
        else:
            continue
        time.sleep(1)

    print_section('End Test')
#
    ## TODO: Terminate Resources


if __name__ == '__main__':
    main()
    pass