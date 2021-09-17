import boto3
import os

# Refer to the Boto3 documentation:
#    http://boto3.readthedocs.io/en/latest/guide/quickstart.html
#
# Your AWS credentials must be configured in accordance with:
#    http://boto3.readthedocs.io/en/latest/guide/configuration.html

IMAGE_ID = 'ami-0747bdcabd34c712a'
INSTANCE_TYPE = 't3.micro'
KEY_NAME = os.getenv("KEY_NAME")
SECURITY_GROUP_NAME = os.getenv("SECURITY_GROUP_NAME")
TAGS = [{'Key': 'project', 'Value': 'getting-started-with-cloud-computing'}]

# Create an EC2 Client
ec2_client = boto3.client("ec2",
                          region_name="us-east-1")

# Launching instance
#
# http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.run_instances
response = ec2_client.run_instances(
    ImageId=IMAGE_ID,
    InstanceType=INSTANCE_TYPE,
    KeyName=KEY_NAME,
    MaxCount=1,
    MinCount=1,
    SecurityGroups=[
        SECURITY_GROUP_NAME,
    ],
    TagSpecifications=[{
        'ResourceType': 'instance',
        'Tags': TAGS
    }, {
        'ResourceType': 'volume',
        'Tags': TAGS
    }]
)

instance = response.get('Instances')[0]

print("Launched instance with Instance Id: [{}]!".format(instance.get('InstanceId')))
