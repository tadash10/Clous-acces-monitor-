import boto3
from botocore.exceptions import ClientError

# Change these to your preferred values
SECURITY_TEAM_EMAIL = "security@yourcompany.com"
REGION = "us-east-1"

def send_email(subject, body):
    """
    Sends an email to the security team with the given subject and body.
    """
    ses = boto3.client("ses", region_name=REGION)
    response = ses.send_email(
        Source=SECURITY_TEAM_EMAIL,
        Destination={"ToAddresses": [SECURITY_TEAM_EMAIL]},
        Message={
            "Subject": {"Data": subject},
            "Body": {"Text": {"Data": body}},
        },
    )
    print(f"Sent email to {SECURITY_TEAM_EMAIL} with message ID {response['MessageId']}")

def check_s3_bucket(bucket_name):
    """
    Checks the permissions and configuration of an S3 bucket.
    """
    s3 = boto3.resource("s3", region_name=REGION)
    bucket = s3.Bucket(bucket_name)

    try:
        # Check the bucket's ACL and policy
        acl = bucket.Acl()
        policy = bucket.Policy().policy_text

        # If the bucket is publicly accessible, send an alert
        if acl.grants[0]["Grantee"]["Type"] == "Group" and acl.grants[0]["Grantee"]["URI"] == "http://acs.amazonaws.com/groups/global/AllUsers":
            send_email(
                subject=f"S3 Bucket {bucket_name} is publicly accessible",
                body=f"The following S3 bucket is publicly accessible: {bucket_name}\n\nBucket policy:\n{policy}",
            )
    except ClientError as e:
        # If the bucket does not exist or we do not have permissions to access it, ignore it
        if e.response["Error"]["Code"] == "NoSuchBucket" or e.response["Error"]["Code"] == "AccessDenied":
            pass
        else:
            raise e

def check_iam_role(role_name):
    """
    Checks the permissions and configuration of an IAM role.
    """
    iam = boto3.client("iam", region_name=REGION)

    try:
        # Check the role's policy
        policy = iam.get_role_policy(RoleName=role_name, PolicyName="default").get("PolicyDocument")

        # If the role allows unrestricted access, send an alert
        if "Effect" in policy and policy["Effect"] == "Allow" and ("*" in policy.get("Action", []) or "*" in policy.get("Resource", [])):
            send_email(
                subject=f"IAM Role {role_name} allows unrestricted access",
                body=f"The following IAM role allows unrestricted access: {role_name}\n\nRole policy:\n{policy}",
            )
    except ClientError as e:
        # If the role does not exist or we do not have permissions to access it, ignore it
        if e.response["Error"]["Code"] == "NoSuchEntity" or e.response["Error"]["Code"] == "AccessDenied":
            pass
        else:
            raise e

def check_ec2_instance(instance_id):
    """
    Checks the permissions and configuration of an EC2 instance.
    """
    ec2 = boto3.client("ec2", region_name=REGION)

    try:
        # Check the instance's security groups
        groups = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="groupSet")["Groups"]

        # If the instance allows unrestricted access
