import os
import logging
import boto3
import json
from datetime import datetime, timedelta
import random
import uuid
import traceback
import re

class MockAWSClient:
    """Mock AWS client for demo mode."""
    
    def __init__(self, service_name):
        self.service_name = service_name
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Created mock AWS client for {service_name}")
    
    def filter_log_events(self, **kwargs):
        """Mock method for CloudWatch Logs filter_log_events."""
        self.logger.info(f"Mock {self.service_name}.filter_log_events called with {kwargs}")
        return {'events': []}
    
    def lookup_events(self, **kwargs):
        """Mock method for CloudTrail lookup_events."""
        self.logger.info(f"Mock {self.service_name}.lookup_events called with {kwargs}")
        return {'Events': []}
    
    def list_detectors(self, **kwargs):
        """Mock method for GuardDuty list_detectors."""
        self.logger.info(f"Mock {self.service_name}.list_detectors called with {kwargs}")
        return {'DetectorIds': ['mock-detector-id']}
    
    def list_findings(self, **kwargs):
        """Mock method for GuardDuty list_findings."""
        self.logger.info(f"Mock {self.service_name}.list_findings called with {kwargs}")
        return {'FindingIds': []}
    
    def get_findings(self, **kwargs):
        """Mock method for GuardDuty get_findings."""
        self.logger.info(f"Mock {self.service_name}.get_findings called with {kwargs}")
        return {'Findings': []}
    
    def authorize_security_group_ingress(self, **kwargs):
        """Mock method for EC2 authorize_security_group_ingress."""
        self.logger.info(f"Mock {self.service_name}.authorize_security_group_ingress called with {kwargs}")
        return {'Return': True}


class AWSIntegration:
    """Class for handling all AWS-related functionality."""
    
    def __init__(self, region=None, demo_mode=True):
        """
        Initialize the AWS integration.
        
        Args:
            region (str, optional): AWS region
            demo_mode (bool, optional): Whether to run in demo mode
        """
        self.region = region or os.environ.get('AWS_REGION', 'us-east-1')
        self.demo_mode = demo_mode
        self.logger = logging.getLogger(__name__)
        self.security_group_id = os.environ.get('AWS_SECURITY_GROUP_ID', '')
        self.lookback_hours = int(os.environ.get('CLOUDTRAIL_LOOKBACK_HOURS', 24))
        
        self.logger.info(f"AWS Integration initialized: demo_mode={demo_mode}, region={self.region}")
    
    def get_client(self, service):
        """
        Create and return a boto3 client for the specified AWS service.
        
        Args:
            service (str): AWS service name
            
        Returns:
            object: Boto3 client
        """
        if self.demo_mode:
            # Return a mock client for demo mode
            return MockAWSClient(service)
        
        # For real AWS integration, use boto3 with proper credentials
        return boto3.client(
            service,
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            region_name=self.region
        )
    
    def fetch_cloudtrail_events(self, start_time=None, end_time=None):
        """
        Fetch CloudTrail events.
        
        Args:
            start_time (datetime, optional): Start time for events
            end_time (datetime, optional): End time for events
            
        Returns:
            list: List of processed CloudTrail events
        """
        if self.demo_mode:
            return self._generate_mock_cloudtrail_events()
        
        try:
            self.logger.info(f"Fetching CloudTrail events from {start_time} to {end_time}")
            
            # Create CloudTrail client
            cloudtrail = self.get_client('cloudtrail')
            
            # Set up parameters for lookup_events
            params = {}
            if start_time:
                params['StartTime'] = start_time
            if end_time:
                params['EndTime'] = end_time
            
            # Fetch events
            response = cloudtrail.lookup_events(**params)
           # print(response)
            # Process events
            processed_events = []
            for event in response.get('Events', []):
                print(json.loads(event.get('CloudTrailEvent', '{}')).get('sourceIPAddress'), event.get('EventTime'))
                
                processed_event = self._process_cloudtrail_event(event)
                processed_events.append(processed_event)
            
            self.logger.info(f"Fetched {len(processed_events)} CloudTrail events")
            return processed_events
            
        except Exception as e:
            self.logger.error(f"Error fetching CloudTrail events: {str(e)}")
            traceback.print_exc()
            return []
    
    def _process_cloudtrail_event(self, event):
        """
        Process a CloudTrail event into a standardized format.
        
        Args:
            event (dict): CloudTrail event from lookup_events API
            
        Returns:
            dict: Processed event
        """
        try:
            # Extract basic event information from the lookup_events API response
            event_id = event.get('EventId', str(uuid.uuid4()))
            event_name = event.get('EventName', 'Unknown')
            event_time = event.get('EventTime', datetime.now())
            event_source = event.get('EventSource', 'Unknown').replace('.amazonaws.com', '')
            
            # Parse the CloudTrail event JSON string
            cloud_trail_event = {}
            if 'CloudTrailEvent' in event:
                try:
                    cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
                except:
                    self.logger.error(f"Error parsing CloudTrailEvent JSON: {event.get('CloudTrailEvent')}")
            
            # Extract user identity
            user_identity = cloud_trail_event.get('userIdentity', {})
            identity_type = user_identity.get('type', 'Unknown')
            
            # Handle different identity types
            if identity_type == 'AssumedRole':
                # For assumed roles, use a more friendly format
                principal_id = user_identity.get('principalId', '')
                role_name = principal_id.split(':')[0] if ':' in principal_id else principal_id
                session_name = principal_id.split(':')[1] if ':' in principal_id else 'Unknown'
                
                # Clean up role name
                if '/' in role_name:
                    role_name = role_name.split('/')[-1]
                
                username = f"{session_name} (role: {role_name})"
                
                # If there's session context, add more details
                if 'sessionContext' in user_identity and 'sessionIssuer' in user_identity['sessionContext']:
                    issuer = user_identity['sessionContext']['sessionIssuer']
                    issuer_name = issuer.get('userName', issuer.get('type', 'Unknown'))
                    if issuer_name != 'Unknown':
                        username = f"{session_name} (via {issuer_name})"
            
            elif identity_type == 'IAMUser':
                username = user_identity.get('userName', 'Unknown IAM User')
            
            elif identity_type == 'Root':
                username = 'Root Account'
            
            elif identity_type == 'AWSService':
                # For AWS services, use the service name
                username = user_identity.get('invokedBy', 'AWS Service')
            
            else:
                # For other types, use a generic format
                username = f"{identity_type}: {user_identity.get('principalId', 'Unknown')}"
            
            # Extract IP and user agent
            source_ip = cloud_trail_event.get('sourceIPAddress', 'Unknown')
            
            # Make service names more friendly
            if source_ip.endswith('.amazonaws.com'):
                service_name = source_ip.replace('.amazonaws.com', '')
                source_ip = f"{service_name.capitalize()} Service"
            
            user_agent = cloud_trail_event.get('userAgent', 'Unknown')
            
            # Make user agent more friendly
            if user_agent == 'aws-internal/3 aws-sdk-java/1.11.991 Linux/4.9.230-0.1.ac.224.84.332.metal1.x86_64 OpenJDK_64-Bit_Server_VM/25.252-b09 java/1.8.0_252 vendor/Oracle_Corporation':
                user_agent = 'AWS Internal Service'
            elif 'aws-cli' in user_agent:
                user_agent = 'AWS CLI'
            elif 'console.amazonaws.com' in user_agent:
                user_agent = 'AWS Console'
            elif 'aws-sdk' in user_agent:
                user_agent = 'AWS SDK'
            
            # Make event source more friendly
            event_source = event_source.upper() if event_source.isupper() else event_source.capitalize()
            
            aws_region = cloud_trail_event.get('awsRegion', 'Unknown')
            
            # Determine risk level based on event characteristics
            risk_level = 'info'
            
            # High-risk events
            high_risk_events = [
                'ConsoleLogin', 'DeleteTrail', 'StopLogging', 'DeleteFlowLogs',
                'DeleteSecurityGroup', 'AuthorizeSecurityGroupIngress',
                'ModifyInstanceAttribute', 'CreateAccessKey', 'CreateUser',
                'AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy'
            ]
            
            # Medium-risk events
            medium_risk_events = [
                'CreateInstance', 'RunInstances', 'StartInstances', 'StopInstances',
                'RebootInstances', 'CreateSecurityGroup', 'CreateBucket',
                'PutBucketPolicy', 'PutBucketAcl'
            ]
            
            # Adjust risk level based on event type
            if event_name in high_risk_events:
                risk_level = 'high'
            elif event_name in medium_risk_events:
                risk_level = 'medium'
            elif 'error' in str(cloud_trail_event).lower() or 'denied' in str(cloud_trail_event).lower():
                risk_level = 'medium'  # Failed operations might indicate attempted abuse
            
            # Lower risk for service-initiated actions
            if 'Service' in username or 'Service' in source_ip:
                if risk_level == 'high':
                    risk_level = 'medium'
                elif risk_level == 'medium':
                    risk_level = 'low'
            
            # Create a user-friendly message
            # Format the event name to be more readable
            friendly_event_name = ' '.join([word for word in re.findall('[A-Z][a-z]*', event_name)])
            if not friendly_event_name:
                friendly_event_name = event_name
            
            # Create a base message
            message = f"{friendly_event_name} by {username}"
            
            # Add location information if available
            if source_ip != 'Unknown':
                message += f" from {source_ip}"
            
            # Add service information
            message += f" on {event_source}"
            
            # Add region if available
            if aws_region != 'Unknown':
                message += f" in {aws_region}"
            
            # Extract request parameters for more context
            request_params = cloud_trail_event.get('requestParameters', {})
            
            # Add specific details based on event type
            if event_name == 'AssumeRole' and request_params:
                role_arn = request_params.get('roleArn', '')
                if role_arn:
                    # Extract just the role name from the ARN
                    role_name = role_arn.split('/')[-1] if '/' in role_arn else role_arn.split(':')[-1]
                    message = f"Assumed role {role_name} by {username}"
                    if source_ip != 'Unknown':
                        message += f" from {source_ip}"
            
            # Extract resources affected
            resources = []
            for resource in event.get('Resources', []):
                resource_type = resource.get('ResourceType', '')
                resource_name = resource.get('ResourceName', '')
                if resource_type and resource_name:
                    # Only add if it's a meaningful resource (not just an access key or session)
                    if not (resource_type == 'AWS::IAM::AccessKey' or 
                            (resource_type == 'AWS::STS::AssumedRole' and 'Session' in resource_name)):
                        # Extract just the resource name from the ARN if it's an ARN
                        if resource_name.startswith('arn:aws:'):
                            resource_name = resource_name.split('/')[-1]
                        resources.append(f"{resource_name}")
            
            # Add resources to message if available
            if resources:
                unique_resources = list(set(resources))  # Remove duplicates
                if len(unique_resources) <= 2:
                    message += f" affecting {', '.join(unique_resources)}"
                else:
                    message += f" affecting {len(unique_resources)} resources"
            
            # Create the standardized event
            processed_event = {
                'id': event_id,
                'timestamp': event_time,
                'message': message,
                'source': 'cloudtrail',
                'event_name': event_name,
                'event_source': event_source,
                'username': username,
                'ip': source_ip,
                'user_agent': user_agent,
                'region': aws_region,
                'risk_level': risk_level,
                'raw_event': cloud_trail_event
            }
            
            return processed_event
            
        except Exception as e:
            self.logger.error(f"Error processing CloudTrail event: {str(e)}")
            traceback.print_exc()
            return {
                'id': event.get('EventId', str(uuid.uuid4())),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'message': f"Error processing CloudTrail event: {str(e)}",
                'source': 'cloudtrail',
                'risk_level': 'info',
                'raw_event': event
            }
    
    def _generate_mock_cloudtrail_events(self, count=10):
        """
        Generate realistic mock CloudTrail events for demo mode.
        
        Args:
            count (int): Number of events to generate
            
        Returns:
            list: List of mock CloudTrail events
        """
        events = []
        import uuid
        import random
        from datetime import datetime, timedelta
        
        # Define possible event types with realistic details
        event_types = [
            # High-risk events
            {
                'name': 'ConsoleLogin',
                'source': 'signin.amazonaws.com',
                'risk_level': 'high',
                'message_template': "Console login with MFA failure by {username} from {ip} using {user_agent}",
                'details': {
                    'additionalEventData': {
                        'MFAUsed': 'No',
                        'LoginTo': 'https://console.aws.amazon.com/console/home'
                    },
                    'responseElements': {
                        'ConsoleLogin': 'Failure'
                    },
                    'errorCode': 'AccessDenied',
                    'errorMessage': 'Failed authentication'
                }
            },
            {
                'name': 'DeleteTrail',
                'source': 'cloudtrail.amazonaws.com',
                'risk_level': 'high',
                'message_template': "CloudTrail trail 'management-events' deleted by {username} from {ip}",
                'details': {
                    'requestParameters': {
                        'name': 'management-events'
                    },
                    'responseElements': {
                        'trailARN': 'arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events'
                    }
                }
            },
            {
                'name': 'StopLogging',
                'source': 'cloudtrail.amazonaws.com',
                'risk_level': 'high',
                'message_template': "CloudTrail logging stopped for trail 'security-trail' by {username} from {ip}",
                'details': {
                    'requestParameters': {
                        'name': 'security-trail'
                    }
                }
            },
            {
                'name': 'CreateUser',
                'source': 'iam.amazonaws.com',
                'risk_level': 'high',
                'message_template': "IAM user 'backdoor-admin' created by {username} from {ip}",
                'details': {
                    'requestParameters': {
                        'userName': 'backdoor-admin',
                        'path': '/'
                    },
                    'responseElements': {
                        'user': {
                            'userName': 'backdoor-admin',
                            'userId': 'AIDA123456789EXAMPLE',
                            'arn': 'arn:aws:iam::123456789012:user/backdoor-admin',
                            'createDate': datetime.now().isoformat()
                        }
                    }
                }
            },
            {
                'name': 'AttachUserPolicy',
                'source': 'iam.amazonaws.com',
                'risk_level': 'high',
                'message_template': "Admin policy 'AdministratorAccess' attached to user 'backdoor-admin' by {username} from {ip}",
                'details': {
                    'requestParameters': {
                        'userName': 'backdoor-admin',
                        'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'
                    }
                }
            },
            {
                'name': 'PutBucketPolicy',
                'source': 's3.amazonaws.com',
                'risk_level': 'high',
                'message_template': "S3 bucket 'financial-data' policy modified to allow public access by {username} from {ip}",
                'details': {
                    'requestParameters': {
                        'bucketName': 'financial-data',
                        'policy': '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::financial-data/*"}]}'
                    }
                }
            },
            {
                'name': 'ModifyVpcEndpoint',
                'source': 'ec2.amazonaws.com',
                'risk_level': 'high',
                'message_template': "VPC endpoint policy modified to bypass security controls by {username} from {ip}",
                'details': {
                    'requestParameters': {
                        'vpcEndpointId': 'vpce-0123456789abcdef0',
                        'policyDocument': '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}'
                    }
                }
            },
            
            # Medium-risk events
            {
                'name': 'RunInstances',
                'source': 'ec2.amazonaws.com',
                'risk_level': 'medium',
                'message_template': "Unusual EC2 instance type 'p3.16xlarge' launched in region 'ap-northeast-1' by {username} from {ip}",
                'details': {
                    'requestParameters': {
                        'instanceType': 'p3.16xlarge',
                        'imageId': 'ami-0c55b159cbfafe1f0',
                        'maxCount': 5,
                        'minCount': 5
                    },
                    'responseElements': {
                        'instancesSet': {
                            'items': [
                                {'instanceId': 'i-0123456789abcdef0'},
                                {'instanceId': 'i-0123456789abcdef1'},
                                {'instanceId': 'i-0123456789abcdef2'},
                                {'instanceId': 'i-0123456789abcdef3'},
                                {'instanceId': 'i-0123456789abcdef4'}
                            ]
                        }
                    }
                }
            },
            {
                'name': 'CreateSecurityGroup',
                'source': 'ec2.amazonaws.com',
                'risk_level': 'medium',
                'message_template': "Security group 'allow-all-traffic' created by {username} from {ip}",
                'details': {
                    'requestParameters': {
                        'groupName': 'allow-all-traffic',
                        'groupDescription': 'Allow all inbound traffic',
                        'vpcId': 'vpc-0123456789abcdef0'
                    },
                    'responseElements': {
                        'groupId': 'sg-0123456789abcdef0'
                    }
                }
            },
            {
                'name': 'AuthorizeSecurityGroupIngress',
                'source': 'ec2.amazonaws.com',
                'risk_level': 'medium',
                'message_template': "Security group ingress rule added to allow all traffic (0.0.0.0/0) by {username} from {ip}",
                'details': {
                    'requestParameters': {
                        'groupId': 'sg-0123456789abcdef0',
                        'ipPermissions': {
                            'items': [
                                {
                                    'ipProtocol': '-1',
                                    'fromPort': 0,
                                    'toPort': 65535,
                                    'ipRanges': {
                                        'items': [
                                            {'cidrIp': '0.0.0.0/0'}
                                        ]
                                    }
                                }
                            ]
                        }
                    }
                }
            },
            {
                'name': 'CreateBucket',
                'source': 's3.amazonaws.com',
                'risk_level': 'medium',
                'message_template': "S3 bucket 'data-exfiltration-target' created in non-standard region 'eu-west-3' by {username} from {ip}",
                'details': {
                    'requestParameters': {
                        'bucketName': 'data-exfiltration-target',
                        'x-amz-acl': 'private'
                    },
                    'additionalEventData': {
                        'LocationConstraint': 'eu-west-3'
                    }
                }
            },
            {
                'name': 'CreateAccessKey',
                'source': 'iam.amazonaws.com',
                'risk_level': 'medium',
                'message_template': "New access key created for user 'admin' by {username} from {ip}",
                'details': {
                    'requestParameters': {
                        'userName': 'admin'
                    },
                    'responseElements': {
                        'accessKey': {
                            'userName': 'admin',
                            'accessKeyId': 'AKIA0123456789EXAMPLE',
                            'status': 'Active',
                            'createDate': datetime.now().isoformat()
                        }
                    }
                }
            },
            
            # Low-risk events
            {
                'name': 'GetObject',
                'source': 's3.amazonaws.com',
                'risk_level': 'low',
                'message_template': "S3 object 'financial-reports/2023-Q4.xlsx' accessed by {username} from {ip}",
                'details': {
                    'requestParameters': {
                        'bucketName': 'company-financial-data',
                        'key': 'financial-reports/2023-Q4.xlsx'
                    }
                }
            },
            {
                'name': 'DescribeInstances',
                'source': 'ec2.amazonaws.com',
                'risk_level': 'low',
                'message_template': "EC2 instances described by {username} from {ip} - unusual time of day",
                'details': {
                    'requestParameters': {
                        'instancesSet': {
                            'items': [
                                {'instanceId': 'i-0123456789abcdef0'},
                                {'instanceId': 'i-0123456789abcdef1'}
                            ]
                        }
                    }
                }
            },
            {
                'name': 'GetCallerIdentity',
                'source': 'sts.amazonaws.com',
                'risk_level': 'low',
                'message_template': "Caller identity checked by {username} from {ip} - potential reconnaissance",
                'details': {
                    'responseElements': {
                        'account': '123456789012',
                        'arn': 'arn:aws:iam::123456789012:user/{username}',
                        'userId': 'AIDA0123456789EXAMPLE'
                    }
                }
            },
            {
                'name': 'DescribeDBInstances',
                'source': 'rds.amazonaws.com',
                'risk_level': 'low',
                'message_template': "RDS database instances enumerated by {username} from {ip}",
                'details': {
                    'requestParameters': {
                        'dbiResourceId': 'db-0123456789ABCDEFGHIJKLMNO'
                    }
                }
            },
            
            # Info-level events
            {
                'name': 'ListBuckets',
                'source': 's3.amazonaws.com',
                'risk_level': 'info',
                'message_template': "S3 buckets listed by {username} from {ip}",
                'details': {}
            },
            {
                'name': 'DescribeRegions',
                'source': 'ec2.amazonaws.com',
                'risk_level': 'info',
                'message_template': "EC2 regions described by {username} from {ip}",
                'details': {
                    'requestParameters': {
                        'regionNames': {
                            'items': [
                                {'regionName': 'us-east-1'},
                                {'regionName': 'us-west-2'},
                                {'regionName': 'eu-west-1'}
                            ]
                        }
                    }
                }
            },
            {
                'name': 'GetAccountSummary',
                'source': 'iam.amazonaws.com',
                'risk_level': 'info',
                'message_template': "IAM account summary retrieved by {username} from {ip}",
                'details': {}
            },
            {
                'name': 'DescribeAlarms',
                'source': 'monitoring.amazonaws.com',
                'risk_level': 'info',
                'message_template': "CloudWatch alarms described by {username} from {ip}",
                'details': {}
            }
        ]
        
        # Define possible usernames with realistic patterns
        usernames = [
            'admin', 
            'john.doe', 
            'jane.smith', 
            'david.wilson', 
            'sarah.johnson',
            'terraform-service',
            'jenkins-automation',
            'cloudformation-service',
            'root'
        ]
        
        # Define possible user agents with realistic patterns
        user_agents = [
            'AWS Console',
            'aws-cli/2.9.19 Python/3.9.16 Linux/5.15.0-1031-aws exe/x86_64.ubuntu.22',
            'aws-sdk-java/2.20.56 Linux/5.15.0-1031-aws OpenJDK_64-Bit_Server_VM/17.0.6+10 Java/17.0.6 vendor/Amazon.com_Inc.',
            'Boto3/1.26.142 Python/3.10.10 Linux/5.15.0-1031-aws',
            'Terraform/1.4.6 (+https://www.terraform.io) terraform-provider-aws/4.67.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36'
        ]
        
        # Define possible IP addresses with realistic patterns
        ip_ranges = [
            # Corporate ranges
            ['10.0.0.0', '10.255.255.255'],
            ['172.16.0.0', '172.31.255.255'],
            ['192.168.0.0', '192.168.255.255'],
            # Public ranges (for external access)
            ['20.0.0.0', '20.255.255.255'],  # Microsoft Azure
            ['35.0.0.0', '35.255.255.255'],  # Google Cloud
            ['52.0.0.0', '52.255.255.255'],  # Amazon AWS
            ['104.0.0.0', '104.255.255.255'], # Various cloud providers
            ['13.0.0.0', '13.255.255.255'],  # Amazon AWS
            # Suspicious ranges
            ['185.0.0.0', '185.255.255.255'], # Known for hosting malicious activities
            ['45.0.0.0', '45.255.255.255'],   # Mixed usage including some suspicious
        ]
        
        # Generate random events
        for i in range(count):
            # Select a random event type with weighted probability
            weights = [1 if e['risk_level'] == 'high' else 
                      3 if e['risk_level'] == 'medium' else 
                      5 if e['risk_level'] == 'low' else 10 for e in event_types]
            event_type = random.choices(event_types, weights=weights)[0]
            
            # Generate random IP address from the ranges
            ip_range = random.choice(ip_ranges)
            start_ip = ip_range[0].split('.')
            end_ip = ip_range[1].split('.')
            
            # Convert to integers
            start_octets = [int(x) for x in start_ip]
            end_octets = [int(x) for x in end_ip]
            
            # Generate random IP within range
            ip_octets = []
            for j in range(4):
                octet = random.randint(start_octets[j], end_octets[j])
                ip_octets.append(str(octet))
            
            ip = '.'.join(ip_octets)
            
            # Select random username and user agent
            username = random.choice(usernames)
            user_agent = random.choice(user_agents)
            
            # Generate timestamp within the last 24 hours
            hours_ago = random.randint(0, 23)
            minutes_ago = random.randint(0, 59)
            seconds_ago = random.randint(0, 59)
            event_time = datetime.now() - timedelta(hours=hours_ago, minutes=minutes_ago, seconds=seconds_ago)
            timestamp = event_time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Create the message
            message = event_type['message_template'].format(
                username=username,
                ip=ip,
                user_agent=user_agent
            )
            
            # Create a mock CloudTrail event
            event_id = f"mock-{uuid.uuid4()}"
            
            # Create the raw event with details
            raw_event = {
                'eventVersion': '1.08',
                'eventID': event_id,
                'eventTime': event_time.isoformat(),
                'eventName': event_type['name'],
                'eventSource': event_type['source'],
                'awsRegion': random.choice(['us-east-1', 'us-west-2', 'eu-west-1', 'ap-northeast-1', 'sa-east-1']),
                'sourceIPAddress': ip,
                'userAgent': user_agent,
                'userIdentity': {
                    'type': 'IAMUser',
                    'principalId': f'AIDA0123456789{username.upper()}',
                    'arn': f'arn:aws:iam::123456789012:user/{username}',
                    'accountId': '123456789012',
                    'accessKeyId': f'AKIA0123456789{username[:8].upper()}',
                    'userName': username
                },
                'eventType': 'AwsApiCall',
                'recipientAccountId': '123456789012'
            }
            
            # Add event-specific details
            for key, value in event_type['details'].items():
                raw_event[key] = value
            
            # Create the processed event
            processed_event = {
                'id': event_id,
                'timestamp': timestamp,
                'message': message,
                'source': 'cloudtrail',
                'event_name': event_type['name'],
                'event_source': event_type['source'],
                'username': username,
                'ip': ip,
                'user_agent': user_agent,
                'risk_level': event_type['risk_level'],
                'raw_event': raw_event,
                'region': raw_event['awsRegion'],
                'account_id': '123456789012'
            }
            
            events.append(processed_event)
        
        # Sort events by timestamp (newest first)
        events.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return events
    
    def fetch_guardduty_findings(self):
        """
        Fetch findings from AWS GuardDuty.
        
        Returns:
            list: List of GuardDuty findings
        """
        guardduty_client = self.get_client('guardduty')
        
        try:
            # List detectors
            detectors = guardduty_client.list_detectors()
            detector_ids = detectors.get('DetectorIds', [])
            
            findings = []
            
            for detector_id in detector_ids:
                # List findings for each detector
                response = guardduty_client.list_findings(
                    DetectorId=detector_id,
                    FindingCriteria={
                        'Criterion': {
                            'severity': {
                                'Eq': ['8', '7', '6', '5', '4']  # High and medium severity
                            }
                        }
                    }
                )
                
                finding_ids = response.get('FindingIds', [])
                
                if finding_ids:
                    # Get finding details
                    finding_details = guardduty_client.get_findings(
                        DetectorId=detector_id,
                        FindingIds=finding_ids
                    )
                    
                    findings.extend(finding_details.get('Findings', []))
            
            return findings
        except Exception as e:
            self.logger.error(f"Error fetching GuardDuty findings: {str(e)}")
            return []
    
    def block_ip_in_security_group(self, ip_address, sg_id=None, description=None):
        """
        Block an IP address by adding a deny rule to a security group.
        
        Args:
            ip_address (str): IP address to block
            sg_id (str, optional): Security group ID
            description (str, optional): Description for the rule
            
        Returns:
            dict: Result of the operation
        """
        if self.demo_mode:
            self.logger.info(f"Demo mode: Simulating blocking IP {ip_address}")
            return {'success': True, 'message': f'Demo mode: IP {ip_address} blocked'}
        
        sg_id = sg_id or self.security_group_id
        
        if not sg_id:
            return {'success': False, 'message': 'No security group ID provided'}
        
        ec2_client = self.get_client('ec2')
        
        try:
            # Format IP for security group rule (CIDR notation)
            ip_cidr = f"{ip_address}/32"
            
            # Add deny rule to security group
            response = ec2_client.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        'IpProtocol': '-1',  # All protocols
                        'FromPort': -1,      # All ports
                        'ToPort': -1,        # All ports
                        'IpRanges': [
                            {
                                'CidrIp': ip_cidr,
                                'Description': description or f'Blocked by CloudSentinel at {datetime.now().isoformat()}'
                            }
                        ]
                    }
                ]
            )
            
            return {
                'success': True,
                'message': f'Successfully blocked IP {ip_address}',
                'security_group_id': sg_id,
                'aws_response': response
            }
            
        except Exception as e:
            self.logger.error(f"Error blocking IP: {str(e)}")
            return {
                'success': False,
                'message': f'Failed to block IP {ip_address}: {str(e)}',
                'security_group_id': sg_id
            }
    
    def process_security_logs(self, callback=None):
        """
        Process security logs from CloudTrail.
        
        Args:
            callback (function, optional): Callback function to process each log event
            
        Returns:
            int: Number of logs processed
        """
        if self.demo_mode:
            self.logger.info("Demo mode: Generating mock CloudTrail events")
            # Generate 5-15 random events
            event_count = random.randint(5, 15)
            events = self._generate_mock_cloudtrail_events(count=event_count)
            
            processed_count = 0
            for event in events:
                if callback:
                    callback(event, source='cloudtrail')
                processed_count += 1
            
            self.logger.info(f"Generated {processed_count} mock CloudTrail events")
            return processed_count
        
        processed_count = 0
        
        try:
            # Get the current time and lookback period
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=self.lookback_hours)
            
            # Process CloudTrail events
            self.logger.info(f"Processing CloudTrail events from {start_time} to {end_time}")
            
            # Try to get events from CloudTrail API
            trail_events = self.fetch_cloudtrail_events(start_time, end_time)
        
            
            # Process the events
            for event in trail_events:
                if callback:
                    callback(event, source='cloudtrail')
                processed_count += 1
            
            return processed_count
            
        except Exception as e:
            self.logger.error(f"Error processing security logs: {str(e)}")
            traceback.print_exc()
            return processed_count 