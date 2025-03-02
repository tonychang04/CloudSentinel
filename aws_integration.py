import os
import logging
import boto3
from datetime import datetime, timedelta

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
        
        # Log groups to monitor
        self.log_groups = os.environ.get('AWS_LOG_GROUPS', '').split(',')
        self.security_group_id = os.environ.get('AWS_SECURITY_GROUP_ID', '')
        
        self.logger.info(f"AWS Integration initialized: demo_mode={demo_mode}, region={self.region}")
    
    def get_client(self, service):
        """
        Create and return a boto3 client for the specified AWS service.
        
        Args:
            service (str): AWS service name
            
        Returns:
            object: Boto3 client or mock client
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
    
    def fetch_cloudwatch_logs(self, log_group_name, start_time=None, end_time=None, filter_pattern=None):
        """
        Fetch logs from CloudWatch based on specified parameters.
        
        Args:
            log_group_name (str): The name of the CloudWatch Log Group
            start_time (datetime, optional): Start time for log query
            end_time (datetime, optional): End time for log query
            filter_pattern (str, optional): CloudWatch Logs filter pattern
            
        Returns:
            list: List of log events
        """
        logs_client = self.get_client('logs')
        
        # Convert datetime objects to milliseconds since epoch if provided
        kwargs = {'logGroupName': log_group_name}
        
        if start_time:
            kwargs['startTime'] = int(start_time.timestamp() * 1000)
        
        if end_time:
            kwargs['endTime'] = int(end_time.timestamp() * 1000)
        
        if filter_pattern:
            kwargs['filterPattern'] = filter_pattern
        
        try:
            response = logs_client.filter_log_events(**kwargs)
            
            events = response.get('events', [])
            
            # Handle pagination if there are more logs
            while 'nextToken' in response and not self.demo_mode:
                kwargs['nextToken'] = response['nextToken']
                response = logs_client.filter_log_events(**kwargs)
                events.extend(response.get('events', []))
            
            return events
        except Exception as e:
            self.logger.error(f"Error fetching CloudWatch logs: {str(e)}")
            return []
    
    def fetch_cloudtrail_events(self, start_time=None, end_time=None):
        """
        Fetch events from AWS CloudTrail.
        
        Args:
            start_time (datetime, optional): Start time for event query
            end_time (datetime, optional): End time for event query
            
        Returns:
            list: List of CloudTrail events
        """
        cloudtrail_client = self.get_client('cloudtrail')
        
        # Prepare lookup attributes
        kwargs = {}
        
        if start_time:
            kwargs['StartTime'] = start_time
        
        if end_time:
            kwargs['EndTime'] = end_time
        
        try:
            response = cloudtrail_client.lookup_events(**kwargs)
            events = response.get('Events', [])
            
            # Handle pagination
            while 'NextToken' in response and not self.demo_mode:
                kwargs['NextToken'] = response['NextToken']
                response = cloudtrail_client.lookup_events(**kwargs)
                events.extend(response.get('Events', []))
            
            return events
        except Exception as e:
            self.logger.error(f"Error fetching CloudTrail events: {str(e)}")
            return []
    
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
    
    def block_ip_in_security_group(self, ip_address, security_group_id=None, description=None):
        """
        Block an IP address by adding a deny rule to a security group.
        
        Args:
            ip_address (str): IP address to block
            security_group_id (str, optional): ID of the security group to modify
            description (str, optional): Description for the security group rule
            
        Returns:
            dict: Result of the operation
        """
        if not ip_address:
            return {'success': False, 'message': 'No IP address provided'}
        
        if self.demo_mode:
            # Demo mode - just return success
            return {
                'success': True,
                'message': f'Demo mode: IP {ip_address} would be blocked in security group'
            }
        
        # Use the provided security group ID or the default one
        sg_id = security_group_id or self.security_group_id
        
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
        Process security logs from various AWS sources.
        
        Args:
            callback (function, optional): Callback function to process each log event
            
        Returns:
            int: Number of logs processed
        """
        if self.demo_mode:
            self.logger.info("Demo mode: Skipping real AWS log processing")
            return 0
        
        processed_count = 0
        
        try:
            # Get the current time and 5 minutes ago
            end_time = datetime.now()
            start_time = end_time - timedelta(minutes=5)
            
            # Process CloudWatch logs
            for log_group in self.log_groups:
                if not log_group:  # Skip empty log group names
                    continue
                    
                self.logger.info(f"Processing CloudWatch logs from {log_group}")
                events = self.fetch_cloudwatch_logs(log_group, start_time, end_time)
                
                for event in events:
                    if callback:
                        callback(event, source='cloudwatch', log_group=log_group)
                    processed_count += 1
            
            # Process CloudTrail events
            self.logger.info("Processing CloudTrail events")
            trail_events = self.fetch_cloudtrail_events(start_time, end_time)
            
            for event in trail_events:
                if callback:
                    callback(event, source='cloudtrail')
                processed_count += 1
            
            # Process GuardDuty findings
            self.logger.info("Processing GuardDuty findings")
            findings = self.fetch_guardduty_findings()
            
            for finding in findings:
                if callback:
                    callback(finding, source='guardduty')
                processed_count += 1
            
            return processed_count
            
        except Exception as e:
            self.logger.error(f"Error processing security logs: {str(e)}")
            return processed_count 