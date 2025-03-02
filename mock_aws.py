import uuid
import logging
import random
from datetime import datetime, timedelta

# Configure logging
logger = logging.getLogger(__name__)

# Global variable for demo logs
demo_logs = []

class MockAWSClient:
    def __init__(self, service_name):
        self.service_name = service_name
        logger.info(f"Created mock AWS client for {service_name}")
        
    def filter_log_events(self, **kwargs):
        """Mock implementation of CloudWatch Logs filter_log_events."""
        global demo_logs
        
        # Generate mock logs if none exist
        if not demo_logs:
            self._generate_mock_logs()
            
        # Return a subset of logs based on the filter
        filter_pattern = kwargs.get('filterPattern', '').lower()
        filtered_logs = []
        
        for log in demo_logs:
            if not filter_pattern or filter_pattern in log['message'].lower():
                filtered_logs.append(log)
                
        logger.info(f"Mock filter_log_events returned {len(filtered_logs)} logs")
        return {'events': filtered_logs}
    
    def authorize_security_group_ingress(self, **kwargs):
        """Mock implementation of EC2 authorize_security_group_ingress."""
        from main import blocked_ips  # Import here to avoid circular imports
        
        # Extract the IP from the request
        ip_ranges = kwargs.get('IpPermissions', [{}])[0].get('IpRanges', [{}])
        if ip_ranges:
            cidr = ip_ranges[0].get('CidrIp', '')
            ip = cidr.split('/')[0]
            blocked_ips.add(ip)
            logger.info(f"Mock authorize_security_group_ingress blocked IP: {ip}")
            
        return {
            'Return': True,
            'SecurityGroupRules': [
                {
                    'SecurityGroupRuleId': f'sgr-{uuid.uuid4().hex[:8]}',
                    'GroupId': kwargs.get('GroupId', 'sg-demo'),
                    'IpProtocol': '-1',
                    'FromPort': -1,
                    'ToPort': -1,
                    'CidrIpv4': ip_ranges[0].get('CidrIp') if ip_ranges else '0.0.0.0/0'
                }
            ]
        }
    
    def _generate_mock_logs(self):
        """Generate mock CloudWatch logs for demo purposes."""
        global demo_logs
        
        # Define some sample users, IPs, and files
        users = ['admin', 'john.doe', 'jane.smith', 'system', 'root']
        ips = [f'192.168.1.{i}' for i in range(1, 20)] + [f'10.0.0.{i}' for i in range(1, 10)]
        malicious_ips = ['45.33.12.10', '58.97.60.32', '118.25.6.39', '202.112.51.44', '91.240.118.6']
        files = ['/etc/passwd', '/var/log/auth.log', '/home/user/data.db', '/opt/app/config.json', '/tmp/cache.tmp']
        
        # Define log templates with placeholders
        log_templates = [
            # Normal logs (info)
            "[{timestamp}] User {user} logged in successfully from {ip}",
            "[{timestamp}] File {file} accessed by {user} from {ip}",
            "[{timestamp}] System update completed successfully by {user}",
            "[{timestamp}] Configuration change by {user} from {ip}",
            "[{timestamp}] Database backup completed successfully",
            
            # Low risk logs
            "[{timestamp}] Failed login attempt for user {user} from {ip}",
            "[{timestamp}] Permission denied for {user} from {ip}",
            "[{timestamp}] Invalid password for {user} from {ip}",
            "[{timestamp}] File not found error reported by {user}",
            
            # Medium risk logs
            "[{timestamp}] Multiple failed login attempts for user {user} from {ip}",
            "[{timestamp}] Unusual file access pattern detected from {ip}",
            "[{timestamp}] Suspicious command execution by {user} from {ip}",
            "[{timestamp}] Unexpected system configuration change from {ip}",
            
            # High risk logs
            "[{timestamp}] Possible brute force attack detected from {ip}",
            "[{timestamp}] Unauthorized access to sensitive file {file} from {ip}",
            "[{timestamp}] Malicious script execution detected from {ip}",
            "[{timestamp}] Data exfiltration attempt detected from {ip}",
            "[{timestamp}] Security breach detected for user {user} from {ip}"
        ]
        
        # Generate logs
        now = datetime.now()
        logs = []
        
        # Generate normal logs (60%)
        for i in range(60):
            timestamp = now - timedelta(minutes=i*5)
            template = log_templates[i % 5]  # Use templates 0-4 (normal)
            ip = ips[i % len(ips)]
            user = users[i % len(users)]
            file = files[i % len(files)]
            
            message = template.format(
                timestamp=timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                user=user,
                ip=ip,
                file=file
            )
            
            logs.append({
                'eventId': f'event-{uuid.uuid4().hex}',
                'timestamp': int(timestamp.timestamp() * 1000),
                'message': message,
                'logStreamName': f'stream-{i % 3 + 1}'
            })
        
        # Generate low risk logs (20%)
        for i in range(20):
            timestamp = now - timedelta(minutes=i*15)
            template = log_templates[5 + (i % 4)]  # Use templates 5-8 (low risk)
            ip = ips[i % len(ips)]
            user = users[i % len(users)]
            
            message = template.format(
                timestamp=timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                user=user,
                ip=ip
            )
            
            logs.append({
                'eventId': f'event-{uuid.uuid4().hex}',
                'timestamp': int(timestamp.timestamp() * 1000),
                'message': message,
                'logStreamName': f'stream-{i % 3 + 1}'
            })
        
        # Generate medium risk logs (15%)
        for i in range(15):
            timestamp = now - timedelta(minutes=i*20)
            template = log_templates[9 + (i % 4)]  # Use templates 9-12 (medium risk)
            ip = ips[i % len(ips)]
            user = users[i % len(users)]
            
            message = template.format(
                timestamp=timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                user=user,
                ip=ip
            )
            
            logs.append({
                'eventId': f'event-{uuid.uuid4().hex}',
                'timestamp': int(timestamp.timestamp() * 1000),
                'message': message,
                'logStreamName': f'stream-{i % 3 + 1}'
            })
        
        # Generate high risk logs (5%)
        for i in range(5):
            timestamp = now - timedelta(minutes=i*30)
            template = log_templates[13 + (i % 5)]  # Use templates 13-17 (high risk)
            ip = malicious_ips[i % len(malicious_ips)]
            user = users[i % len(users)]
            
            message = template.format(
                timestamp=timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                user=user,
                ip=ip
            )
            
            logs.append({
                'eventId': f'event-{uuid.uuid4().hex}',
                'timestamp': int(timestamp.timestamp() * 1000),
                'message': message,
                'logStreamName': f'stream-{i % 3 + 1}'
            })
        
        # Sort logs by timestamp (newest first)
        logs.sort(key=lambda x: x['timestamp'], reverse=True)
        demo_logs = logs
        logger.info(f"Generated {len(demo_logs)} mock logs")

# Function to get demo logs (for external access)
def get_demo_logs():
    global demo_logs
    return demo_logs

# Function to reset demo logs
def reset_demo_logs():
    global demo_logs
    demo_logs = [] 