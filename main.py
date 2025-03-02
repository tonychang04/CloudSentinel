import os
import re
import boto3
import json
import uuid
import logging
import threading
import time
import random
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from collections import defaultdict

# Import the MockAWSClient
from mock_aws import MockAWSClient, get_demo_logs, reset_demo_logs

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)  # Enable CORS for all routes

# In-memory storage for demo purposes
analysis_history = []
blocked_ips = set()
demo_logs = []
threat_stats = {
    'high': 0,
    'medium': 0,
    'low': 0,
    'info': 0
}
recent_events = []

# Demo mode flag - set to True to use mock data instead of real AWS
DEMO_MODE = os.environ.get('DEMO_MODE', 'True').lower() == 'true'

# AWS Configuration
def get_aws_client(service):
    """Create and return a boto3 client for the specified AWS service."""
    if DEMO_MODE:
        # Return a mock client for demo mode
        return MockAWSClient(service)
    
    return boto3.client(
        service,
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
        region_name=os.environ.get('AWS_REGION', 'us-east-1')
    )

# Log Fetching Module
def fetch_cloudwatch_logs(log_group_name, start_time=None, end_time=None, filter_pattern=None):
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
    logs_client = get_aws_client('logs')
    
    # Convert datetime objects to milliseconds since epoch if provided
    kwargs = {'logGroupName': log_group_name}
    
    if start_time:
        kwargs['startTime'] = int(start_time.timestamp() * 1000)
    
    if end_time:
        kwargs['endTime'] = int(end_time.timestamp() * 1000)
    
    if filter_pattern:
        kwargs['filterPattern'] = filter_pattern
    
    response = logs_client.filter_log_events(**kwargs)
    
    events = response.get('events', [])
    
    # Handle pagination if there are more logs
    while 'nextToken' in response and not DEMO_MODE:
        kwargs['nextToken'] = response['nextToken']
        response = logs_client.filter_log_events(**kwargs)
        events.extend(response.get('events', []))
    
    return events

# Log Parsing & Threat Analysis
def parse_log_entry(log_entry):
    """
    Parse a log entry to extract relevant information.
    
    Args:
        log_entry (dict): Log entry from CloudWatch
        
    Returns:
        dict: Parsed log data with extracted fields
    """
    message = log_entry.get('message', '')
    
    # Extract timestamp (example pattern, adjust based on your log format)
    timestamp_match = re.search(r'\[(.*?)\]', message)
    timestamp = timestamp_match.group(1) if timestamp_match else None
    
    # Extract IP address (IPv4)
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
    ip_address = ip_match.group(0) if ip_match else None
    
    # Extract user if available
    user_match = re.search(r'user[:\s]+([^\s]+)', message, re.IGNORECASE)
    user = user_match.group(1) if user_match else None
    
    # If no user found, try another pattern
    if not user:
        user_match = re.search(r'for user (\w+)', message, re.IGNORECASE)
        user = user_match.group(1) if user_match else None
    
    # If still no user found, try another pattern
    if not user:
        user_match = re.search(r'by (\w+) from', message, re.IGNORECASE)
        user = user_match.group(1) if user_match else None
    
    return {
        'timestamp': timestamp,
        'ip_address': ip_address,
        'user': user,
        'message': message,
        'log_stream': log_entry.get('logStreamName'),
        'event_id': log_entry.get('eventId')
    }

def analyze_threat(parsed_log):
    """
    Analyze a parsed log entry for potential threats.
    
    Args:
        parsed_log (dict): Parsed log data
        
    Returns:
        dict: Threat analysis result
    """
    global threat_stats, recent_events
    
    message = parsed_log.get('message', '').lower()
    
    # Define threat keywords and their risk levels
    threat_patterns = {
        'high': [
            r'unauthorized', r'attack', r'exploit', r'malicious',
            r'brute\s*force', r'injection', r'xss', r'csrf',
            r'multiple failed login', r'security breach', r'alert',
            r'critical'
        ],
        'medium': [
            r'failed login', r'warning', r'suspicious', r'unusual',
            r'permission denied', r'access denied', r'warn'
        ],
        'low': [
            r'error', r'failed', r'invalid', r'timeout'
        ]
    }
    
    # Check for matches against threat patterns
    detected_threats = []
    risk_level = 'info'
    
    for level, patterns in threat_patterns.items():
        for pattern in patterns:
            if re.search(pattern, message, re.IGNORECASE):
                detected_threats.append(pattern)
                # Update risk level to the highest detected
                if level == 'high' or (level == 'medium' and risk_level != 'high'):
                    risk_level = level
                elif level == 'low' and risk_level not in ['high', 'medium']:
                    risk_level = level
    
    # Update threat statistics
    threat_stats[risk_level] += 1
    
    # Create analysis result
    result = {
        'id': str(uuid.uuid4()),
        'risk_level': risk_level,
        'detected_threats': detected_threats,
        'timestamp': datetime.now().isoformat(),
        'log_data': parsed_log
    }
    
    # Add to recent events for the dashboard
    if risk_level != 'info':
        recent_events.append({
            'id': result['id'],
            'timestamp': result['timestamp'],
            'message': parsed_log.get('message', '')[:100] + ('...' if len(parsed_log.get('message', '')) > 100 else ''),
            'ip': parsed_log.get('ip_address'),
            'risk_level': risk_level,
            'threats': ', '.join(detected_threats[:3]) + ('...' if len(detected_threats) > 3 else '')
        })
        # Keep only the 10 most recent events
        recent_events = recent_events[-10:]
    
    return result

# Automated Prevention Actions
def block_ip_in_security_group(ip_address, security_group_id, description=None):
    """
    Block an IP address by adding a deny rule to a security group.
    
    Args:
        ip_address (str): IP address to block
        security_group_id (str): ID of the security group to modify
        description (str, optional): Description for the security group rule
        
    Returns:
        dict: Result of the operation
    """
    if not ip_address:
        return {'success': False, 'message': 'No IP address provided'}
    
    ec2_client = get_aws_client('ec2')
    
    try:
        # Format IP for security group rule (CIDR notation)
        ip_cidr = f"{ip_address}/32"
        
        # Add deny rule to security group
        response = ec2_client.authorize_security_group_ingress(
            GroupId=security_group_id,
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
        
        # Add to blocked IPs list for demo
        blocked_ips.add(ip_address)
        
        # Add to recent events
        recent_events.append({
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'message': f'IP {ip_address} blocked in security group {security_group_id}',
            'ip': ip_address,
            'risk_level': 'blocked',
            'threats': 'Manual block'
        })
        
        return {
            'success': True,
            'message': f'Successfully blocked IP {ip_address}',
            'security_group_id': security_group_id,
            'aws_response': response
        }
        
    except Exception as e:
        logger.error(f"Error blocking IP: {str(e)}")
        return {
            'success': False,
            'message': f'Failed to block IP {ip_address}: {str(e)}',
            'security_group_id': security_group_id
        }

# Background monitoring thread
def background_monitor():
    """Background thread that periodically checks for new logs and analyzes them."""
    while True:
        try:
            # In a real implementation, this would fetch new logs from CloudWatch
            # For demo purposes, we'll just analyze a random subset of our demo logs
            if DEMO_MODE and demo_logs:
                # Get a random subset of logs
                import random
                sample_size = min(5, len(demo_logs))
                sample_logs = random.sample(demo_logs, sample_size)
                
                # Analyze the logs
                for log in sample_logs:
                    parsed_log = parse_log_entry(log)
                    analysis = analyze_threat(parsed_log)
                    
                    # Add to analysis history
                    analysis_history.append(analysis)
                    
                    # Auto-block high risk IPs
                    if analysis['risk_level'] == 'high' and analysis['log_data'].get('ip_address'):
                        ip = analysis['log_data']['ip_address']
                        if ip not in blocked_ips:
                            block_ip_in_security_group(ip, 'sg-demo', 'Auto-blocked high risk IP')
            
            # Sleep for a while before the next check
            time.sleep(30)
        except Exception as e:
            logger.error(f"Error in background monitor: {str(e)}")
            time.sleep(60)  # Sleep longer on error


@app.route('/api/logs', methods=['POST'])
def process_logs():
    """API endpoint to fetch and analyze logs."""
    global recent_events
    
    try:
        data = request.json or {}
        filter_pattern = data.get('filter_pattern', '')
        
        # Get logs from mock AWS client
        logs_client = get_aws_client('logs')
        response = logs_client.filter_log_events(
            logGroupName='demo-logs',
            filterPattern=filter_pattern
        )
        
        # Process the logs
        results = []
        for event in response.get('events', []):
            # Extract data from log message
            message = event.get('message', '')
            
            # Determine risk level based on message content
            risk_level = 'info'
            if 'brute force' in message.lower() or 'security breach' in message.lower() or 'malicious' in message.lower():
                risk_level = 'high'
                threat_stats['high'] += 1
            elif 'multiple failed' in message.lower() or 'suspicious' in message.lower() or 'unusual' in message.lower():
                risk_level = 'medium'
                threat_stats['medium'] += 1
            elif 'failed' in message.lower() or 'denied' in message.lower() or 'invalid' in message.lower():
                risk_level = 'low'
                threat_stats['low'] += 1
            else:
                threat_stats['info'] += 1
            
            # Extract IP address using regex
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
            ip_address = ip_match.group(0) if ip_match else None
            
            # Extract timestamp
            timestamp_match = re.search(r'\[(.*?)\]', message)
            timestamp = timestamp_match.group(1) if timestamp_match else datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Extract user
            user_match = re.search(r'user (\w+\.?\w*)', message, re.IGNORECASE)
            user = user_match.group(1) if user_match else None
            
            # Create log data object
            log_data = {
                'timestamp': timestamp,
                'ip_address': ip_address,
                'user': user,
                'message': message
            }
            
            # Create result object
            result = {
                'id': str(uuid.uuid4()),
                'risk_level': risk_level,
                'detected_threats': ['Suspicious Activity'],
                'log_data': log_data
            }
            
            results.append(result)
            
            # Add to recent events if not info level
            if risk_level != 'info' and ip_address:
                recent_events.append({
                    'id': result['id'],
                    'timestamp': timestamp,
                    'message': message,
                    'ip': ip_address,
                    'risk_level': risk_level
                })
        
        # Keep only the 10 most recent events
        recent_events = recent_events[-10:]
        
        return jsonify({
            'log_count': len(results),
            'analysis_results': results
        })
    except Exception as e:
        logger.error(f"Error in logs API: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/prevent', methods=['POST'])
def prevent_threat():
    """API endpoint to take prevention actions based on threat analysis."""
    try:
        data = request.json or {}
        ip = data.get('ip_address')
        
        if not ip:
            return jsonify({'success': False, 'message': 'No IP address provided'})
        
        # Block the IP using mock AWS client
        ec2_client = get_aws_client('ec2')
        response = ec2_client.authorize_security_group_ingress(
            GroupId='sg-demo',
            IpPermissions=[
                {
                    'IpProtocol': '-1',
                    'FromPort': -1,
                    'ToPort': -1,
                    'IpRanges': [
                        {
                            'CidrIp': f'{ip}/32',
                            'Description': data.get('description', 'Blocked by CloudSentinel')
                        }
                    ]
                }
            ]
        )
        
        # Add to recent events
        recent_events.append({
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'message': f'IP {ip} blocked',
            'ip': ip,
            'risk_level': 'blocked'
        })
        
        return jsonify({
            'success': True,
            'message': f'Successfully blocked IP {ip}'
        })
    except Exception as e:
        logger.error(f"Error in prevent API: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/analysis', methods=['GET'])
def get_analysis():
    """API endpoint to retrieve historical analysis results."""
    try:
        return jsonify({
            'analysis_count': len(analysis_history),
            'results': analysis_history[-100:]  # Return the most recent 100 results
        })
    except Exception as e:
        logger.error(f"Error in analysis API: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard', methods=['GET'])
def get_dashboard_data():
    """API endpoint to retrieve dashboard data."""
    try:
        
        # Add debug logging
        logger.info("Dashboard API called")
        
        response_data = {
            'threat_stats': threat_stats,
            'blocked_ips': list(blocked_ips),
            'recent_events': recent_events,
            'total_logs_analyzed': sum(threat_stats.values())
        }
        
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"Error in dashboard API: {str(e)}")
        return jsonify({'error': str(e), 'message': 'Failed to fetch dashboard data'}), 500

@app.route('/api/demo/reset', methods=['POST'])
def reset_demo():
    """API endpoint to reset the demo data."""
    try:
        global analysis_history, blocked_ips, threat_stats, recent_events
        
        # Reset in-memory data
        analysis_history = []
        blocked_ips = set()
        threat_stats = {
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        recent_events = []
        
        # Reset mock logs
        reset_demo_logs()
        
        return jsonify({'success': True, 'message': 'Demo data reset successfully'})
    except Exception as e:
        logger.error(f"Error in reset API: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Start the background monitoring thread when the app starts
@app.before_first_request
def start_background_tasks():
    """Start background tasks before the first request is processed."""
    if DEMO_MODE:
        thread = threading.Thread(target=background_monitor)
        thread.daemon = True
        thread.start()

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path.startswith('api/'):
        # Let the API routes handle API requests
        return jsonify({'error': 'API endpoint not found'}), 404
    elif path != "" and os.path.exists(os.path.join('build', path)):
        return send_from_directory('build', path)
    else:
        return send_from_directory('build', 'index.html')

if __name__ == '__main__':
    # Try a different port if 5000 is in use
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=True)
