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
import traceback
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(override=True)

# Import the AWS integration class
from aws_integration import AWSIntegration, MockAWSClient
from ai_analyzer import AILogAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app, resources={r"/api/*": {"origins": "*"}})  # Enable CORS for all routes

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




DEMO_MODE = False

# Initialize global variables - IMPORTANT: Define these at the module level
all_logs = []
ai_analysis_results = []

# Initialize AWS Integration
aws = AWSIntegration(
    region=os.environ.get('AWS_REGION', 'us-east-1'),
    demo_mode=DEMO_MODE
)

# Initialize the AI Log Analyzer
ai_analyzer = AILogAnalyzer(
    model_name=os.environ.get('LLM_MODEL', 'gpt-3.5-turbo'),
    api_key=os.environ.get('OPENAI_API_KEY')
)

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

def process_log_with_ai(log_event):
    """Process a log event with AI analysis."""
    global ai_analysis_results, threat_stats, blocked_ips, recent_events, all_logs
    
    try:
        # Perform AI analysis
        analysis = ai_analyzer.analyze_log(log_event)
        
        # Add the analysis to the log event
        log_event['ai_analysis'] = analysis
        
        # Store the analysis result
        ai_analysis_results.append({
            'log_id': log_event['id'],
            'timestamp': datetime.now().isoformat(),
            'log_message': log_event['message'],
            'analysis': analysis
        })
        
        # Keep only the most recent 100 analysis results
        if len(ai_analysis_results) > 100:
            ai_analysis_results = ai_analysis_results[-100:]
        
        # If AI suggests a different risk level, update it
        if analysis.get('risk_level') != log_event['risk_level']:
            logger.info(f"AI adjusted risk level from {log_event['risk_level']} to {analysis['risk_level']} for log: {log_event['message']}")
            
            # Update the risk level
            old_risk_level = log_event['risk_level']
            log_event['risk_level'] = analysis['risk_level']
            
            # Update threat stats
            threat_stats[old_risk_level] -= 1
            threat_stats[analysis['risk_level']] += 1
            
            # If AI upgraded to high risk, consider blocking the IP
            if analysis['risk_level'] == 'high' and log_event.get('ip') and log_event['ip'] not in blocked_ips:
                logger.info(f"AI suggested blocking IP {log_event['ip']} due to high risk")
                
                # Block the IP
                result = aws.block_ip_in_security_group(
                    log_event['ip'], 
                    description=f"Blocked by AI analysis: {analysis['explanation']}"
                )
                
                if result.get('success'):
                    blocked_ips.add(log_event['ip'])
                    
                    # Add blocking event
                    block_event = {
                        'id': str(uuid.uuid4()),
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'message': f"IP {log_event['ip']} automatically blocked based on AI analysis: {analysis['explanation']}",
                        'ip': log_event['ip'],
                        'user': log_event.get('user'),
                        'risk_level': 'blocked',
                        'source': log_event.get('source')
                    }
                    recent_events.append(block_event)
                    all_logs.append(block_event)
        
        return log_event
    except Exception as e:
        logger.error(f"Error in AI log processing: {str(e)}")
        traceback.print_exc()
        return log_event  # Return the original log event if AI processing fails

# Background thread for generating new logs in demo mode
def background_log_generator():
    """Background thread that periodically generates CloudTrail-style logs."""
    global recent_events, threat_stats, all_logs, blocked_ips
    
    logger.info("Starting background CloudTrail log generator thread")
    
    while True:
        try:
            # Sleep for a random interval (5-15 seconds)
            sleep_time = random.randint(5, 15)
            time.sleep(sleep_time)
            
            # Use the AWS integration to generate mock CloudTrail events
            events = aws._generate_mock_cloudtrail_events(count=random.randint(1, 3))
            
            for event in events:
                # Update threat stats
                risk_level = event['risk_level']
                threat_stats[risk_level] = threat_stats.get(risk_level, 0) + 1
                
                # Process with AI (if enabled)
                try:
                    event = process_log_with_ai(event)
                except Exception as e:
                    logger.error(f"Error processing log with AI: {str(e)}")
                
                # Add to all_logs
                all_logs.append(event)
                
                # Add to recent_events (except info logs)
                if event['risk_level'] != 'info':
                    recent_events.append(event)
                    
                    # Keep only the most recent 20 events
                    if len(recent_events) > 20:
                        recent_events = recent_events[-20:]
                
                # Log the current state
                logger.info(f"Generated new {event['risk_level']} risk CloudTrail event: {event['message']}")
            
            logger.info(f"Current stats - all_logs: {len(all_logs)}, recent_events: {len(recent_events)}")
            logger.info(f"Threat stats: {threat_stats}")
            
            # Keep all_logs from growing too large
            if len(all_logs) > 1000:
                all_logs = all_logs[-1000:]
                
        except Exception as e:
            logger.error(f"Error in background CloudTrail log generator: {str(e)}")
            traceback.print_exc()
            time.sleep(30)  # Sleep longer on error

# Background thread for monitoring AWS logs in real mode
def background_monitor():
    """Background thread that periodically checks AWS logs."""
    global recent_events, threat_stats, all_logs, blocked_ips
    
    logger.info("Starting AWS monitoring thread")
    
    while True:
        try:
            logger.info("Checking AWS CloudTrail events...")
            
            # Process security logs from AWS
            def log_callback(event, source=None, log_group=None):
                """Callback function for processing AWS logs."""
                try:
                    # The event is already processed by the AWS integration
                    log_event = event
                    
                    # Process with AI if needed
                    if 'ai_analysis' not in log_event:
                        log_event = process_log_with_ai(log_event)
                    
                    # Add to all_logs
                    all_logs.append(log_event)
                    
                    # Update threat stats
                    risk_level = log_event.get('risk_level', 'info')
                    threat_stats[risk_level] = threat_stats.get(risk_level, 0) + 1
                    
                    # Add to recent_events if not info level
                    if risk_level != 'info':
                        recent_events.append(log_event)
                        
                        # Keep only the most recent 20 events
                        if len(recent_events) > 20:
                            recent_events = recent_events[-20:]
                    
                except Exception as e:
                    logger.error(f"Error in log callback: {str(e)}")
            
            # Process logs from AWS
            processed_count = aws.process_security_logs(callback=log_callback)
            
            logger.info(f"Processed {processed_count} AWS CloudTrail events")
            
            # Keep all_logs from growing too large
            if len(all_logs) > 1000:
                all_logs = all_logs[-1000:]
            
            # Sleep for 5 minutes before checking again
            time.sleep(300)
            
        except Exception as e:
            logger.error(f"Error in AWS monitoring: {str(e)}")
            traceback.print_exc()
            time.sleep(60)  # Sleep for 1 minute on error

# API Routes
@app.route('/')
def index():
    """Serve the main application page."""
    return render_template('index.html')

@app.route('/static/<path:path>')
def serve_static(path):
    """Serve static files."""
    return send_from_directory('static', path)

@app.route('/api/dashboard', methods=['GET'])
def get_dashboard_data():
    """API endpoint to retrieve dashboard data."""
    global all_logs, recent_events, threat_stats, blocked_ips
    
    try:
        # Add debug logging
        logger.info("Dashboard API called")
        logger.info(f"Current stats - all_logs: {len(all_logs)}, recent_events: {len(recent_events)}")
        logger.info(f"Threat stats: {threat_stats}")
        logger.info(f"Blocked IPs: {blocked_ips}")
        
        response_data = {
            'threat_stats': threat_stats,
            'blocked_ips': list(blocked_ips),
            'recent_events': recent_events,
            'total_logs_analyzed': sum(threat_stats.values())
        }
        
        logger.info(f"Dashboard response: {json.dumps(response_data)[:200]}...")  # Log first 200 chars
        
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"Error in dashboard API: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e), 'message': 'Failed to fetch dashboard data'}), 500

@app.route('/api/logs', methods=['POST'])
def process_logs():
    """API endpoint to fetch and analyze logs."""
    global analysis_history, all_logs
    
    try:
        data = request.json or {}
        filter_pattern = data.get('filter_pattern', '').lower()
        include_ai_analysis = data.get('include_ai_analysis', False)
        page = int(data.get('page', 1))
        page_size = int(data.get('page_size', 20))
        
        logger.info(f"Log analysis API called with filter: '{filter_pattern}', include_ai_analysis: {include_ai_analysis}, page: {page}, page_size: {page_size}")
        
        # Calculate start and end indices for pagination
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        
        # Filter logs based on filter_pattern
        filtered_logs = []
        for event in all_logs:
            message = event.get('message', '')
            if not filter_pattern or filter_pattern in message.lower():
                filtered_logs.append(event)
        
        # Get total count of filtered logs
        total_filtered = len(filtered_logs)
        
        # Apply pagination
        paginated_logs = filtered_logs[start_idx:end_idx]
        
        # Process paginated logs
        analysis_results = []
        for event in paginated_logs:
            try:
                # Extract data from the event
                timestamp = event.get('timestamp')
                message = event.get('message', '')
                ip_address = event.get('ip')
                risk_level = event.get('risk_level')
                user = event.get('user')
                
                # Create analysis result
                analysis_result = {
                    'id': event.get('id', str(uuid.uuid4())),
                    'log_data': {
                        'timestamp': timestamp,
                        'ip_address': ip_address,
                        'user': user,
                        'message': message
                    },
                    'risk_level': risk_level
                }
                
                # Include AI analysis if requested
                if include_ai_analysis:
                    # Check if the event already has AI analysis
                    if 'ai_analysis' in event:
                        analysis_result['ai_analysis'] = event['ai_analysis']
                    else:
                        # Perform AI analysis on-demand
                        analysis_result['ai_analysis'] = ai_analyzer.analyze_log(event)
                
                analysis_results.append(analysis_result)
                
                # Add to analysis history
                if analysis_result not in analysis_history:
                    analysis_history.append(analysis_result)
                    # Keep analysis history from growing too large
                    if len(analysis_history) > 100:
                        analysis_history = analysis_history[-100:]
                
            except Exception as e:
                logger.error(f"Error processing event: {str(e)}, Event: {event}")
                continue
        
        logger.info(f"Log analysis complete. Found {len(analysis_results)} results from page {page} (total filtered: {total_filtered}).")
        
        # Make sure we're returning the correct data structure
        response_data = {
            'success': True,
            'analysis_results': analysis_results,
            'total_logs': len(all_logs),
            'total_filtered': total_filtered,
            'page': page,
            'page_size': page_size,
            'total_pages': (total_filtered + page_size - 1) // page_size,
            'filter_pattern': filter_pattern
        }
        
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"Error in logs API: {str(e)}", exc_info=True)
        traceback.print_exc()
        return jsonify({
            'error': str(e), 
            'message': 'Failed to fetch logs', 
            'success': False
        }), 500

@app.route('/api/prevent', methods=['POST'])
def prevent_threat():
    """API endpoint to take preventive action against a threat."""
    global blocked_ips, recent_events, all_logs
    
    try:
        # Log the raw request data
        logger.info(f"Prevention API called with data: {request.get_data(as_text=True)}")
        logger.info(f"Request content type: {request.content_type}")
        logger.info(f"Request JSON: {request.json if request.is_json else 'Not JSON'}")
        
        # Check if the request is JSON
        if not request.is_json:
            logger.error("Request is not JSON")
            return jsonify({
                'success': False,
                'message': 'Request must be JSON'
            }), 400
        
        data = request.json or {}
        action = data.get('action')
        ip_address = data.get('ip_address')
        reason = data.get('reason', 'Manual prevention action')
        
        logger.info(f"Parsed data - action: {action}, IP: {ip_address}, reason: {reason}")
        
        if not action:
            logger.error("No action specified")
            return jsonify({
                'success': False,
                'message': 'No action specified'
            }), 400
        
        if action == 'block_ip':
            if not ip_address:
                return jsonify({
                    'success': False,
                    'message': 'No IP address provided'
                }), 400
            
            # Check if IP is already blocked
            if ip_address in blocked_ips:
                return jsonify({
                    'success': True,
                    'message': f'IP {ip_address} is already blocked'
                })
            
            # Block the IP using AWS integration
            result = aws.block_ip_in_security_group(
                ip_address,
                description=f"Manually blocked: {reason}"
            )
            
            if result.get('success'):
                # Add to blocked IPs set
                blocked_ips.add(ip_address)
                
                # Create a log entry for the block
                block_event = {
                    'id': str(uuid.uuid4()),
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': f"IP {ip_address} manually blocked: {reason}",
                    'ip': ip_address,
                    'risk_level': 'blocked',
                    'source': 'manual',
                    'user': data.get('user', 'admin')
                }
                
                # Add to recent events and all logs
                recent_events.append(block_event)
                all_logs.append(block_event)
                
                # Keep recent_events from growing too large
                if len(recent_events) > 20:
                    recent_events = recent_events[-20:]
                
                return jsonify({
                    'success': True,
                    'message': f'Successfully blocked IP {ip_address}',
                    'details': result
                })
            else:
                return jsonify({
                    'success': False,
                    'message': f'Failed to block IP {ip_address}',
                    'details': result
                }), 500
        
        elif action == 'unblock_ip':
            if not ip_address:
                return jsonify({
                    'success': False,
                    'message': 'No IP address provided'
                }), 400
            
            # Check if IP is blocked
            if ip_address not in blocked_ips:
                return jsonify({
                    'success': True,
                    'message': f'IP {ip_address} is not blocked'
                })
            
            # In demo mode, just remove from the set
            if DEMO_MODE:
                blocked_ips.remove(ip_address)
                
                # Create a log entry for the unblock
                unblock_event = {
                    'id': str(uuid.uuid4()),
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': f"IP {ip_address} manually unblocked: {reason}",
                    'ip': ip_address,
                    'risk_level': 'info',
                    'source': 'manual',
                    'user': data.get('user', 'admin')
                }
                
                # Add to recent events and all logs
                recent_events.append(unblock_event)
                all_logs.append(unblock_event)
                
                return jsonify({
                    'success': True,
                    'message': f'Successfully unblocked IP {ip_address} (demo mode)'
                })
            else:
                # For real AWS, we would need to remove the security group rule
                # This is a simplified version - in a real implementation, you would
                # need to find and remove the specific rule for this IP
                return jsonify({
                    'success': False,
                    'message': 'Unblocking IPs in AWS mode is not implemented yet'
                }), 501
        
        else:
            return jsonify({
                'success': False,
                'message': f'Unknown action: {action}'
            }), 400
            
    except Exception as e:
        logger.error(f"Error in prevention API: {str(e)}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to execute prevention action'
        }), 500

@app.route('/api/ai/analyze', methods=['POST'])
def analyze_log_with_ai():
    """API endpoint to analyze a log with AI."""
    try:
        data = request.json
        log_id = data.get('log_id')
        log_message = data.get('message')
        
        if not log_id and not log_message:
            return jsonify({
                'success': False,
                'message': 'Either log_id or message must be provided'
            }), 400
        
        # Find the log entry if log_id is provided
        log_entry = None
        if log_id:
            for log in all_logs:
                if log.get('id') == log_id:
                    log_entry = log
                    break
            
            if not log_entry:
                return jsonify({
                    'success': False,
                    'message': f'Log entry with ID {log_id} not found'
                }), 404
        else:
            # Create a temporary log entry from the message
            log_entry = {
                'id': str(uuid.uuid4()),
                'message': log_message,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'source': 'manual',
                'risk_level': 'unknown'
            }
        
        # Perform AI analysis
        analysis = ai_analyzer.analyze_log(log_entry)
        
        return jsonify({
            'success': True,
            'log': log_entry,
            'analysis': analysis
        })
    except Exception as e:
        logger.error(f"Error in AI log analysis: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to analyze log with AI'
        }), 500

@app.route('/api/ai/report', methods=['GET'])
def get_ai_security_report():
    """API endpoint to get an AI-generated security report."""
    try:
        # Generate a security report using AI
        report = ai_analyzer.generate_security_report(
            logs=all_logs[-50:],  # Use the most recent 50 logs
            blocked_ips=list(blocked_ips),
            threat_stats=threat_stats
        )
        
        return jsonify({
            'success': True,
            'report': report
        })
    except Exception as e:
        logger.error(f"Error generating AI security report: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to generate AI security report'
        }), 500

@app.route('/api/ai/analysis', methods=['GET'])
def get_ai_analysis():
    """API endpoint to get AI analysis results."""
    try:
        return jsonify({
            'success': True,
            'analysis_results': ai_analysis_results,
            'total_analyses': len(ai_analysis_results)
        })
    except Exception as e:
        logger.error(f"Error in AI analysis API: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to fetch AI analysis results'
        }), 500


@app.route('/api/debug', methods=['GET'])
def debug_info():
    """API endpoint to get debug information."""
    global all_logs, recent_events, threat_stats, blocked_ips, ai_analysis_results
    
    return jsonify({
        'all_logs_count': len(all_logs),
        'recent_events_count': len(recent_events),
        'threat_stats': threat_stats,
        'blocked_ips_count': len(blocked_ips),
        'ai_analysis_count': len(ai_analysis_results),
        'demo_mode': DEMO_MODE,
        'sample_recent_event': recent_events[0] if recent_events else None,
        'sample_log': all_logs[0] if all_logs else None
    })

def analyze_log_without_ai(log_event):
    """
    Analyze a log event without using AI.
    
    This function uses rule-based analysis to determine the risk level and
    provide insights about the log event.
    
    Args:
        log_event (dict): The log event to analyze
        
    Returns:
        dict: The log event with analysis added
    """
    # Make a copy of the log event to avoid modifying the original
    event = log_event.copy()
    
    # If the event already has a risk level from CloudTrail processing, use it
    if 'risk_level' in event and event['risk_level'] != 'info':
        risk_level = event['risk_level']
    else:
        risk_level = 'info'  # Default risk level
    
    # Initialize analysis
    analysis = []
    
    # Check if this is a CloudTrail event
    if event.get('source') == 'cloudtrail':
        event_name = event.get('event_name', '')
        event_source = event.get('event_source', '')
        username = event.get('username', '')
        ip = event.get('ip', '')
        user_agent = event.get('user_agent', '')
        raw_event = event.get('raw_event', {})
        
        # High-risk events
        high_risk_events = {
            'ConsoleLogin': 'Console login attempts, especially failures, may indicate unauthorized access attempts',
            'DeleteTrail': 'Deleting CloudTrail trails is a common technique to cover tracks during an attack',
            'StopLogging': 'Stopping CloudTrail logging is a common technique to avoid detection',
            'CreateUser': 'Creating new IAM users, especially with admin privileges, could indicate account takeover',
            'AttachUserPolicy': 'Attaching admin policies to users is a privilege escalation technique',
            'PutBucketPolicy': 'Modifying bucket policies to allow public access is a common data exfiltration technique',
            'ModifyVpcEndpoint': 'Modifying VPC endpoints can be used to bypass security controls'
        }
        
        # Medium-risk events
        medium_risk_events = {
            'RunInstances': 'Launching unusual or high-powered instances could indicate cryptomining or resource theft',
            'CreateSecurityGroup': 'Creating new security groups could be preparation for network attacks',
            'AuthorizeSecurityGroupIngress': 'Opening security groups to all traffic is a security risk',
            'CreateBucket': 'Creating buckets in non-standard regions could indicate data exfiltration',
            'CreateAccessKey': 'Creating new access keys could indicate credential harvesting'
        }
        
        # Check for specific high-risk patterns
        if event_name in high_risk_events:
            risk_level = 'high'
            analysis.append(high_risk_events[event_name])
            
            # Add more specific analysis based on event details
            if event_name == 'ConsoleLogin':
                if 'errorCode' in raw_event and raw_event['errorCode'] == 'AccessDenied':
                    analysis.append('Failed login attempts may indicate brute force attacks')
                if 'additionalEventData' in raw_event and raw_event['additionalEventData'].get('MFAUsed') == 'No':
                    analysis.append('Login without MFA is a security concern, especially for privileged accounts')
            
            elif event_name == 'CreateUser' and 'backdoor' in event.get('message', '').lower():
                analysis.append('User name suggests malicious intent - possible backdoor account creation')
            
            elif event_name == 'AttachUserPolicy' and 'AdministratorAccess' in event.get('message', ''):
                analysis.append('Attaching AdministratorAccess policy grants full control of the AWS account')
            
            elif event_name == 'PutBucketPolicy' and '"Principal":"*"' in str(raw_event):
                analysis.append('Policy allows access from any principal (public access), which is a major security risk')
        
        # Check for specific medium-risk patterns
        elif event_name in medium_risk_events:
            risk_level = 'medium'
            analysis.append(medium_risk_events[event_name])
            
            # Add more specific analysis based on event details
            if event_name == 'RunInstances':
                if 'p3.' in event.get('message', '') or 'g4.' in event.get('message', ''):
                    analysis.append('High-performance GPU instances could indicate unauthorized cryptomining')
                if 'requestParameters' in raw_event and raw_event['requestParameters'].get('maxCount', 1) > 2:
                    analysis.append(f"Launching multiple instances ({raw_event['requestParameters'].get('maxCount')}) simultaneously is unusual")
            
            elif event_name == 'AuthorizeSecurityGroupIngress':
                if '0.0.0.0/0' in str(raw_event):
                    analysis.append('Rule allows access from any IP address (0.0.0.0/0), which is a security risk')
                if '-1' in str(raw_event) or 'all' in str(raw_event).lower():
                    analysis.append('Rule allows all protocols, which is overly permissive')
        
        # Check for suspicious IP addresses
        if ip.startswith(('185.', '45.')):
            if risk_level == 'info':
                risk_level = 'low'
            analysis.append(f'IP address {ip} is from a range known to host malicious activities')
        
        # Check for suspicious user agents
        suspicious_agents = ['curl', 'wget', 'python-requests', 'Go-http-client']
        if any(agent in user_agent for agent in suspicious_agents):
            if risk_level == 'info':
                risk_level = 'low'
            analysis.append(f'Unusual user agent "{user_agent}" suggests programmatic access')
        
        # Check for root account usage
        if username == 'root':
            if risk_level != 'high':
                risk_level = 'medium'
            analysis.append('Root account usage is against AWS best practices and should be investigated')
        
        # Check for unusual regions
        unusual_regions = ['ap-east-1', 'me-south-1', 'af-south-1', 'eu-south-1']
        if 'region' in event and event['region'] in unusual_regions:
            if risk_level == 'info':
                risk_level = 'low'
            analysis.append(f'Activity in unusual region {event["region"]} could indicate an attempt to evade detection')
    
    # For non-CloudTrail events, use basic pattern matching
    else:
        message = event.get('message', '').lower()
        
        # Check for high-risk patterns
        high_risk_patterns = [
            'brute force', 'unauthorized', 'malicious', 'breach', 'attack',
            'compromise', 'exploit', 'backdoor', 'ransomware', 'crypto'
        ]
        
        # Check for medium-risk patterns
        medium_risk_patterns = [
            'failed login', 'multiple failed', 'unusual', 'suspicious',
            'unexpected', 'denied', 'permission denied', 'invalid password'
        ]
        
        # Check for low-risk patterns
        low_risk_patterns = [
            'failed', 'error', 'warning', 'not found', 'invalid'
        ]
        
        # Check message against patterns
        if any(pattern in message for pattern in high_risk_patterns):
            risk_level = 'high'
            matching_patterns = [p for p in high_risk_patterns if p in message]
            analysis.append(f'Message contains high-risk terms: {", ".join(matching_patterns)}')
        
        elif any(pattern in message for pattern in medium_risk_patterns):
            risk_level = 'medium'
            matching_patterns = [p for p in medium_risk_patterns if p in message]
            analysis.append(f'Message contains medium-risk terms: {", ".join(matching_patterns)}')
        
        elif any(pattern in message for pattern in low_risk_patterns):
            risk_level = 'low'
            matching_patterns = [p for p in low_risk_patterns if p in message]
            analysis.append(f'Message contains low-risk terms: {", ".join(matching_patterns)}')
    
    # Add IP-based analysis for any event type
    if 'ip' in event:
        ip = event['ip']
        
        # Check for internal IPs
        if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', 
                          '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                          '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', 
                          '172.31.', '192.168.')):
            analysis.append(f'IP {ip} is from an internal network range')
        else:
            analysis.append(f'IP {ip} is from an external network')
    
    # Update the event with analysis results
    event['risk_level'] = risk_level
    event['analysis'] = analysis
    event['ai_analysis'] = False  # Mark as non-AI analysis
    
    return event

if __name__ == '__main__':
    logger.info("Starting CloudSentinel application")
    
    # Start the background thread
    if DEMO_MODE:
        logger.info("Starting demo mode with simulated logs")
        try:
            demo_thread = threading.Thread(target=background_log_generator)
            demo_thread.daemon = True
            demo_thread.start()
            logger.info("Background log generator thread started successfully")
        except Exception as e:
            logger.error(f"Failed to start background log generator thread: {str(e)}")
            traceback.print_exc()
    else:
        logger.info("Starting AWS monitoring mode")
        try:
            monitor_thread = threading.Thread(target=background_monitor)
            monitor_thread.daemon = True
            monitor_thread.start()
            logger.info("AWS monitoring thread started successfully")
        except Exception as e:
            logger.error(f"Failed to start AWS monitoring thread: {str(e)}")
            traceback.print_exc()
    
    # Start the Flask app
    port = int(os.environ.get('PORT', 8000))  # Changed to 8000 to match React proxy
    logger.info(f"Starting Flask app on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)  # Set debug=False to avoid duplicate threads
