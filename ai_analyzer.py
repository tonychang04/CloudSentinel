import os
import logging
import json
import time
import requests
from datetime import datetime

class AILogAnalyzer:
    """Class for analyzing logs using AI/LLM capabilities."""
    
    def __init__(self, model_name="gpt-3.5-turbo", api_key=None):
        """
        Initialize the AI Log Analyzer.
        
        Args:
            model_name (str): Name of the LLM model to use
            api_key (str, optional): API key for the LLM service
        """
        self.model_name = model_name
        self.api_key = api_key or os.environ.get('OPENAI_API_KEY')
        self.logger = logging.getLogger(__name__)
        
        # Check if API key is available
        if not self.api_key:
            self.logger.warning("No API key provided for AI Log Analyzer. Some features will be limited.")
        
        self.logger.info(f"AI Log Analyzer initialized with model: {model_name}")
    
    def analyze_log(self, log_entry):
        """
        Analyze a single log entry using AI.
        
        Args:
            log_entry (dict): Log entry to analyze
            
        Returns:
            dict: Analysis results including risk assessment, explanation, and recommendations
        """
        if not self.api_key:
            self.logger.warning("No API key available for AI analysis. Using rule-based fallback.")
            return self._rule_based_analysis(log_entry)
        
        try:
            # Extract log message
            message = log_entry.get('message', '')
            source = log_entry.get('source', 'unknown')
            ip = log_entry.get('ip', 'unknown')
            user = log_entry.get('user', 'unknown')
            
            # Prepare prompt for the LLM
            prompt = f"""
            Analyze the following security log entry and provide:
            1. A risk assessment (high, medium, low, or info)
            2. A brief explanation of the potential security implications
            3. Recommended actions to take
            
            Log details:
            - Source: {source}
            - IP Address: {ip}
            - User: {user}
            - Message: {message}
            
            Format your response as JSON with the following structure:
            {{
                "risk_level": "high|medium|low|info",
                "explanation": "Brief explanation of the security implications",
                "recommendations": ["Recommendation 1", "Recommendation 2"],
                "indicators": ["suspicious indicator 1", "suspicious indicator 2"]
            }}
            """
            
            # Call the LLM API
            response = self._call_llm_api(prompt)
            
            # Parse the response
            try:
                analysis = json.loads(response)
                
                # Ensure the response has the expected structure
                if not all(k in analysis for k in ['risk_level', 'explanation', 'recommendations']):
                    self.logger.warning("LLM response missing required fields, using rule-based fallback")
                    return self._rule_based_analysis(log_entry)
                
                # Add timestamp to the analysis
                analysis['timestamp'] = datetime.now().isoformat()
                analysis['log_id'] = log_entry.get('id')
                
                return analysis
                
            except json.JSONDecodeError:
                self.logger.error(f"Failed to parse LLM response as JSON: {response}")
                return self._rule_based_analysis(log_entry)
                
        except Exception as e:
            self.logger.error(f"Error in AI log analysis: {str(e)}")
            return self._rule_based_analysis(log_entry)
    
    def analyze_log_batch(self, log_entries, max_batch_size=10):
        """
        Analyze a batch of log entries using AI.
        
        Args:
            log_entries (list): List of log entries to analyze
            max_batch_size (int): Maximum number of logs to analyze in one batch
            
        Returns:
            list: Analysis results for each log entry
        """
        results = []
        
        # Process logs in batches to avoid overwhelming the API
        for i in range(0, len(log_entries), max_batch_size):
            batch = log_entries[i:i+max_batch_size]
            
            # Analyze each log in the batch
            for log_entry in batch:
                analysis = self.analyze_log(log_entry)
                results.append(analysis)
            
            # Sleep briefly to avoid rate limits
            if i + max_batch_size < len(log_entries):
                time.sleep(1)
        
        return results
    
    def generate_security_report(self, logs, blocked_ips, threat_stats):
        """
        Generate a comprehensive security report using AI.
        
        Args:
            logs (list): Recent log entries
            blocked_ips (list): List of blocked IP addresses
            threat_stats (dict): Statistics about threat levels
            
        Returns:
            dict: Security report with insights and recommendations
        """
        if not self.api_key:
            self.logger.warning("No API key available for AI report generation.")
            return {
                "summary": "AI-powered report generation is not available without an API key.",
                "insights": [],
                "recommendations": []
            }
        
        try:
            # Prepare the data for the prompt
            log_summary = "\n".join([
                f"- [{log.get('timestamp', 'unknown')}] {log.get('risk_level', 'unknown').upper()}: {log.get('message', 'unknown')}"
                for log in logs[:20]  # Limit to 20 logs to avoid token limits
            ])
            
            blocked_ips_str = ", ".join(blocked_ips[:20])  # Limit to 20 IPs
            
            stats_str = ", ".join([f"{level}: {count}" for level, count in threat_stats.items()])
            
            # Prepare prompt for the LLM
            prompt = f"""
            Generate a comprehensive security report based on the following data:
            
            Recent security logs:
            {log_summary}
            
            Blocked IP addresses: {blocked_ips_str}
            
            Threat statistics: {stats_str}
            
            Please provide:
            1. A summary of the security situation
            2. Key insights from the log data
            3. Patterns or trends you've identified
            4. Specific recommendations for improving security
            
            Format your response as JSON with the following structure:
            {{
                "summary": "Overall security situation summary",
                "insights": ["Insight 1", "Insight 2", ...],
                "patterns": ["Pattern 1", "Pattern 2", ...],
                "recommendations": ["Recommendation 1", "Recommendation 2", ...]
            }}
            """
            
            # Call the LLM API
            response = self._call_llm_api(prompt)
            
            # Parse the response
            try:
                report = json.loads(response)
                
                # Ensure the response has the expected structure
                if not all(k in report for k in ['summary', 'insights', 'recommendations']):
                    self.logger.warning("LLM response missing required fields for security report")
                    return {
                        "summary": "Failed to generate a complete AI security report.",
                        "insights": [],
                        "recommendations": []
                    }
                
                # Add timestamp to the report
                report['timestamp'] = datetime.now().isoformat()
                
                return report
                
            except json.JSONDecodeError:
                self.logger.error(f"Failed to parse LLM response as JSON: {response}")
                return {
                    "summary": "Failed to generate AI security report due to parsing error.",
                    "insights": [],
                    "recommendations": []
                }
                
        except Exception as e:
            self.logger.error(f"Error in AI security report generation: {str(e)}")
            return {
                "summary": f"Error generating AI security report: {str(e)}",
                "insights": [],
                "recommendations": []
            }
    
    def _call_llm_api(self, prompt):
        """
        Call the LLM API with the given prompt.
        
        Args:
            prompt (str): Prompt to send to the LLM
            
        Returns:
            str: Response from the LLM
        """
        # This implementation uses OpenAI's API, but you can replace it with any LLM API
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            
            data = {
                "model": self.model_name,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,  # Lower temperature for more consistent results
                "max_tokens": 1000
            }
            
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"]
            else:
                self.logger.error(f"LLM API error: {response.status_code} - {response.text}")
                return ""
                
        except Exception as e:
            self.logger.error(f"Error calling LLM API: {str(e)}")
            return ""
    
    def _rule_based_analysis(self, log_entry):
        """
        Fallback rule-based analysis when AI is not available.
        
        Args:
            log_entry (dict): Log entry to analyze
            
        Returns:
            dict: Analysis results
        """
        message = log_entry.get('message', '').lower()
        risk_level = log_entry.get('risk_level', 'info')
        
        # Define some basic rules for analysis
        explanation = "Automated rule-based analysis"
        recommendations = ["Monitor for further suspicious activity"]
        indicators = []
        
        # Check for common security issues
        if any(keyword in message for keyword in ['unauthorized', 'attack', 'breach', 'exploit']):
            risk_level = 'high'
            explanation = "Potential security breach detected"
            recommendations = [
                "Investigate the source IP immediately",
                "Check affected systems for compromise",
                "Consider blocking the IP address"
            ]
            indicators = ["Security breach keywords detected"]
            
        elif any(keyword in message for keyword in ['failed login', 'multiple failed', 'brute force']):
            risk_level = 'medium'
            explanation = "Possible authentication attack"
            recommendations = [
                "Monitor login attempts from this IP",
                "Verify account security",
                "Consider implementing rate limiting"
            ]
            indicators = ["Multiple authentication failures"]
            
        elif any(keyword in message for keyword in ['warning', 'suspicious', 'unusual']):
            risk_level = 'medium'
            explanation = "Suspicious activity detected"
            recommendations = [
                "Review the activity details",
                "Check for other related events"
            ]
            indicators = ["Suspicious activity keywords detected"]
            
        elif any(keyword in message for keyword in ['error', 'failed', 'denied']):
            risk_level = 'low'
            explanation = "System error or access issue"
            recommendations = [
                "Check system logs for related errors",
                "Verify permissions are correctly configured"
            ]
            indicators = ["Error or access denial detected"]
        
        return {
            'risk_level': risk_level,
            'explanation': explanation,
            'recommendations': recommendations,
            'indicators': indicators,
            'timestamp': datetime.now().isoformat(),
            'log_id': log_entry.get('id'),
            'ai_powered': False
        } 