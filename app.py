from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import re
import os
import random
from datetime import datetime
import requests
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
cors = CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:3000"],
        "methods": ["OPTIONS", "GET", "POST"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Add CORS headers to all responses
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
    return response

# Define constant for loading time simulation
MIN_LOADING_TIME = 1  # seconds

# Load API configuration from environment variables
DEEPSEEK_API_URL = os.getenv("DEEPSEEK_API_URL", "https://api.deepseek.com/v1/chat/completions")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
OPENAI_API_URL = os.getenv("OPENAI_API_URL", "https://api.openai.com/v1/chat/completions")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# Load known vulnerabilities from a JSON file
VULNERABILITIES_FILE = "vulnerabilities.json"

def load_vulnerabilities():
    """Load the known vulnerabilities from the JSON file."""
    if os.path.exists(VULNERABILITIES_FILE):
        with open(VULNERABILITIES_FILE, 'r') as f:
            return json.load(f)
    else:
        # Create a sample vulnerabilities file if it doesn't exist
        sample_vulns = {
            "patterns": [
                {
                    "id": "SQL-INJECTION-1",
                    "regex": r"SQL syntax.*?error",
                    "description": "Potential SQL injection attempt detected"
                },
                {
                    "id": "XSS-1",
                    "regex": r"<script>.*?</script>",
                    "description": "Potential XSS attack detected"
                }
                # More patterns would be defined in the actual JSON file
            ]
        }
        with open(VULNERABILITIES_FILE, 'w') as f:
            json.dump(sample_vulns, f, indent=2)
        return sample_vulns

# Initialize vulnerabilities
VULNERABILITIES = load_vulnerabilities()

class LogAnalyzer:
    """Class to handle log file analysis."""
    
    def __init__(self, log_content: str):
        self.log_content = log_content
        self.vulnerabilities = VULNERABILITIES
    
    def basic_pattern_matching(self) -> List[Dict[str, Any]]:
        """Perform basic pattern matching against known vulnerability patterns."""
        findings = []
        lines = self.log_content.split('\n')
        
        # First, apply normal pattern matching
        for pattern in self.vulnerabilities["patterns"]:
            try:
                regex = re.compile(pattern["regex"], re.IGNORECASE)
            except Exception as regex_error:
                print(f"Error compiling regex in pattern {pattern['id']}: {str(regex_error)}")
                continue
            
            for i, line in enumerate(lines):
                match = regex.search(line)
                if match:
                    # Extract the match position for highlighting in the UI
                    match_position = {
                        "start": match.start(),
                        "end": match.end()
                    }
                    
                    findings.append({
                        "vulnerability_id": pattern["id"],
                        "description": pattern["description"],
                        "line_number": i + 1,
                        "line_content": line.strip(),
                        "confidence": "medium",  # Basic pattern matching has medium confidence
                        "match_position": match_position
                    })
        
        # Then, add contextual DDoS detection
        ddos_findings = self.detect_ddos_patterns(lines)
        findings.extend(ddos_findings)
        
        return findings
        
    def detect_ddos_patterns(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Perform advanced DDoS detection by analyzing log patterns over time."""
        findings = []
        
        # Extract timestamps and IP addresses for time-based analysis
        time_based_records = []
        ip_request_count = {}
        endpoint_request_count = {}
        timestamp_pattern = r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]'
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        endpoint_pattern = r'GET (/\S*)'
        
        for i, line in enumerate(lines):
            timestamp_match = re.search(timestamp_pattern, line)
            ip_match = re.search(ip_pattern, line)
            endpoint_match = re.search(endpoint_pattern, line)
            
            if timestamp_match and ip_match:
                timestamp = timestamp_match.group(1)
                ip = ip_match.group(1)
                endpoint = endpoint_match.group(1) if endpoint_match else "/"
                
                time_based_records.append({
                    "timestamp": timestamp,
                    "ip": ip,
                    "endpoint": endpoint,
                    "line_index": i
                })
                
                # Count requests per IP
                ip_request_count[ip] = ip_request_count.get(ip, 0) + 1
                
                # Count requests per endpoint
                endpoint_request_count[endpoint] = endpoint_request_count.get(endpoint, 0) + 1
        
        # Detect rapid requests from the same IP (potential DoS)
        for ip, count in ip_request_count.items():
            if count >= 5:  # Threshold for suspicion
                # Find the first line with this IP for reference
                first_line_index = next((r["line_index"] for r in time_based_records if r["ip"] == ip), 0)
                
                findings.append({
                    "vulnerability_id": "DDOS-SOURCE-IP-001",
                    "description": f"High request rate detected from IP {ip} ({count} requests)",
                    "line_number": first_line_index + 1,
                    "line_content": lines[first_line_index].strip(),
                    "confidence": "high" if count > 10 else "medium",
                    "match_position": {
                        "start": lines[first_line_index].find(ip),
                        "end": lines[first_line_index].find(ip) + len(ip)
                    },
                    "severity": "high" if count > 20 else "medium"
                })
        
        # Detect distributed attacks (many IPs, same endpoint)
        for endpoint, count in endpoint_request_count.items():
            if count >= 10:  # High traffic to one endpoint
                # Count unique IPs for this endpoint
                unique_ips = len(set(r["ip"] for r in time_based_records if r["endpoint"] == endpoint))
                
                if unique_ips >= 3:  # If 3+ different IPs are hitting the same endpoint
                    # Find a representative line
                    line_index = next((r["line_index"] for r in time_based_records if r["endpoint"] == endpoint), 0)
                    
                    findings.append({
                        "vulnerability_id": "DDOS-DISTRIBUTED-002",
                        "description": f"Distributed attack pattern detected: {unique_ips} different IPs requesting same endpoint ({endpoint}) {count} times",
                        "line_number": line_index + 1,
                        "line_content": lines[line_index].strip(),
                        "confidence": "high" if unique_ips > 5 else "medium",
                        "match_position": {
                            "start": lines[line_index].find(endpoint) if lines[line_index].find(endpoint) >= 0 else 0,
                            "end": lines[line_index].find(endpoint) + len(endpoint) if lines[line_index].find(endpoint) >= 0 else len(lines[line_index])
                        },
                        "severity": "high" if unique_ips > 10 else "medium"
                    })
        
        # Detect time-based patterns (many requests in a short timeframe)
        if len(time_based_records) >= 5:
            try:
                # Group requests by 5-second intervals
                time_windows = {}
                for record in time_based_records:
                    timestamp = datetime.strptime(record["timestamp"], "%Y-%m-%d %H:%M:%S")
                    # Round to 5-second windows
                    window_key = timestamp.strftime("%Y-%m-%d %H:%M") + ":" + str(5 * (timestamp.second // 5))
                    if window_key not in time_windows:
                        time_windows[window_key] = []
                    time_windows[window_key].append(record)
                
                # Check if any 5-second window has more than threshold requests
                for window, records in time_windows.items():
                    if len(records) >= 10:  # Threshold for time-based detection
                        unique_ips = len(set(r["ip"] for r in records))
                        
                        # If many requests in a short time window, likely DDoS
                        finding_description = f"Time-based attack pattern: {len(records)} requests in a 5-second window"
                        if unique_ips > 1:
                            finding_description += f" from {unique_ips} different IPs"
                        
                        line_index = records[0]["line_index"]
                        findings.append({
                            "vulnerability_id": "DDOS-TIMEWINDOW-001",
                            "description": finding_description,
                            "line_number": line_index + 1,
                            "line_content": lines[line_index].strip(),
                            "confidence": "high" if len(records) > 20 else "medium",
                            "match_position": {
                                "start": 0,
                                "end": len(lines[line_index])
                            },
                            "severity": "high" if len(records) > 30 or unique_ips > 5 else "medium"
                        })
            except Exception as e:
                # If datetime parsing fails, continue with other detection methods
                print(f"Error in time-based DDoS detection: {str(e)}")
        
        return findings

    def structure_log_content(self) -> Dict[str, Any]:
        """Structure the log content for better processing by the reasoning model."""
        structured_logs = []
        
        # Simple regex patterns for common log formats
        timestamp_pattern = r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}'
        log_level_pattern = r'\b(DEBUG|INFO|WARNING|ERROR|CRITICAL|WARN|ERR|FATAL)\b'
        
        lines = self.log_content.split('\n')
        for i, line in enumerate(lines):
            structured_entry = {
                "line_number": i + 1,
                "raw_content": line.strip()
            }
            
            # Extract timestamp if present
            timestamp_match = re.search(timestamp_pattern, line)
            if timestamp_match:
                structured_entry["timestamp"] = timestamp_match.group(0)
            
            # Extract log level if present
            log_level_match = re.search(log_level_pattern, line, re.IGNORECASE)
            if log_level_match:
                structured_entry["log_level"] = log_level_match.group(0).upper()
            
            structured_logs.append(structured_entry)
        
        return {
            "log_entries": structured_logs,
            "total_lines": len(lines),
            "analysis_timestamp": datetime.now().isoformat()
        }

class DeepSeekReasoner:
    """Class to handle interactions with the DeepSeek reasoning model."""
    
    def __init__(self):
        self.deepseek_api_url = DEEPSEEK_API_URL
        self.deepseek_api_key = DEEPSEEK_API_KEY
        self.openai_api_url = OPENAI_API_URL
        self.openai_api_key = OPENAI_API_KEY
    
    def analyze_logs(self, structured_logs: Dict[str, Any], basic_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Use the DeepSeek reasoning model to analyze the structured logs."""
        
        try:
            # Check if DeepSeek API key is valid
            if self.deepseek_api_key and len(self.deepseek_api_key) > 10:
                # Create a prompt for the DeepSeek model
                prompt = self._create_prompt(structured_logs, basic_findings)
                
                # Make the API call to DeepSeek
                response = self._call_deepseek_api(prompt)
                
                # Parse the response
                return self._parse_response(response)
            # Try OpenAI as fallback
            elif self.openai_api_key and len(self.openai_api_key) > 10:
                print("Using OpenAI API as fallback")
                # Create a prompt
                prompt = self._create_prompt(structured_logs, basic_findings)
                
                # Make the API call to OpenAI
                response = self._call_openai_api(prompt)
                
                # Parse the response
                return self._parse_response(response)
            else:
                # Use fallback mode with simulated response if no API keys are available
                print("Using fallback mode - No API keys configured")
                return self._generate_fallback_response(structured_logs, basic_findings)
            
        except Exception as e:
            # Try OpenAI if DeepSeek fails
            if "deepseek" in str(e).lower() and self.openai_api_key and len(self.openai_api_key) > 10:
                print(f"Error during DeepSeek analysis: {str(e)}")
                print("Falling back to OpenAI API")
                try:
                    prompt = self._create_prompt(structured_logs, basic_findings)
                    response = self._call_openai_api(prompt)
                    return self._parse_response(response)
                except Exception as openai_e:
                    print(f"Error during OpenAI fallback: {str(openai_e)}")
                    print("Falling back to simulated response")
                    return self._generate_fallback_response(structured_logs, basic_findings)
            else:
                print(f"Error during API analysis: {str(e)}")
                print("Falling back to simulated response")
                # Return a simulated fallback response
                return self._generate_fallback_response(structured_logs, basic_findings)
    
    def _generate_fallback_response(self, structured_logs: Dict[str, Any], basic_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a simulated response for development purposes."""
        # Create reasoning steps
        reasoning_steps = []
        confirmed_findings = []
        new_findings = []
        
        # Add raw_response field for debugging
        raw_response = """This is a simulated raw response from the model.

Here's what I found in your log files:
1. Several potential security vulnerabilities
2. Examples of suspicious activity
3. Recommendations for securing your system

{
  "reasoning": [{"id": "step-1", "type": "evaluation", "content": "Analyzing log patterns", "conclusion": "completed"}],
  "confirmed_findings": [{"vulnerability_id": "SAMPLE-1", "description": "Sample vulnerability", "line_number": 42}],
  "recommendations": [{"priority": "high", "action": "This is a sample recommendation"}]
}"""
        
        # Process each basic finding
        for i, finding in enumerate(basic_findings):
            # Simulate reasoning about this finding
            reasoning_id = f"reasoning-{i+1}"
            
            # Create more detailed evaluation based on vulnerability type
            evaluation_content = ""
            if "SQL" in finding.get('vulnerability_id', ''):
                evaluation_content = f"Evaluating finding {finding['vulnerability_id']}: {finding['description']} at line {finding['line_number']}.\n\nThis appears to be a SQL injection attempt. The pattern '{finding.get('line_content', '')}' contains SQL syntax that could be used to manipulate database queries. This is a serious security vulnerability as it could allow attackers to read, modify, or delete database content, or even execute system commands in some scenarios."
            elif "PATH" in finding.get('vulnerability_id', '') or "FILE" in finding.get('vulnerability_id', ''):
                evaluation_content = f"Evaluating finding {finding['vulnerability_id']}: {finding['description']} at line {finding['line_number']}.\n\nThis appears to be a path traversal or file inclusion attempt. The pattern '{finding.get('line_content', '')}' contains directory traversal sequences (../) which could allow attackers to access files outside the intended directory structure. This is particularly dangerous as it might expose sensitive configuration files or system information."
            elif "XSS" in finding.get('vulnerability_id', ''):
                evaluation_content = f"Evaluating finding {finding['vulnerability_id']}: {finding['description']} at line {finding['line_number']}.\n\nThis appears to be a cross-site scripting (XSS) attempt. The pattern '{finding.get('line_content', '')}' contains script tags or JavaScript code that could be executed in users' browsers. This is a serious vulnerability that could lead to session hijacking, credential theft, or malicious actions performed in the user's browser context."
            else:
                evaluation_content = f"Evaluating finding {finding['vulnerability_id']}: {finding['description']} at line {finding['line_number']}.\n\nExamined the log entry and found patterns matching known attack signatures. This type of activity should be investigated as it could indicate an attempt to exploit vulnerabilities in the system."
            
            reasoning = {
                "id": reasoning_id,
                "type": "evaluation",
                "content": evaluation_content,
                "conclusion": "confirmed" if random.random() > 0.2 else "rejected",  # Randomly confirm or reject
                "evaluation": f"The detected pattern at position {finding.get('match_position', {}).get('start', 0)} to {finding.get('match_position', {}).get('end', 0)} in the log line shows strong evidence of a security issue. Context analysis suggests this is a {random.choice(['targeted', 'opportunistic', 'automated'])} attack attempt."
            }
            reasoning_steps.append(reasoning)
            
            if reasoning["conclusion"] == "confirmed":
                confirmed_findings.append({
                    **finding,
                    "reasoning_id": reasoning_id,
                    "severity": random.choice(["high", "medium", "low"])
                })
        
        # Add some simulated "new" findings
        if structured_logs["total_lines"] > 5:
            # Fake vulnerability IDs
            vuln_types = ["PATH-TRAVERSAL", "DDOS", "CRED-EXPOSURE", "INSECURE-CONFIG"]
            
            for i in range(min(2, structured_logs["total_lines"] // 10 + 1)):
                reasoning_id = f"reasoning-{len(reasoning_steps) + 1}"
                vuln_id = f"{random.choice(vuln_types)}-{random.randint(1, 99)}"
                
                # Create a detailed discovery reasoning
                discovery_content = f"Identified a pattern consistent with {vuln_id} in the logs. Further analysis reveals potentially malicious behavior that wasn't caught by basic pattern matching. This finding requires immediate attention as it appears to be an active attempt to compromise system security."
                
                reasoning = {
                    "id": reasoning_id,
                    "type": "discovery",
                    "content": discovery_content,
                    "conclusion": "new_vulnerability",
                    "evaluation": "Based on context analysis and behavior patterns observed across multiple log entries, this appears to be part of a coordinated attack sequence rather than an isolated incident."
                }
                reasoning_steps.append(reasoning)
                
                line_number = random.randint(1, max(1, structured_logs["total_lines"] - 1))
                line_content = next((entry["raw_content"] for entry in structured_logs["log_entries"] if entry["line_number"] == line_number), "")
                
                # Generate a plausible match position
                start_pos = random.randint(0, max(0, len(line_content) - 10))
                end_pos = min(len(line_content), start_pos + random.randint(5, 10))
                
                new_findings.append({
                    "vulnerability_id": vuln_id,
                    "description": f"Potential {vuln_id.lower().replace('-', ' ')} attempt detected",
                    "line_number": line_number,
                    "line_content": line_content,
                    "confidence": random.choice(["high", "medium", "low"]),
                    "reasoning_id": reasoning_id,
                    "severity": random.choice(["high", "medium", "low"]),
                    "match_position": {
                        "start": start_pos,
                        "end": end_pos
                    }
                })
        
        # Add overall reasoning steps
        reasoning_id = f"reasoning-{len(reasoning_steps) + 1}"
        reasoning_steps.append({
            "id": reasoning_id,
            "type": "summary",
            "content": f"Analyzed {structured_logs['total_lines']} log lines, confirmed {len(confirmed_findings)} findings from basic scan and discovered {len(new_findings)} new vulnerabilities",
            "conclusion": "completed",
            "evaluation": "The combination of findings suggests a coordinated attack attempt rather than random probing. Recommended actions include blocking suspicious IPs, reviewing application security controls, and implementing additional monitoring."
        })
        
        # Generate recommendations
        recommendations = []
        if confirmed_findings or new_findings:
            sev_counts = {
                "high": len([f for f in confirmed_findings + new_findings if f.get("severity") == "high"]),
                "medium": len([f for f in confirmed_findings + new_findings if f.get("severity") == "medium"]),
                "low": len([f for f in confirmed_findings + new_findings if f.get("severity") == "low"])
            }
            
            if sev_counts["high"] > 0:
                recommendations.append({
                    "priority": "high",
                    "action": "Immediate investigation required for high severity findings"
                })
            
            if any("SQL" in f["vulnerability_id"] for f in confirmed_findings + new_findings):
                recommendations.append({
                    "priority": "high",
                    "action": "Review and strengthen input validation on all database-connected forms and APIs"
                })
            
            if any("XSS" in f["vulnerability_id"] for f in confirmed_findings + new_findings):
                recommendations.append({
                    "priority": "high",
                    "action": "Implement content security policy (CSP) and output encoding"
                })
            
            # Add DDoS-specific recommendations when detected
            if any(("DDOS" in f["vulnerability_id"] or "DOS" in f["vulnerability_id"]) for f in confirmed_findings + new_findings):
                # Check the specific type of DDoS for more targeted recommendations
                if any("DISTRIBUTED" in f["vulnerability_id"] for f in confirmed_findings + new_findings):
                    recommendations.append({
                        "priority": "high",
                        "action": "Implement a web application firewall (WAF) to filter malicious traffic from multiple sources"
                    })
                    
                if any("TIMEWINDOW" in f["vulnerability_id"] for f in confirmed_findings + new_findings):
                    recommendations.append({
                        "priority": "high",
                        "action": "Configure rate limiting at the application and infrastructure level to restrict requests per time window"
                    })
                    
                if any("SOURCE-IP" in f["vulnerability_id"] for f in confirmed_findings + new_findings):
                    recommendations.append({
                        "priority": "high",
                        "action": "Implement IP-based rate limiting and consider using CAPTCHA for suspicious IPs"
                    })
                
                # General DDoS mitigation recommendations
                recommendations.append({
                    "priority": "high",
                    "action": "Consider using a CDN or DDoS protection service like Cloudflare to absorb attack traffic"
                })
                
                recommendations.append({
                    "priority": "medium",
                    "action": "Implement automated scaling of resources to handle traffic spikes during attacks"
                })
                
                recommendations.append({
                    "priority": "medium",
                    "action": "Create an incident response plan specifically for DDoS attacks"
                })
            
            # Add some generic recommendations
            if random.random() > 0.5:
                recommendations.append({
                    "priority": "medium",
                    "action": "Implement robust logging and monitoring for suspicious activities"
                })
                
            if random.random() > 0.7:
                recommendations.append({
                    "priority": "medium",
                    "action": "Conduct a comprehensive security review of the application"
                })
        
        # Default recommendation
        if not recommendations:
            recommendations.append({
                "priority": "low",
                "action": "Continue monitoring for suspicious activities"
            })
        
        return {
            "reasoning": reasoning_steps,
            "confirmed_findings": confirmed_findings,
            "new_findings": new_findings,
            "recommendations": recommendations,
            "raw_response": raw_response,  # Add the raw response
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    def _create_prompt(self, structured_logs: Dict[str, Any], basic_findings: List[Dict[str, Any]]) -> str:
        """Create a prompt for the DeepSeek reasoning model."""
        prompt = f"""
        You are a security expert analyzing log files. Given the following log file content and basic findings, 
        please analyze for security vulnerabilities, attack patterns, and suspicious activities.
        
        Log file summary:
        - Total lines: {structured_logs["total_lines"]}
        - Analysis timestamp: {structured_logs["analysis_timestamp"]}
        
        Basic findings from pattern matching:
        {json.dumps(basic_findings, indent=2)}
        
        Selected log entries for context:
        """
        
        # Add a selection of log entries, focusing on entries with findings
        relevant_line_numbers = set(finding["line_number"] for finding in basic_findings)
        
        # Add context around the findings (5 lines before and after)
        for line_num in list(relevant_line_numbers):
            for i in range(max(1, line_num - 5), min(structured_logs["total_lines"], line_num + 6)):
                relevant_line_numbers.add(i)
        
        # Add the relevant log entries to the prompt
        for entry in structured_logs["log_entries"]:
            if entry["line_number"] in relevant_line_numbers:
                prompt += f"\nLine {entry['line_number']}: {entry['raw_content']}"
        
        # Add specific instructions for DDoS detection if relevant patterns are found
        ddos_patterns = [pattern for pattern in self.vulnerabilities["patterns"] if "DDOS" in pattern["id"] or "DOS" in pattern["id"]]
        has_ddos_findings = any("DDOS" in finding["vulnerability_id"] or "DOS" in finding["vulnerability_id"] for finding in basic_findings)
        
        # Check if the raw log content contains patterns that suggest DDoS
        ddos_content_check = False
        try:
            log_content_str = "\n".join([entry.get("raw_content", "") for entry in structured_logs.get("log_entries", [])])
            # Use try/except inside the loop to handle individual pattern errors
            ddos_content_check = False
            for pattern in ddos_patterns:
                try:
                    if re.search(pattern["regex"], log_content_str, re.IGNORECASE):
                        ddos_content_check = True
                        break
                except Exception as pattern_error:
                    print(f"Error in pattern {pattern['id']}: {str(pattern_error)}")
                    continue
        except Exception as e:
            print(f"Error checking for DDoS patterns in structured logs: {str(e)}")
        
        prompt += """
        
        Please provide a detailed analysis including:
        1. Confirmation or rejection of the basic findings with reasoning
        2. Additional vulnerabilities or security issues not captured by basic pattern matching
        3. Assessment of potential impact and severity
        4. Recommended actions
        """
        
        if has_ddos_findings or ddos_content_check:
            prompt += """
            
        CRITICAL FOCUS ON DDOS ANALYSIS:
        This log appears to contain patterns consistent with DDoS attacks. Please pay special attention to:
        - Time-based patterns (many requests in short timeframes)
        - IP distribution patterns (requests from many different IPs to same endpoints)
        - System resource indicators (CPU usage, memory exhaustion, connection drops)
        - Request rate indicators (requests per second/minute)
        
        For DDoS findings, include detailed recommendations for:
        1. Immediate mitigation steps
        2. Infrastructure-level protections
        3. Application-level defenses
        4. Monitoring and alerting improvements
            """
        
        prompt += """
        
        Return your analysis in a structured JSON format with the following fields:
        {
          "reasoning": [
            {"id": "step-1", "type": "evaluation", "content": "...", "conclusion": "..."}
          ],
          "confirmed_findings": [
            {"vulnerability_id": "...", "description": "...", "line_number": 123, "severity": "high|medium|low", "reasoning_id": "step-1"}
          ],
          "new_findings": [
            {"vulnerability_id": "...", "description": "...", "line_number": 123, "severity": "high|medium|low", "reasoning_id": "step-2"}
          ],
          "recommendations": [
            {"priority": "high|medium|low", "action": "..."}
          ]
        }
        """
        
        return prompt
    
    def _call_deepseek_api(self, prompt: str) -> Dict[str, Any]:
        """Make an API call to the DeepSeek reasoning model."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.deepseek_api_key}"
        }
        
        payload = {
            "model": "deepseek-chat",  # Updated model
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert security analyst specialized in identifying vulnerabilities from log files."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,  # Lower temperature for more deterministic responses
            "max_tokens": 4000
        }
        
        response = requests.post(self.deepseek_api_url, headers=headers, json=payload)
        response.raise_for_status()
        
        return response.json()
        
    def _call_openai_api(self, prompt: str) -> Dict[str, Any]:
        """Make an API call to the OpenAI API."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.openai_api_key}"
        }
        
        payload = {
            "model": "gpt-4",  # Adjust model as needed
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert security analyst specialized in identifying vulnerabilities from log files."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,  # Lower temperature for more deterministic responses
            "max_tokens": 4000
        }
        
        response = requests.post(self.openai_api_url, headers=headers, json=payload)
        response.raise_for_status()
        
        return response.json()
    
    def _parse_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse the response from the DeepSeek API."""
        try:
            # Extract the model's response text
            response_text = response["choices"][0]["message"]["content"]
            
            # Include the raw response text in the result
            analysis_results = {
                "raw_response": response_text,
                "reasoning": [],
                "confirmed_findings": [],
                "new_findings": [],
                "recommendations": [],
                "analysis_timestamp": datetime.now().isoformat()
            }
            
            # Try to parse JSON from the response, but don't fail if it can't parse
            try:
                # Find JSON object in the response text
                import re
                json_match = re.search(r'({[\s\S]*})', response_text)
                
                if json_match:
                    # Parse the JSON structure and combine with our result
                    parsed_json = json.loads(json_match.group(1))
                    for key, value in parsed_json.items():
                        analysis_results[key] = value
            except Exception as parse_err:
                print(f"Note: Could not parse JSON from model response: {str(parse_err)}")
                analysis_results["parse_error"] = str(parse_err)
                
            return analysis_results
                
        except Exception as e:
            print(f"Error parsing API response: {str(e)}")
            print(f"Raw response: {response}")
            
            # Return a fallback response with error info
            return {
                "error": f"Error parsing response: {str(e)}",
                "raw_response": str(response) if hasattr(response, "__str__") else "Could not stringify response",
                "reasoning": [],
                "analysis_timestamp": datetime.now().isoformat()
            }

@app.route('/analyze', methods=['POST'])
def analyze_logs():
    """Endpoint to analyze log files."""
    if not request.json or 'log_content' not in request.json:
        return jsonify({'error': 'Missing log_content in request'}), 400
    
    try:
        # Extract all fields from the request
        log_content = request.json['log_content']
        timestamp = request.json.get('timestamp', datetime.now().isoformat())
        log_format = request.json.get('format', 'raw_log')
        
        print(f"Received log analysis request: format={log_format}, timestamp={timestamp}")
        
        # Initialize the analyzer
        analyzer = LogAnalyzer(log_content)
        
        # Perform basic pattern matching
        basic_findings = analyzer.basic_pattern_matching()
        
        # Structure the log content
        structured_logs = analyzer.structure_log_content()
        
        # Initialize the DeepSeek reasoner
        reasoner = DeepSeekReasoner()
        
        # Get analysis from the DeepSeek reasoning model
        analysis_results = reasoner.analyze_logs(structured_logs, basic_findings)
        
        # Combine all results
        response = {
            "basic_findings": basic_findings,
            "deepseek_analysis": analysis_results,
            "log_summary": {
                "total_lines": structured_logs["total_lines"],
                "analysis_timestamp": structured_logs["analysis_timestamp"],
                "request_timestamp": timestamp,
                "log_format": log_format
            }
        }
        
        # Debug: Print if raw_response is in the analysis_results
        if "raw_response" in analysis_results:
            print(f"Raw response is included in results (length: {len(analysis_results['raw_response'])})")
        else:
            print("WARNING: raw_response is missing from analysis_results!")
            
        # Print the structure of the response for debugging
        print(f"Response structure: {list(response.keys())}")
        print(f"Deepseek analysis structure: {list(response['deepseek_analysis'].keys())}")
        
        return jsonify(response)
    
    except Exception as e:
        print(f"Error in /analyze endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Make sure the vulnerabilities file exists
    load_vulnerabilities()
    # Run the Flask app
    app.run(debug=True)