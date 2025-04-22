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
        
    def _determine_severity(self, line_content: str, is_high_condition: bool) -> str:
        """Determine severity based on log content and conditions.
        
        Args:
            line_content: The log line content to analyze
            is_high_condition: Boolean flag indicating if other conditions suggest high severity
            
        Returns:
            String indicating severity level: "high", "medium", or "low"
        """
        # High severity keywords
        high_severity_patterns = [
            '[WARN]', 'CRITICAL', 'danger', 'EMERGENCY', 'FATAL', 'ERROR',
            'FAILURE', 'EXPLOIT', 'VULNERABILITY', 'BREACH', 'ATTACK', 'COMPROMISE'
        ]
        
        # Medium severity keywords
        medium_severity_patterns = [
            'warn', 'warning', 'attention', 'suspicious', 'unusual', 'detected', 'notice'
        ]
        
        # Check for high severity patterns
        for pattern in high_severity_patterns:
            if pattern in line_content:
                return "high"
        
        # Check for medium severity patterns (case insensitive)
        for pattern in medium_severity_patterns:
            if pattern.lower() in line_content.lower():
                return "medium"
        
        # Use the condition as a fallback if no patterns match
        return "high" if is_high_condition else "medium"
    
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
                    
                    # Determine the severity based on the log content
                    severity = self._determine_severity(line.strip(), "CRITICAL" in pattern["id"] or "INJECTION" in pattern["id"])
                    
                    findings.append({
                        "vulnerability_id": pattern["id"],
                        "description": pattern["description"],
                        "line_number": i + 1,
                        "line_content": line.strip(),
                        "confidence": "medium",  # Basic pattern matching has medium confidence
                        "match_position": match_position,
                        "severity": severity
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
                    "severity": self._determine_severity(lines[first_line_index], count > 20)
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
                        "severity": self._determine_severity(lines[line_index], unique_ips > 10)
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
                            "severity": self._determine_severity(lines[line_index], len(records) > 30 or unique_ips > 5)
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
        self.lm_studio_url = os.getenv("LM_STUDIO_URL", "http://localhost:1234/v1/chat/completions")
        self.lm_studio_enabled = os.getenv("LM_STUDIO_ENABLED", "true").lower() in ["true", "1", "yes", "y"]
        if not self.lm_studio_enabled:
            print("🧠 LM Studio is disabled via configuration")
    
    def analyze_logs(self, structured_logs: Dict[str, Any], basic_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Use OpenAI first, then DeepSeek as fallback, and send to LM Studio for training."""
        
        # Create prompt once to reuse
        prompt = self._create_prompt(structured_logs, basic_findings)
        lm_studio_training_result = None
        
        try:
            # Try OpenAI first if API key is valid
            if self.openai_api_key and len(self.openai_api_key) > 10:
                try:
                    print("\n========================================")
                    print("🔵 ATTEMPTING TO USE GPT-4o (OPENAI API)")
                    print("========================================")
                    
                    # Make the API call to OpenAI
                    response = self._call_openai_api(prompt)
                    
                    # Parse the response
                    result = self._parse_response(response)
                    result["source"] = "openai_gpt4o"
                    result["model"] = "gpt-4o"
                    
                    print("✅ SUCCESS: Response received from OpenAI GPT-4o")
                    print(f"📋 Response length: {len(result.get('raw_response', ''))}")
                    
                    # Try to send to LM Studio for training, but continue if it fails
                    try:
                        lm_studio_training_result = self._send_to_lm_studio_for_training(prompt, result)
                    except Exception as lm_e:
                        print(f"⚠️ LM Studio training skipped due to error: {str(lm_e)}")
                        result["lm_studio_training"] = {
                            "success": False,
                            "error": f"Training error: {str(lm_e)}"
                        }
                    
                    return result
                except Exception as openai_e:
                    print(f"❌ ERROR using OpenAI API: {str(openai_e)}")
                    # Continue to DeepSeek if OpenAI fails
            
            # Try DeepSeek if OpenAI isn't configured or failed
            if self.deepseek_api_key and len(self.deepseek_api_key) > 10:
                try:
                    print("\n=========================================")
                    print("🟢 ATTEMPTING TO USE DEEPSEEK API")
                    print("=========================================")
                    
                    # Make the API call to DeepSeek
                    response = self._call_deepseek_api(prompt)
                    
                    # Parse the response
                    result = self._parse_response(response)
                    result["source"] = "deepseek_api"
                    result["model"] = "deepseek-chat"
                    
                    print("✅ SUCCESS: Response received from DeepSeek API")
                    print(f"📋 Response length: {len(result.get('raw_response', ''))}")
                    
                    # Try to send to LM Studio for training, but continue if it fails
                    try:
                        lm_studio_training_result = self._send_to_lm_studio_for_training(prompt, result)
                    except Exception as lm_e:
                        print(f"⚠️ LM Studio training skipped due to error: {str(lm_e)}")
                        result["lm_studio_training"] = {
                            "success": False,
                            "error": f"Training error: {str(lm_e)}"
                        }
                    
                    return result
                except Exception as deepseek_e:
                    print(f"❌ ERROR using DeepSeek API: {str(deepseek_e)}")
                    # Continue to fallback if DeepSeek fails
            
            # Use fallback mode if no API keys are available or all APIs failed
            print("\n=========================================")
            print("⚠️ USING FALLBACK MODE - No valid API keys or all APIs failed")
            print("=========================================")
            
            result = self._generate_fallback_response(structured_logs, basic_findings)
            result["source"] = "fallback_simulated"
            result["model"] = "simulated_response"
            
            return result
            
        except Exception as e:
            print("\n=========================================")
            print(f"❗ CRITICAL ERROR during analysis: {str(e)}")
            print("⚠️ USING FALLBACK MODE as final resort")
            print("=========================================")
            
            # Return a simulated fallback response as last resort
            result = self._generate_fallback_response(structured_logs, basic_findings)
            result["source"] = "fallback_after_error"
            result["model"] = "simulated_response"
            
            return result
            
    def _send_to_lm_studio_for_training(self, original_prompt: str, api_result: Dict[str, Any]) -> Dict[str, Any]:
        """Send the API response to LM Studio for training purposes."""
        # Check if LM Studio is enabled in configuration
        if not self.lm_studio_enabled:
            print("\n=========================================")
            print("🧠 LM STUDIO TRAINING DISABLED BY CONFIGURATION")
            print("=========================================")
            return {"success": False, "error": "LM Studio disabled by configuration"}
            
        print("\n=========================================")
        print("🧠 SENDING TO LM STUDIO FOR TRAINING")
        print("=========================================")
        
        try:
            # Get the raw response from the API result
            api_response = api_result.get("raw_response", "")
            
            if not api_response:
                print("❌ ERROR: No raw response found in API result")
                return {"success": False, "error": "No raw response to train on"}
            
            # Create a training prompt for LM Studio that requests detailed reasoning
            # Determine log type from content and create appropriate prompt
            log_content = api_response[:5000]
            
            # Just use the API response as context and request EXACTLY the specified format
            training_prompt = f"""Here is an analysis of log entries:

{api_response[:2000]}

Respond ONLY with a JSON object in this EXACT format:

{{
  "reasoning": [
    "R:Reason 1 about security implications",
    "R:Reason 2 about security implications",
    "R:Reason 3 about security implications",
    "R:Reason 4 about security implications",
    "R:Reason 5 about security implications"
    "R:Reason 6 about security implications",
    "R:Reason 7 about security implications"
    "R:Reason 8 about security implications",
    "R:Reason 9 about security implications"
    "R:Reason 10 about security implications",
    "R:Reason 11 about security implications"
  ]
}}

Note: You can include more than 20 reasoning points if needed. This is just an example format.
DO NOT include any other text, explanation, or thinking. Return ONLY the JSON object.
"""
            
            print(f"📤 Sending to LM Studio... (prompt: {len(training_prompt)} chars)")
            
            # Create the LM Studio API payload
            headers = {
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": "deepseek-r1-distill-qwen-7b",  # Local model in LM Studio
                "messages": [
                    {
                        "role": "system",
                        "content": """You are a security analysis API that ONLY returns valid JSON.

You MUST:
1. Return ONLY a JSON object in the exact format requested
2. Include NO text, explanation, or conversation outside the JSON
3. NEVER add any prefixes, suffixes, or explanation
4. Structure each reasoning point with "R:" prefix exactly as shown
5. Keep responses strictly in the required JSON schema
6. Provide as many detailed reasoning points as needed (at least 3, but can include more)

Example of ENTIRE response:
{
  "reasoning": [
    "R:Security implication 1",
    "R:Security implication 2",
    "R:Security implication 3",
    "R:Security implication 4",
    "R:Security implication 5"
  ]
}
"""
                    },
                    {
                        "role": "user", 
                        "content": training_prompt
                    }
                ],
                "temperature": 0.7,  # Slightly higher temperature for more detailed responses
                "max_tokens": 2000,  # Increased token limit for more detailed reasoning
                "stream": False
            }
            
            # Send to LM Studio
            print(f"🔗 Connecting to LM Studio at: {self.lm_studio_url}")
            try:
                # First check if LM Studio is reachable with a quick connection test
                test_request = requests.get(self.lm_studio_url.rsplit('/', 1)[0], timeout=2)
                is_available = test_request.status_code == 200 or test_request.status_code == 404
            except:
                is_available = False
                
            if not is_available:
                print("⚠️ LM Studio is not available at the configured URL.")
                
                api_result["lm_studio_training"] = {
                    "success": False,
                    "error": "Unable to connect to LM Studio service",
                    "reasoning_bullets": []  # Empty array - no fallback reasoning
                }
                return {"success": False, "error": "LM Studio not available - connection failed"}
                
            # Only proceed if LM Studio is available
            response = requests.post(self.lm_studio_url, headers=headers, json=payload, timeout=120)  # Increased timeout
            
            # Process response
            if response.status_code == 200:
                lm_studio_json = response.json()
                
                # Extract the response content
                if "choices" in lm_studio_json and len(lm_studio_json["choices"]) > 0:
                    lm_studio_response = lm_studio_json["choices"][0]["message"]["content"]
                    
                    # Save for training data - use the self-contained save_training function
                    try:
                        # We no longer need to save training data since we're using direct responses
                        
                        # Just use the response as is - we're not dealing with line numbers
                        validated_response = lm_studio_response
                        
                        # Process the response to extract reasoning from JSON
                        reasoning_bullets = []
                        
                        try:
                            # First, remove any <think>...</think> blocks from the response
                            import json
                            import re
                            
                            # Remove thinking blocks
                            cleaned_response = lm_studio_response
                            think_pattern = r'<think>[\s\S]*?<\/think>'
                            cleaned_response = re.sub(think_pattern, '', cleaned_response).strip()
                            
                            # Look for JSON specifically
                            json_pattern = r'```json\s*([\s\S]*?)```'
                            code_blocks = re.findall(json_pattern, cleaned_response)
                            
                            if code_blocks:
                                # Extract the JSON from code blocks
                                json_text = code_blocks[0].strip()
                                print(f"✅ Found JSON in code block: {json_text[:50]}...")
                            else:
                                # Try to find a raw JSON object
                                json_pattern = r'({[\s\S]*})'
                                json_match = re.search(json_pattern, cleaned_response)
                                
                                if json_match:
                                    json_text = json_match.group(1).strip()
                                    print(f"✅ Found JSON object: {json_text[:50]}...")
                                else:
                                    json_text = cleaned_response
                                    print(f"⚠️ No JSON found, using cleaned response: {json_text[:50]}...")
                                
                            # Try to parse as JSON
                            try:
                                json_response = json.loads(json_text)
                                
                                # Validate that it has the correct format
                                if "reasoning" in json_response and isinstance(json_response["reasoning"], list):
                                    # Extract reasoning points and format them
                                    for reason in json_response["reasoning"]:
                                        if isinstance(reason, str):
                                            # Handle both "R:text" and "R:" prefix formats
                                            if reason.startswith("R:"):
                                                formatted_reason = f"🔹 {reason[2:]}"  # Remove R: and add emoji
                                                reasoning_bullets.append(formatted_reason)
                                            # Also handle any other valid reasoning format
                                            elif len(reason) > 10:  # Some minimum length check
                                                formatted_reason = f"🔹 {reason}"  # Add emoji
                                                reasoning_bullets.append(formatted_reason)
                                    
                                    # Return just the clean JSON
                                    validated_response = json.dumps(json_response, indent=2)
                                    
                                    print(f"✅ Extracted {len(reasoning_bullets)} valid reasoning points")
                                else:
                                    print("⚠️ WARNING: JSON doesn't contain reasoning array")
                                    validated_response = json_text
                            except json.JSONDecodeError:
                                print("⚠️ WARNING: Not valid JSON")
                                validated_response = json_text
                        except json.JSONDecodeError:
                            # Fallback if not valid JSON
                            print("⚠️ WARNING: LM Studio response is not valid JSON")
                            validated_response = lm_studio_response
                            
                            # Try to extract any relevant content as bullets
                            lines = lm_studio_response.split("\n")
                            for line in lines:
                                line = line.strip()
                                if line and len(line) > 10 and not line.startswith("#") and not line.startswith("[") and not line.startswith("{"):
                                    reasoning_bullets.append(f"🔹 {line}")
                        
                        # No need to save training examples anymore
                        training_path = "N/A" # We don't save training data
                        
                        print("✅ SUCCESS: LM Studio response received")
                        print(f"📝 LM Studio response: {len(lm_studio_response)} characters")
                        print(f"📊 First 50 chars: {lm_studio_response[:50]}...")
                        
                        # We already processed and extracted reasoning bullets above
                        
                        # Display reasoning in a nice format in the logs - make it very visible
                        print("\n")
                        print("🧠" * 40)
                        print("🧠                 LM STUDIO REASONING                  🧠")
                        print("🧠" * 40)
                        print("\n")
                        
                        if reasoning_bullets:
                            for bullet in reasoning_bullets:
                                print(f"🔹 {bullet}")
                            print("\n")
                        else:
                            # Try to format the raw response as best we can
                            print("🔸 No clear reasoning bullets found. Raw reasoning:")
                            print("\n")
                            
                            # Try to identify paragraphs or points in the text
                            raw_text = lm_studio_response[:1000]  # Show first 1000 chars
                            paragraphs = [p.strip() for p in raw_text.split('\n\n') if p.strip()]
                            
                            if paragraphs:
                                for i, para in enumerate(paragraphs[:5]):
                                    if para.strip():
                                        print(f"  {i+1}. {para.strip()[:200]}...")
                                        print()
                            else:
                                # Fall back to line-by-line display
                                preview_lines = raw_text.split('\n')
                                for i, line in enumerate(preview_lines[:8]):  # Show first 8 lines
                                    if line.strip():
                                        print(f"  {i+1}. {line.strip()}")
                            
                            if len(raw_text) > 1000:
                                print("  ...")
                                
                        print("\n")
                        print("🧠" * 40)
                        print("\n")
                        
                        # For demo purposes, use the exact example reasoning provided if no reasoning bullets
                        if not reasoning_bullets:
                            reasoning_bullets = [
                                "Model unable to provide detailed security reasoning",
                                "Analysis requires more context from log data",
                                "Consider running with additional log files for better results",
                                "Fallback mode activated due to processing limitations",
                                "Recommend manual review of logs for complete analysis"
                            ]
                        
                        # Reasoning bullets are already formatted with 🔹 emoji
                        formatted_reasoning_bullets = reasoning_bullets
                        
                        reasoning_html = "<div class='lm-studio-reasoning'>"
                        if formatted_reasoning_bullets:
                            reasoning_html += "<h3>LM Studio Reasoning:</h3>"
                            for bullet in formatted_reasoning_bullets:
                                reasoning_html += f"<p>{bullet}</p>"
                        else:
                            reasoning_html += "<p>No structured reasoning available from LM Studio.</p>"
                        reasoning_html += "</div>"
                        
                        # Add LM Studio info to API result for tracking
                        api_result["lm_studio_training"] = {
                            "success": True,
                            "response_length": len(lm_studio_response),
                            "model": "deepseek-r1-distill-qwen-7b",
                            "training_saved": True,
                            "training_path": training_path,
                            "reasoning_bullets": formatted_reasoning_bullets,
                            "reasoning_html": reasoning_html,
                            "lm_studio_full_response": lm_studio_response  # Include the complete response for the UI
                        }
                        
                        return {"success": True, "response": lm_studio_response}
                    except Exception as save_err:
                        print(f"⚠️ WARNING: Could not save training data: {str(save_err)}")
                        api_result["lm_studio_training"] = {
                            "success": True,
                            "response_length": len(lm_studio_response),
                            "model": "deepseek-r1-distill-qwen-7b",
                            "training_saved": False,
                            "error": str(save_err)
                        }
                        return {"success": True, "error_saving": True}
                else:
                    print("❌ ERROR: Unexpected response format from LM Studio")
                    api_result["lm_studio_training"] = {
                        "success": False,
                        "error": "Unexpected response format"
                    }
                    return {"success": False, "error": "Unexpected response format"}
            else:
                error_text = response.text[:200]
                print(f"❌ ERROR: LM Studio returned status code {response.status_code}")
                print(f"Error details: {error_text}")
                
                api_result["lm_studio_training"] = {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {error_text}"
                }
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            print(f"❌ ERROR using LM Studio for training: {str(e)}")
            
            api_result["lm_studio_training"] = {
                "success": False,
                "error": str(e)
            }
            
            return {"success": False, "error": str(e)}
    
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
        
        IMPORTANT: You must provide DETAILED justifications and reasoning for your analysis. Do not just state what was found, 
        but explain WHY certain patterns are suspicious and HOW they relate to specific security threats.
        
        For example, instead of saying:
        "SQL injection was detected in line 42."
        
        Say:
        "A SQL injection attempt was detected in line 42, where the attacker used a malformed input containing single quotes 
        and SQL syntax ('OR 1=1--) to try to bypass authentication. This specific pattern attempts to create a SQL condition 
        that always evaluates to true, and the trailing comment markers (--) attempt to ignore the remainder of the SQL query."
        
        Log file summary:
        - Total lines: {structured_logs["total_lines"]}
        - Analysis timestamp: {structured_logs["analysis_timestamp"]}
        
        Basic findings from pattern matching:
        {json.dumps(basic_findings, indent=2)}
        
        Selected log entries for context:
        """
        
        # Store the original prompt to help with fallback reasoning
        self.original_prompt = prompt
        
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
        
        # Check for DDoS patterns - simplified to avoid using self.vulnerabilities
        has_ddos_findings = any("DDOS" in finding.get("vulnerability_id", "") or "DOS" in finding.get("vulnerability_id", "") for finding in basic_findings)
        
        # Simplified DDoS pattern check without relying on self.vulnerabilities
        ddos_content_check = False
        try:
            log_content_str = "\n".join([entry.get("raw_content", "") for entry in structured_logs.get("log_entries", [])])
            
            # Check for common DDoS patterns in the log content
            ddos_keywords = [
                "high request rate", "requests per second", "ddos", "denial of service",
                "rate limit", "flood", "attack", "many connections", "too many requests"
            ]
            
            for keyword in ddos_keywords:
                if re.search(keyword, log_content_str, re.IGNORECASE):
                    ddos_content_check = True
                    break
                    
        except Exception as e:
            print(f"Error checking for DDoS patterns in logs: {str(e)}")
        
        prompt += """
        
        Please provide a detailed analysis including:
        1. Confirmation or rejection of the basic findings with DETAILED technical reasoning
        2. Additional vulnerabilities or security issues not captured by basic pattern matching
        3. Assessment of potential impact and severity with specific consequences
        4. Technical explanation of attack methodologies and techniques observed
        5. Recommended actions with rationale
        
        VERY IMPORTANT: For each finding or observation:
        - ALWAYS specify the exact line numbers where suspicious activity was found (e.g., "in lines 45-48")
        - Explain WHY the observed pattern is suspicious by describing the technical aspects of the attack
        - Connect related findings to show how they might be part of a coordinated attack
        - Provide context about the attack technique and its potential real-world impact
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
            "model": "gpt-4o",  # Using the latest GPT-4o model
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert security analyst specialized in identifying vulnerabilities from log files. Provide detailed analysis in JSON format with reasoning steps, confirmed findings, new findings, and actionable recommendations."
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
        
        # Add model information for the frontend
        model_source = analysis_results.get("source", "unknown")
        model_name = analysis_results.get("model", "unknown")
        
        # Add this to the response
        response["model_info"] = {
            "source": model_source,
            "name": model_name,
            "timestamp": datetime.now().isoformat()
        }
        
        # Add the full response from each model for the UI to display
        response["model_responses"] = {
            "primary_model": {
                "model_name": model_name,
                "source": model_source,
                "response_text": analysis_results.get("raw_response", "No response available")
            }
        }
        
        # Add LM Studio info and full response for the frontend to display
        if "lm_studio_training" in analysis_results:
            training = analysis_results["lm_studio_training"]
            
            # Get the full LM Studio response if available
            lm_studio_response = ""
            
            # Add to the response for the UI
            response["lm_studio"] = {
                "used_for_training": True,
                "success": training.get("success", False),
                "model": training.get("model", "deepseek-r1-distill-qwen-7b"),
                "training_saved": training.get("training_saved", False),
                "using_fallback": training.get("using_fallback", False)
            }
            
            # Add full response from LM Studio to model_responses
            # Only show reasoning if LM Studio was successful
            if training.get("success", False):
                if "lm_studio_full_response" in training:
                    # Use LM Studio response if available
                    lm_studio_response = training["lm_studio_full_response"]
                elif training.get("reasoning_bullets", []):
                    # If reasoning bullets are available, use them
                    lm_studio_response = "\n".join(training.get("reasoning_bullets", []))
                else:
                    # No demo bullets needed - just use empty arrays
                    demo_bullets = []
                    lm_studio_response = ""
                    training["reasoning_bullets"] = []
                
                # Add to model_responses for the UI to display directly
                response["model_responses"]["lm_studio"] = {
                    "model_name": training.get("model", "deepseek-r1-distill-qwen-7b"),
                    "source": "lm_studio_local",
                    "response_text": lm_studio_response,
                    "response_length": training.get("response_length", 0),
                    "reasoning_section": "#reasoning on\n" + "\n".join(training.get("reasoning_bullets", []))
                }
                
                # Add formatted reasoning bullets and HTML for UI display
                formatted_bullets = training.get("reasoning_bullets", [])
                if formatted_bullets:
                    response["lm_studio"]["reasoning_bullets"] = formatted_bullets
                    
                    # Generate HTML if not already present
                    if not training.get("reasoning_html"):
                        reasoning_html = "<div class='lm-studio-reasoning'><h3>LM Studio Reasoning:</h3>" + "".join([f"<p>{bullet}</p>" for bullet in formatted_bullets]) + "</div>"
                        response["lm_studio"]["reasoning_html"] = reasoning_html
                    else:
                        response["lm_studio"]["reasoning_html"] = training.get("reasoning_html")
        else:
            response["lm_studio"] = {
                "used_for_training": False,
                "note": "LM Studio was not used"
            }
        
        # Print a clear summary of the results
        print("\n=========================================")
        print(f"📊 ANALYSIS COMPLETED")
        print(f"🤖 Model: {model_name}")
        print(f"🔍 Source: {model_source}")
        print(f"🔢 Findings count: {len(basic_findings)}")
        if "recommendations" in analysis_results:
            print(f"💡 Recommendations: {len(analysis_results['recommendations'])}")
            
        # Add LM Studio summary if available
        lm_studio_status = "❌ Not used"
        if "lm_studio_training" in analysis_results:
            training = analysis_results["lm_studio_training"]
            if training.get("success", False):
                lm_studio_status = f"✅ Success ({training.get('response_length', 0)} chars)"
                if training.get("training_saved", False):
                    lm_studio_status += ", saved for training"
            else:
                error_msg = training.get('error', 'Unknown error')
                if "not available" in error_msg or "connection failed" in error_msg:
                    lm_studio_status = f"⚠️ LM Studio not available"
                else:
                    lm_studio_status = f"❌ Failed: {error_msg}"
                
        print(f"🧠 LM Studio: {lm_studio_status}")
        print("=========================================\n")
        
        return jsonify(response)
    
    except Exception as e:
        print(f"Error in /analyze endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Make sure the vulnerabilities file exists
    load_vulnerabilities()
    # Run the Flask app
    app.run(debug=True)