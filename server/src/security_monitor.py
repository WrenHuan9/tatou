"""
Security monitoring module - detects and records potential attacks
Simplified version utilizing existing logging system
"""
import time
import re
from collections import defaultdict, deque
from typing import Dict, List, Any
import logging

class SecurityMonitor:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        
        # Attack detection thresholds
        self.LOGIN_ATTEMPTS_THRESHOLD = 5  # 5 failed login attempts
        self.LOGIN_TIME_WINDOW = 300  # 5 minutes
        self.FILE_SIZE_LIMIT = 50 * 1024 * 1024  # 50MB
        self.REQUEST_RATE_LIMIT = 100  # 100 requests per minute
        self.REQUEST_TIME_WINDOW = 60  # 1 minute
        
        # Store attack attempts
        self.login_attempts: Dict[str, deque] = defaultdict(lambda: deque())
        self.request_counts: Dict[str, deque] = defaultdict(lambda: deque())
        self.suspicious_ips: set = set()
        
    def check_login_brute_force(self, ip: str, success: bool) -> bool:
        """Detect login brute force attacks"""
        current_time = time.time()
        
        if not success:
            # Record failed attempts
            self.login_attempts[ip].append(current_time)
            
            # Clean expired records
            while (self.login_attempts[ip] and 
                   current_time - self.login_attempts[ip][0] > self.LOGIN_TIME_WINDOW):
                self.login_attempts[ip].popleft()
            
            # Check if threshold exceeded
            if len(self.login_attempts[ip]) >= self.LOGIN_ATTEMPTS_THRESHOLD:
                self.suspicious_ips.add(ip)
                self.logger.warning(
                    "event=security_alert type=brute_force_login ip=%s attempts=%d",
                    ip, len(self.login_attempts[ip])
                )
                # Log detailed incident for recovery analysis
                self.log_attack_incident("brute_force_login", ip, {
                    "attempts": len(self.login_attempts[ip]),
                    "threshold": self.LOGIN_ATTEMPTS_THRESHOLD,
                    "time_window": self.LOGIN_TIME_WINDOW,
                    "recovery_action": "IP marked as suspicious"
                })
                return True
        else:
            # Login successful, clear records for this IP
            if ip in self.login_attempts:
                del self.login_attempts[ip]
        
        return False
    
    def check_file_upload_attack(self, ip: str, file_size: int, filename: str) -> bool:
        """Detect file upload attacks"""
        # Check file size
        if file_size > self.FILE_SIZE_LIMIT:
            self.logger.warning(
                "event=security_alert type=large_file_upload ip=%s size=%d filename=%s",
                ip, file_size, filename
            )
            return True
        
        # Check if filename contains suspicious characters
        if re.search(r'[<>:"|?*]', filename):
            self.logger.warning(
                "event=security_alert type=suspicious_filename ip=%s filename=%s",
                ip, filename
            )
            return True
        
        return False
    
    def check_path_traversal(self, ip: str, path: str) -> bool:
        """Detect path traversal attacks"""
        if '..' in path or '//' in path:
            self.logger.warning(
                "event=security_alert type=path_traversal ip=%s path=%s",
                ip, path
            )
            return True
        return False
    
    def check_rate_limiting(self, ip: str) -> bool:
        """Detect request rate limiting"""
        current_time = time.time()
        
        # Record request
        self.request_counts[ip].append(current_time)
        
        # Clean expired records
        while (self.request_counts[ip] and 
               current_time - self.request_counts[ip][0] > self.REQUEST_TIME_WINDOW):
            self.request_counts[ip].popleft()
        
        # Check if limit exceeded
        if len(self.request_counts[ip]) > self.REQUEST_RATE_LIMIT:
            self.suspicious_ips.add(ip)
            self.logger.warning(
                "event=security_alert type=rate_limit_exceeded ip=%s requests=%d",
                ip, len(self.request_counts[ip])
            )
            return True
        
        return False
    
    def check_watermark_link_brute_force(self, ip: str, status_code: int) -> bool:
        """Detect watermark link brute force guessing"""
        if status_code == 404:
            # Record 404 requests
            current_time = time.time()
            if not hasattr(self, 'watermark_404_attempts'):
                self.watermark_404_attempts = defaultdict(lambda: deque())
            
            self.watermark_404_attempts[ip].append(current_time)
            
            # Clean expired records
            while (self.watermark_404_attempts[ip] and 
                   current_time - self.watermark_404_attempts[ip][0] > 300):  # 5 minutes
                self.watermark_404_attempts[ip].popleft()
            
            # Check if threshold exceeded (20 404s)
            if len(self.watermark_404_attempts[ip]) > 20:
                self.suspicious_ips.add(ip)
                self.logger.warning(
                    "event=security_alert type=watermark_brute_force ip=%s attempts=%d",
                    ip, len(self.watermark_404_attempts[ip])
                )
                return True
        
        return False
    
    def check_rmap_attack(self, ip: str, success: bool, error_msg: str = "") -> bool:
        """Detect RMAP protocol attacks"""
        if not success:
            self.logger.warning(
                "event=security_alert type=rmap_attack ip=%s error=%s",
                ip, error_msg
            )
            return True
        return False
    
    def check_admin_access_attack(self, ip: str, success: bool) -> bool:
        """Detect admin interface attacks"""
        if not success:
            self.logger.warning(
                "event=security_alert type=admin_access_attack ip=%s",
                ip
            )
            return True
        return False
    
    def is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is marked as suspicious"""
        return ip in self.suspicious_ips
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get security monitoring summary"""
        return {
            "suspicious_ips": list(self.suspicious_ips),
            "active_login_attempts": {ip: len(attempts) for ip, attempts in self.login_attempts.items()},
            "active_request_counts": {ip: len(counts) for ip, counts in self.request_counts.items()},
        }
    
    def recover_from_attack(self, ip: str = None, attack_type: str = None) -> Dict[str, Any]:
        """Recover from attacks - clear suspicious IPs and reset counters"""
        recovery_actions = []
        
        if ip:
            # Recover specific IP
            if ip in self.suspicious_ips:
                self.suspicious_ips.remove(ip)
                recovery_actions.append(f"Removed IP {ip} from suspicious list")
            
            if ip in self.login_attempts:
                del self.login_attempts[ip]
                recovery_actions.append(f"Cleared login attempts for IP {ip}")
            
            if ip in self.request_counts:
                del self.request_counts[ip]
                recovery_actions.append(f"Cleared request counts for IP {ip}")
                
        elif attack_type:
            # Recover specific attack type
            if attack_type == "brute_force":
                self.login_attempts.clear()
                recovery_actions.append("Cleared all brute force attempts")
            elif attack_type == "rate_limit":
                self.request_counts.clear()
                recovery_actions.append("Cleared all rate limit counters")
            elif attack_type == "all":
                self.suspicious_ips.clear()
                self.login_attempts.clear()
                self.request_counts.clear()
                recovery_actions.append("Cleared all security data")
        else:
            # Recover all
            self.suspicious_ips.clear()
            self.login_attempts.clear()
            self.request_counts.clear()
            recovery_actions.append("Cleared all security data")
        
        # Log recovery action
        if recovery_actions:
            self.logger.info(
                "event=security_recovery actions=%s timestamp=%s",
                "; ".join(recovery_actions), time.time()
            )
        
        return {
            "recovery_actions": recovery_actions,
            "timestamp": time.time(),
            "remaining_suspicious_ips": len(self.suspicious_ips),
            "remaining_login_attempts": len(self.login_attempts),
            "remaining_request_counts": len(self.request_counts)
        }
    
    def log_attack_incident(self, attack_type: str, ip: str, details: Dict[str, Any]) -> None:
        """Log detailed attack incident for recovery analysis"""
        incident_data = {
            "attack_type": attack_type,
            "ip": ip,
            "timestamp": time.time(),
            "details": details,
            "recovery_needed": True
        }
        
        self.logger.warning(
            "event=attack_incident type=%s ip=%s details=%s recovery_needed=true",
            attack_type, ip, str(details)
        )
        
        # Store incident for later analysis
        if not hasattr(self, 'attack_incidents'):
            self.attack_incidents = []
        self.attack_incidents.append(incident_data)
    
    def get_attack_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent attack incidents for analysis"""
        if not hasattr(self, 'attack_incidents'):
            return []
        return self.attack_incidents[-limit:]
    
    def analyze_attack_patterns(self) -> Dict[str, Any]:
        """Analyze attack patterns for recovery planning"""
        if not hasattr(self, 'attack_incidents'):
            return {"analysis": "No incidents recorded"}
        
        incidents = self.attack_incidents
        if not incidents:
            return {"analysis": "No incidents to analyze"}
        
        # Analyze patterns
        attack_types = {}
        ip_frequency = {}
        time_patterns = {}
        
        for incident in incidents:
            # Count attack types
            attack_type = incident['attack_type']
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
            # Count IP frequency
            ip = incident['ip']
            ip_frequency[ip] = ip_frequency.get(ip, 0) + 1
            
            # Analyze time patterns
            timestamp = incident['timestamp']
            hour = time.strftime('%H', time.localtime(timestamp))
            time_patterns[hour] = time_patterns.get(hour, 0) + 1
        
        return {
            "total_incidents": len(incidents),
            "attack_type_distribution": attack_types,
            "top_attacking_ips": sorted(ip_frequency.items(), key=lambda x: x[1], reverse=True)[:10],
            "hourly_attack_pattern": time_patterns,
            "analysis_timestamp": time.time(),
            "recommendations": self._generate_recovery_recommendations(attack_types, ip_frequency)
        }
    
    def _generate_recovery_recommendations(self, attack_types: Dict, ip_frequency: Dict) -> List[str]:
        """Generate recovery recommendations based on attack patterns"""
        recommendations = []
        
        if 'brute_force_login' in attack_types and attack_types['brute_force_login'] > 10:
            recommendations.append("Consider implementing CAPTCHA for login attempts")
        
        if 'rate_limit_exceeded' in attack_types and attack_types['rate_limit_exceeded'] > 5:
            recommendations.append("Consider reducing rate limit thresholds")
        
        if len(ip_frequency) > 20:
            recommendations.append("Consider implementing IP whitelist/blacklist")
        
        if not recommendations:
            recommendations.append("Current security measures are adequate")
        
        return recommendations

# Global security monitoring instance (will be initialized in create_app)
security_monitor = None
