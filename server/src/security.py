#!/usr/bin/env python3
"""
Tatou Security System - unified security monitoring, analysis and testing tool
"""
import argparse
import requests
import time
import random
import string
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

class TatouSecurity:
    """Tatou Security System unified tool"""
    
    def __init__(self, base_url="http://localhost:5000", admin_key="your-strong-admin-key-for-leak-detection"):
        self.base_url = base_url
        self.admin_key = admin_key
        self.session = requests.Session()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )
        self.logger = logging.getLogger(__name__)
        
        # Monitoring metrics
        self.metrics = {
            'health_checks': 0,
            'security_alerts': 0,
            'failed_requests': 0,
            'last_check': None
        }
    
    def check_health(self) -> bool:
        """Check service health status"""
        try:
            response = requests.get(f"{self.base_url}/healthz", timeout=5)
            if response.status_code == 200:
                self.metrics['health_checks'] += 1
                self.logger.info("Health check passed")
                return True
            else:
                self.logger.warning(f"Health check failed: {response.status_code}")
                return False
        except Exception as e:
            self.logger.error(f"Health check error: {e}")
            self.metrics['failed_requests'] += 1
            return False
    
    def check_security_status(self) -> bool:
        """Check security status"""
        try:
            headers = {'X-Admin-Key': self.admin_key}
            response = requests.get(f"{self.base_url}/api/security-status", headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                print("Security Status:")
                print(f"  Suspicious IPs: {len(data['security_summary']['suspicious_ips'])}")
                print(f"  Active login attempts: {len(data['security_summary']['active_login_attempts'])}")
                print(f"  Active request counts: {len(data['security_summary']['active_request_counts'])}")
                return True
            else:
                print(f"Failed to get security status: {response.status_code}")
                return False
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def analyze_logs(self, log_file="../logs/app.log") -> Dict[str, Any]:
        """Analyze security logs"""
        log_path = Path(log_file)
        if not log_path.exists():
            print(f"Log file does not exist: {log_file}")
            return {}
        
        security_events = []
        with open(log_path, 'r', encoding='utf-8') as f:
            for line in f:
                if 'event=security_alert' in line or 'SECURITY_BLOCK' in line:
                    security_events.append(line.strip())
        
        result = {
            'total_security_events': len(security_events),
            'recent_events': security_events[-5:] if security_events else [],
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        print(f"Log Analysis Results:")
        print(f"  Total security events: {result['total_security_events']}")
        if result['recent_events']:
            print(f"  Recent events:")
            for event in result['recent_events']:
                print(f"    {event}")
        
        return result
    
    def run_attack_test(self):
        """Run attack tests"""
        print("Running attack tests...")
        
        # 1. Brute force test
        print("  Testing brute force detection...")
        for i in range(6):  # Exceed 5 attempt threshold
            try:
                response = self.session.post(f"{self.base_url}/api/login", 
                    json={"email": "test@example.com", "password": "wrong"})
                print(f"    Attempt {i+1}: {response.status_code}")
                time.sleep(0.5)
            except:
                pass
        
        # 2. Path traversal test
        print("  Testing path traversal detection...")
        try:
            response = self.session.get(f"{self.base_url}/../../../etc/passwd")
            print(f"    Path traversal: {response.status_code}")
        except:
            pass
        
        # 3. Watermark link brute force test
        print("  Testing watermark link brute force detection...")
        for i in range(25):  # Exceed 20 attempt threshold
            random_link = ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))
            try:
                response = self.session.get(f"{self.base_url}/api/get-version/{random_link}")
                if i < 3:  # Only show first 3 attempts
                    print(f"    Attempt {i+1}: {response.status_code}")
                time.sleep(0.2)
            except:
                pass
        
        # 4. Rate limiting test
        print("  Testing rate limiting detection...")
        for i in range(10):
            try:
                response = self.session.get(f"{self.base_url}/healthz")
                if i < 3:  # Only show first 3 requests
                    print(f"    Request {i+1}: {response.status_code}")
                time.sleep(0.1)  # Fast requests
            except:
                pass
        
        # 5. Admin interface test
        print("  Testing admin interface attack detection...")
        wrong_keys = ["wrong_key", "admin", "password"]
        for key in wrong_keys:
            try:
                headers = {'X-Admin-Key': key}
                response = self.session.get(f"{self.base_url}/api/security-status", headers=headers)
                print(f"    Admin key '{key}': {response.status_code}")
                time.sleep(0.5)
            except:
                pass
        
        print("Attack tests completed, please check logs")
    
    def generate_alert(self, alert_type: str, message: str, severity: str = "WARNING"):
        """Generate security alert"""
        self.logger.warning(f"SECURITY_ALERT: {alert_type} - {message}")
        self.metrics['security_alerts'] += 1
    
    def check_security_thresholds(self, security_data: dict):
        """Check security thresholds"""
        if not security_data or 'security_summary' not in security_data:
            return
        
        summary = security_data['security_summary']
        
        # Check suspicious IP count
        suspicious_ips = summary.get('suspicious_ips', [])
        if len(suspicious_ips) > 5:
            self.generate_alert(
                'SUSPICIOUS_IPS_HIGH',
                f"High number of suspicious IPs detected: {len(suspicious_ips)}",
                'HIGH'
            )
        
        # Check active login attempts
        login_attempts = summary.get('active_login_attempts', {})
        for ip, attempts in login_attempts.items():
            if attempts > 3:
                self.generate_alert(
                    'BRUTE_FORCE_ACTIVE',
                    f"Active brute force attempts from IP {ip}: {attempts} attempts",
                    'HIGH'
                )
    
    def run_monitoring_cycle(self):
        """Run a monitoring cycle"""
        self.logger.info("Starting monitoring cycle...")
        
        # Health check
        health_ok = self.check_health()
        if not health_ok:
            self.generate_alert('SERVICE_DOWN', 'Service health check failed', 'CRITICAL')
        
        # Security status check
        security_data = self.check_security_status()
        if security_data:
            self.check_security_thresholds(security_data)
        
        # Log analysis
        log_analysis = self.analyze_logs()
        if log_analysis and log_analysis.get('total_security_events', 0) > 10:
            self.generate_alert(
                'HIGH_SECURITY_EVENTS',
                f"High number of security events in logs: {log_analysis['total_security_events']}",
                'MEDIUM'
            )
        
        self.metrics['last_check'] = datetime.now().isoformat()
        self.logger.info("Monitoring cycle completed")
    
    def start_monitoring(self, interval: int = 60):
        """Start continuous monitoring"""
        self.logger.info(f"Starting continuous monitoring (interval: {interval}s)")
        
        try:
            while True:
                self.run_monitoring_cycle()
                time.sleep(interval)
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped")
        except Exception as e:
            self.logger.error(f"Monitoring error: {e}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get monitoring metrics"""
        return {
            'metrics': self.metrics,
            'timestamp': datetime.now().isoformat()
        }
    
    def recover_from_attacks(self, ip: str = None, attack_type: str = None) -> bool:
        """Recover from attacks"""
        try:
            data = {}
            if ip:
                data['ip'] = ip
            if attack_type:
                data['attack_type'] = attack_type
            
            headers = {'X-Admin-Key': self.admin_key, 'Content-Type': 'application/json'}
            response = requests.post(f"{self.base_url}/api/security-recover", 
                                   json=data, headers=headers, timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                print("🔄 Recovery completed:")
                for action in result['recovery_result']['recovery_actions']:
                    print(f"  ✅ {action}")
                print(f"  Remaining suspicious IPs: {result['recovery_result']['remaining_suspicious_ips']}")
                return True
            else:
                print(f"❌ Recovery failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Recovery error: {e}")
            return False
    
    def get_attack_incidents(self, limit: int = 20) -> Dict[str, Any]:
        """Get recorded attack incidents"""
        try:
            headers = {'X-Admin-Key': self.admin_key}
            response = requests.get(f"{self.base_url}/api/security-incidents?limit={limit}", 
                                  headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                incidents = data['incidents']
                
                print(f"📊 Attack incidents (last {len(incidents)}):")
                if not incidents:
                    print("  No incidents recorded")
                else:
                    for i, incident in enumerate(incidents[-5:], 1):  # show last 5
                        timestamp = datetime.fromtimestamp(incident['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                        print(f"  {i}. {incident['attack_type']} - {incident['ip']} - {timestamp}")
                        if 'details' in incident:
                            details = incident['details']
                            if 'attempts' in details:
                                print(f"     Attempts: {details['attempts']}")
                            if 'recovery_action' in details:
                                print(f"     Recovery action: {details['recovery_action']}")
                
                return data
            else:
                print(f"❌ Failed to fetch incidents: {response.status_code}")
                return {}
        except Exception as e:
            print(f"❌ Error fetching incidents: {e}")
            return {}
    
    def analyze_attacks(self) -> Dict[str, Any]:
        """Analyze attack patterns"""
        try:
            headers = {'X-Admin-Key': self.admin_key}
            response = requests.get(f"{self.base_url}/api/security-analysis", 
                                  headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                analysis = data['analysis']
                
                print("🔍 Attack pattern analysis:")
                if 'total_incidents' in analysis:
                    print(f"  Total incidents: {analysis['total_incidents']}")
                
                if 'attack_type_distribution' in analysis:
                    print("  Attack type distribution:")
                    for attack_type, count in analysis['attack_type_distribution'].items():
                        print(f"    {attack_type}: {count} times")
                
                if 'top_attacking_ips' in analysis:
                    print("  Top attacking IPs:")
                    for ip, count in analysis['top_attacking_ips'][:5]:
                        print(f"    {ip}: {count} times")
                
                if 'recommendations' in analysis:
                    print("  Recovery recommendations:")
                    for rec in analysis['recommendations']:
                        print(f"    • {rec}")
                
                return data
            else:
                print(f"❌ Attack analysis failed: {response.status_code}")
                return {}
        except Exception as e:
            print(f"❌ Attack analysis error: {e}")
            return {}

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Tatou Security System')
    parser.add_argument('--url', default='http://localhost:5000', help='Service URL')
    parser.add_argument('--admin-key', default='your-strong-admin-key-for-leak-detection', help='Admin key')
    parser.add_argument('--log-file', default='../logs/app.log', help='Log file path')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Status check command
    subparsers.add_parser('status', help='Check security status')
    
    # Log analysis command
    subparsers.add_parser('logs', help='Analyze security logs')
    
    # Attack test command
    subparsers.add_parser('test', help='Run attack tests')
    
    # Monitoring command
    monitor_parser = subparsers.add_parser('monitor', help='Continuous monitoring')
    monitor_parser.add_argument('--interval', type=int, default=60, help='Monitoring interval (seconds)')
    
    # Health check command
    subparsers.add_parser('health', help='Health check')
    
    # Recovery command
    recover_parser = subparsers.add_parser('recover', help='Recover from attacks')
    recover_parser.add_argument('--ip', help='Recover a specific IP')
    recover_parser.add_argument('--attack-type', help='Recover a specific attack type (e.g., brute_force, rate_limit, all)')
    
    # Incidents command
    subparsers.add_parser('incidents', help='View attack incidents')
    
    # Analysis command
    subparsers.add_parser('analyze', help='Analyze attack patterns')
    
    args = parser.parse_args()
    
    security = TatouSecurity(args.url, args.admin_key)
    
    if args.command == 'status':
        security.check_security_status()
    elif args.command == 'logs':
        security.analyze_logs(args.log_file)
    elif args.command == 'test':
        security.run_attack_test()
    elif args.command == 'health':
        security.check_health()
    elif args.command == 'monitor':
        print(f"Starting monitoring (interval: {args.interval}s)")
        security.start_monitoring(args.interval)
    elif args.command == 'recover':
        security.recover_from_attacks(args.ip, args.attack_type)
    elif args.command == 'incidents':
        security.get_attack_incidents()
    elif args.command == 'analyze':
        security.analyze_attacks()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
