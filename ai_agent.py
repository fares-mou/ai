import json
import time
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime
import threading
from collections import deque
import random
import joblib

class RealTimeAIAgent:
    def __init__(self):
        self.learning_mode = True
        self.normal_behavior_db = []
        self.detection_model = None
        self.scaler = None
        self.learning_duration = 3600
        self.learning_start_time = time.time()

        self.recent_behaviors = deque(maxlen=100)
        self.alerts = []
        self.blocked_ips = set()
        self.total_packets_analyzed = 0
        self.last_error = None

        print("🤖 Real-Time AI Agent Initialized")
        print("🎓 Learning NORMAL BEHAVIORS in entire network for 1 HOUR...")
        print("📡 Monitoring all traffic regardless of IP addresses")

    def analyze_network_behavior(self, packet_data):
        """Analyses network behavior from real packets or packets-like data"""
        self.total_packets_analyzed += 1
        behavior = self._extract_behavior_features(packet_data)
        
        if behavior is None:
            return "skip"

        if self.learning_mode:
            return self._learn_from_behavior(behavior, packet_data)
        else:
            return self._detect_anomalies(behavior, packet_data)

    def _extract_behavior_features(self, packet):
        """Extracts features from Scapy packets (IP/TCP/UDP)"""
        try:
            # Check if it's a Scapy packet (has IP layer)
            from scapy.layers.inet import IP, TCP, UDP
            
            if not packet.haslayer(IP):
                return None

            ip_layer = packet.getlayer(IP)
            protocol_name = "OTHER"
            dest_port = 0
            
            if packet.haslayer(TCP):
                protocol_name = "TCP"
                dest_port = packet.getlayer(TCP).dport
            elif packet.haslayer(UDP):
                protocol_name = "UDP"
                dest_port = packet.getlayer(UDP).dport

            behavior = {
                'timestamp': time.time(),
                'source_ip': ip_layer.src,
                'dest_port': dest_port,
                'packet_size': len(packet),
                'protocol': protocol_name,
                'request_rate': self._calculate_request_rate_real(ip_layer.src),
                'session_duration': 0, # Placeholder for real flow analysis
                'behavior_pattern': f"{protocol_name}_Activity",
                'connection_frequency': self._get_connection_frequency(),
                'payload_pattern': self._analyze_payload_real(packet),
                'ports_accessed': len(self.blocked_ips) # Using blocked_ips as a crude proxy for tracked state
            }
            
            # Simple heuristic for behavior pattern
            if dest_port in [80, 443]: behavior['behavior_pattern'] = "Web_Traffic"
            elif dest_port == 22: behavior['behavior_pattern'] = "SSH_Access"
            elif dest_port == 21: behavior['behavior_pattern'] = "FTP_Access"
            
            return behavior
        except Exception as e:
            # Fallback for simulated packets (from original code)
            if isinstance(packet, dict):
                return {
                    'timestamp': time.time(),
                    'dest_port': packet.get('dest_port', 0),
                    'packet_size': packet.get('packet_size', 0),
                    'protocol': packet.get('protocol', 'unknown'),
                    'request_rate': 1.0,
                    'session_duration': packet.get('session_duration', 0),
                    'behavior_pattern': packet.get('behavior_type', 'normal'),
                    'connection_frequency': 1.0,
                    'payload_pattern': "Normal",
                    'ports_accessed': 1
                }
            return None

    def _learn_from_behavior(self, behavior, original_packet):
        """يتعلم من التصرفات الجديدة"""
        self.normal_behavior_db.append(behavior)
        self.recent_behaviors.append(behavior)

        elapsed = time.time() - self.learning_start_time
        remaining = max(0, self.learning_duration - elapsed)

        # عرض تقدم التعلم كل 30 ثانية
        if int(elapsed) % 30 == 0 and int(elapsed) > 0:
            print(f"📚 Learning: {len(self.normal_behavior_db)} behaviors - {int(remaining/60)}m {int(remaining%60)}s remaining")

        # تحقق إذا انتهى وقت التعلم
        if elapsed >= self.learning_duration:
            self._switch_to_detection_mode()
            return "learning_complete"

        return "learning"

    def set_learning_duration(self, seconds):
        """Updates the learning duration and resets the start timer if currently learning"""
        self.learning_duration = seconds
        if self.learning_mode:
            self.learning_start_time = time.time()
            print(f"🕒 Learning duration updated to {seconds}s. Timer reset.")

    def activate_protection(self):
        """Manually switch to protection mode and train the model"""
        if len(self.normal_behavior_db) < 50:
            return False
            
        success = self._train_detection_model()
        if success:
            self.learning_mode = False
            print("🛡️ PROTECTION ACTIVATED")
            return True
        return False

    def _switch_to_detection_mode(self):
        """Standard automatic switch logic"""
        success = self.activate_protection()
        if not success:
            print("❌ Training failed, extending learning time")
            self.learning_mode = True
            self.learning_start_time = time.time()

    def _train_detection_model(self):
        """يدرب نموذج الكشف على البيانات المجمعة"""
        if len(self.normal_behavior_db) < 50:
            print(f"⚠️ Not enough data ({len(self.normal_behavior_db)} samples). Need at least 50.")
            return False

        print(f"🤖 Training detection model on {len(self.normal_behavior_db)} normal behaviors...")

        try:
            # تحويل البيانات لميزات رقمية
            features = self._prepare_features_for_training()

            # تدريب Isolation Forest
            self.detection_model = IsolationForest(
                n_estimators=100,
                contamination=0.05,  # 5% متوقع أن يكون شاذ
                random_state=42,
                verbose=1
            )
            self.detection_model.fit(features)

            print(f"✅ Model trained successfully!")
            print(f"📊 Model features: {len(features[0])} behavioral features")
            return True

        except Exception as e:
            print(f"❌ Training failed: {e}")
            return False

    def _detect_anomalies(self, behavior, original_packet):
        """يكشف التصرفات الشاذة"""
        if self.detection_model is None:
            return "allow"

        try:
            features = self._behavior_to_features(behavior)
            prediction = self.detection_model.predict([features])
            anomaly_score = self.detection_model.decision_function([features])

            is_anomaly = prediction[0] == -1

            if is_anomaly:
                self._handle_suspicious_behavior(behavior, original_packet, anomaly_score[0])
                return "block"
            else:
                return "allow"

        except Exception as e:
            print(f"❌ Detection error: {e}")
            return "allow"

    def unblock_ip(self, ip):
        """Removes an IP from the blocked list"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            print(f"🔓 IP {ip} has been manually ALLOWED")
            return True
        return False

    def _handle_suspicious_behavior(self, behavior, packet, anomaly_score):
        """يتعامل مع التصرف المشبوه"""
        # Scapy packets don't have .get(), they are objects.
        # Fallback to behavior dictionary if packet is Scapy object
        source_ip = behavior.get('source_ip', 'unknown')
        if source_ip == 'unknown' and hasattr(packet, 'haslayer'):
            from scapy.layers.inet import IP
            if packet.haslayer(IP):
                source_ip = packet[IP].src

        alert_msg = f"SUSPICIOUS BEHAVIOR DETECTED - Source: {source_ip} - Anomaly Score: {anomaly_score:.3f}"

        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'message': alert_msg,
            'source_ip': source_ip,
            'score': float(anomaly_score),
            'action': 'blocked',
            'details': f"Port: {behavior['dest_port']}, Pattern: {behavior['behavior_pattern']}, Protocol: {behavior['protocol']}",
            'behavior_type': behavior['behavior_pattern']
        }

        self.alerts.append(alert_data)
        self.blocked_ips.add(source_ip)

        print(f"🚨 {alert_msg}")
        print(f"🔒 Blocking IP: {source_ip}")

    def _analyze_behavior_pattern(self, packet):
        """Analyzes behavior pattern based on ports and frequency"""
        port = packet.get('dest_port', 0)
        if port == 21: return "FTP_Activity"
        if port == 22: return "SSH_Activity"
        if port in [80, 443]: return "Web_Activity"
        return "Generic_Network_Activity"

    def _get_connection_frequency(self):
        """Calculates connection frequency in the network"""
        if len(self.recent_behaviors) < 2:
            return 1.0
        time_span = self.recent_behaviors[-1]['timestamp'] - self.recent_behaviors[0]['timestamp']
        return len(self.recent_behaviors) / max(time_span, 1.0)

    def _calculate_request_rate_real(self, ip):
        """Calculates request rate for a specific IP based on recent behaviors"""
        recent_ip_traffic = [
            b for b in self.recent_behaviors
            if b.get('source_ip') == ip
        ]

        if len(recent_ip_traffic) < 2:
            return 1.0

        time_span = time.time() - recent_ip_traffic[0]['timestamp']
        return len(recent_ip_traffic) / max(time_span, 1.0)

    def _analyze_payload_real(self, packet):
        """Analyzes internal packet payload for malicious patterns"""
        from scapy.layers.inet import TCP, UDP
        payload = ""
        
        if packet.haslayer(TCP):
            payload = str(packet.getlayer(TCP).payload)
        elif packet.haslayer(UDP):
            payload = str(packet.getlayer(UDP).payload)
            
        malicious_patterns = [
            'sql', 'SELECT', 'UNION', 'OR 1=1', 'script', 'alert', 
            '/etc/passwd', 'cmd.exe', 'bin/sh', 'exploit', 'nmap'
        ]
        
        for pattern in malicious_patterns:
            if pattern.lower() in payload.lower():
                return f"Potential_{pattern}_Attack"
                
        if len(payload) > 1400:
            return "Large_Payload"
            
        return "Normal_Payload"

    def _prepare_features_for_training(self):
        """يحضر البيانات للتدريب"""
        features = []
        for behavior in self.normal_behavior_db:
            try:
                features.append(self._behavior_to_features(behavior))
            except:
                continue
        return np.array(features)

    def _behavior_to_features(self, behavior):
        """يحول التصرف لميزات رقمية"""
        protocol_hash = hash(behavior['protocol']) % 100
        pattern_hash = hash(behavior['behavior_pattern']) % 100
        payload_hash = hash(behavior['payload_pattern']) % 100

        return [
            behavior['dest_port'],
            behavior['packet_size'],
            behavior['request_rate'],
            behavior['session_duration'],
            behavior['connection_frequency'],
            behavior['ports_accessed'],
            protocol_hash,
            pattern_hash,
            payload_hash
        ]

    def get_stats(self):
        """إرجاع إحصائيات النظام"""
        elapsed = time.time() - self.learning_start_time
        remaining = max(0, self.learning_duration - elapsed)

        return {
            'learning_mode': self.learning_mode,
            'normal_behaviors': len(self.normal_behavior_db),
            'alerts_count': len(self.alerts),
            'blocked_ips_count': len(self.blocked_ips),
            'total_packets': self.total_packets_analyzed,
            'model_trained': self.detection_model is not None,
            'learning_time_elapsed': int(elapsed),
            'learning_time_remaining': int(remaining),
            'learning_progress': min(1.0, elapsed / self.learning_duration)
        }

    def get_recent_alerts(self, count=10):
        """إرجاع آخر التنبيهات"""
        return self.alerts[-count:]

    def save_trained_agent(self, file_path="trained_agent.pkl"):
        """يحفظ الـ Agent المدرب"""
        if self.detection_model is None:
            print("⚠️ Cannot save: Model is not trained yet!")
            return False

        agent_data = {
            'detection_model': self.detection_model,
            'normal_behavior_db': self.normal_behavior_db,
            'learning_complete': not self.learning_mode,
            'training_time': datetime.now().isoformat(),
            'total_behaviors_learned': len(self.normal_behavior_db)
        }
        joblib.dump(agent_data, file_path)
        print(f"💾 Agent saved to {file_path}")
        print(f"📊 Total behaviors learned: {len(self.normal_behavior_db)}")

    def load_trained_agent(self, file_path="trained_agent.pkl"):
        """يحمل الـ Agent المدرب"""
        try:
            agent_data = joblib.load(file_path)
            self.detection_model = agent_data['detection_model']
            self.normal_behavior_db = agent_data['normal_behavior_db']
            self.learning_mode = not agent_data['learning_complete']
            print("📂 Trained agent loaded successfully!")
            print(f"🎯 Behaviors in memory: {len(self.normal_behavior_db)}")
            return True
        except Exception as e:
            print(f"❌ Failed to load agent: {e}")
            return False