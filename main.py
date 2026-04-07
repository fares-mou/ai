import flet as ft
import time
import threading
import random
from datetime import datetime
from ai_agent import RealTimeAIAgent
from gui import SecurityDashboard
from scapy.all import sniff

def start_sniffing(ai_agent):
    """Starts real-world packet sniffing using Scapy with fallback"""
    print("📡 Starting Real Traffic Capture...")
    
    def packet_callback(packet):
        ai_agent.analyze_network_behavior(packet)

    try:
        sniff(prn=packet_callback, store=0)
    except Exception as e:
        print(f"⚠️ Capture Error: {e}")
        print("🔄 Attempting Layer 3 Fallback...")
        try:
            from scapy.all import conf, L3RawSocket
            conf.L3socket = L3RawSocket
            sniff(prn=packet_callback, store=0)
        except Exception as e2:
            error_msg = f"CRITICAL: Packet capture failed. Please install Npcap: {e2}"
            print(error_msg)
            ai_agent.last_error = error_msg

def main():
    print("🚀 Starting AI Network Security Agent")
    print("👨‍💻 Developed by Fares Benatmane")
    print("=" * 50)

    # Initialize AI Agent (Neutral State - NOT learning yet)
    ai_agent = RealTimeAIAgent()
    ai_agent.learning_mode = False 

    print("✅ AI Agent Engine Initialized")
    print("💻 Launching SOC Dashboard...")
    print("💡 Click 'START LEARNING' in the GUI to begin traffic analysis.")

    # Start GUI - The GUI will now handle starting the sniffing thread and mode switching
    dashboard = SecurityDashboard(ai_agent)
    ft.app(target=dashboard.create_dashboard)

if __name__ == "__main__":
    main()