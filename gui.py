import flet as ft
import time
import threading
from datetime import datetime
import os

class SecurityDashboard:
    def __init__(self, ai_agent):
        self.ai_agent = ai_agent
        self.page = None
        self.sniff_thread = None
        
        # --- UI References ---
        self.status_text = ft.Text("SYSTEM INITIALIZING...", size=18, weight=ft.FontWeight.BOLD)
        self.learning_progress = ft.ProgressBar(width=400, color=ft.colors.CYAN_400, bgcolor=ft.colors.GREY_900)
        self.time_text = ft.Text("00:00:00", size=14, color=ft.colors.CYAN_200)
        self.alerts_list = ft.ListView(expand=True, spacing=10, padding=10)
        self.blocked_ips_list = ft.ListView(expand=True, spacing=10, padding=10)
        
        # File Picker for Loading Models
        self.file_picker = ft.FilePicker(on_result=self._on_file_result)

    def create_dashboard(self, page: ft.Page):
        self.page = page
        page.title = "AI SOC SENTINEL - Fares Benatmane"
        page.theme_mode = ft.ThemeMode.DARK
        page.padding = 0  # We use a container for padding
        page.window_width = 1300
        page.window_height = 900
        page.overlay.append(self.file_picker)
        
        # --- Custom Colors/Styles ---
        neon_blue = "#00f2ff"
        neon_green = "#39ff14"
        dark_bg = "#0a0b10"
        glass_effect = ft.colors.with_opacity(0.1, ft.colors.WHITE)

        # --- Header ---
        header = ft.Container(
            content=ft.Row([
                ft.Row([
                    ft.Icon(ft.icons.SHIELD, color=neon_blue, size=40),
                    ft.Column([
                        ft.Text("AI SOC SENTINEL", size=24, weight=ft.FontWeight.BOLD, color=ft.colors.WHITE),
                        ft.Text("NEXT-GEN CYBER DEFENSE UNIT", size=10, color=ft.colors.BLUE_200),
                    ], spacing=0)
                ]),
                ft.Row([
                    ft.Container(
                        content=ft.Text("OPERATOR: FARES BENATMANE", size=12, weight=ft.FontWeight.W_500, color=neon_blue),
                        padding=ft.padding.all(10),
                        border=ft.border.all(1, neon_blue),
                        border_radius=5
                    )
                ])
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            padding=30,
            bgcolor=ft.colors.with_opacity(0.05, ft.colors.BLACK)
        )

        # --- Sidebar Navigation ---
        def on_tab_change(e):
            tabs = [dashboard_view, models_view, security_wall_view]
            for i, view in enumerate(tabs):
                view.visible = (i == e.control.selected_index)
            page.update()

        nav_rail = ft.NavigationBar(
            destinations=[
                ft.NavigationDestination(icon=ft.icons.DASHBOARD, label="DASHBOARD"),
                ft.NavigationDestination(icon=ft.icons.STORAGE, label="MODEL ARCHIVE"),
                ft.NavigationDestination(icon=ft.icons.GPP_BAD, label="SECURITY WALL"),
            ],
            on_change=on_tab_change,
            bgcolor=ft.colors.TRANSPARENT,
            selected_index=0,
        )

        # --- Dashboard View (Home) ---
        self.packets_stat = self._create_stat_card("TRAFFIC FLOW", "0", ft.icons.SENSORS, ft.colors.CYAN_400)
        self.behaviors_stat = self._create_stat_card("PATTERNS MAPPED", "0", ft.icons.HUB, ft.colors.GREEN_400)
        self.alerts_stat = self._create_stat_card("THREAT VECTORS", "0", ft.icons.WARNING_AMBER, ft.colors.RED_400)
        self.blocked_stat = self._create_stat_card("ISOLATED NODES", "0", ft.icons.BLOCK, ft.colors.ORANGE_400)

        self.duration_dropdown = ft.Dropdown(
            label="Capture Duration",
            value="3600",
            options=[
                ft.dropdown.Option("60", "1 Minute (TEST)"),
                ft.dropdown.Option("300", "5 Minutes"),
                ft.dropdown.Option("3600", "1 Hour"),
                ft.dropdown.Option("86400", "24 Hours"),
            ],
            on_change=self._on_duration_change
        )

        controls = ft.Container(
            content=ft.Column([
                ft.Text("CONTROL CONSOLE", size=14, weight=ft.FontWeight.BOLD, color=ft.colors.GREY_400),
                ft.Row([
                    ft.ElevatedButton("START LEARNING", icon=ft.icons.PLAY_CIRCLE, on_click=self._toggle_learning_mode, style=ft.ButtonStyle(bgcolor=ft.colors.BLUE_900)),
                    ft.ElevatedButton("ACTIVATE DEFENSE", icon=ft.icons.SECURITY, on_click=self._toggle_protection_mode, style=ft.ButtonStyle(bgcolor=ft.colors.GREEN_900)),
                ], spacing=10),
                self.duration_dropdown
            ]),
            padding=20, border_radius=15, bgcolor=glass_effect
        )

        dashboard_view = ft.Column([
            ft.Row([
                ft.Container(
                    content=ft.Column([
                        ft.Row([ft.Icon(ft.icons.RADAR, color=neon_blue), self.status_text]),
                        self.learning_progress,
                        self.time_text
                    ]),
                    padding=25, bgcolor=glass_effect, border_radius=20, expand=True
                ),
                controls
            ], spacing=20),
            ft.Row([self.packets_stat, self.behaviors_stat, self.alerts_stat, self.blocked_stat], spacing=20),
            ft.Container(
                content=ft.Column([
                    ft.Text("LIVE SECURITY FEED", weight=ft.FontWeight.BOLD, color=ft.colors.GREY_400),
                    self.alerts_list
                ]),
                padding=20, bgcolor=glass_effect, border_radius=20, expand=True
            )
        ], visible=True, spacing=20, expand=True)

        # --- Models View ---
        models_view = ft.Column([
            ft.Text("MODEL ARCHIVE MANAGEMENT", size=24, weight=ft.FontWeight.BOLD),
            ft.Text("Select and load intelligence models into the active agent.", color=ft.colors.GREY_500),
            ft.Row([
                ft.ElevatedButton("BROWSE MODELS", icon=ft.icons.FOLDER_OPEN, on_click=lambda _: self.file_picker.pick_files(allowed_extensions=["pkl"])),
                ft.ElevatedButton("SAVE ACTIVE MODEL", icon=ft.icons.SAVE_ALT, on_click=self._on_save_agent_click, bgcolor=ft.colors.AMBER_900),
            ], spacing=20),
            ft.Container(
                content=ft.Text("No external models loaded. System is using current memory state.", color=ft.colors.GREY_600),
                padding=40, border=ft.border.all(1, ft.colors.GREY_800), border_radius=10, alignment=ft.alignment.center
            )
        ], visible=False, spacing=30, expand=True)

        # --- Security Wall View ---
        security_wall_view = ft.Column([
            ft.Text("IP ISOLATION PROTOCOLS", size=24, weight=ft.FontWeight.BOLD),
            ft.Text("Manage blocked traffic and manually override security decisions.", color=ft.colors.GREY_500),
            ft.Container(
                content=self.blocked_ips_list,
                padding=20, bgcolor=glass_effect, border_radius=20, expand=True
            )
        ], visible=False, spacing=20, expand=True)

        # --- Layout Assembly ---
        page.add(
            ft.Container(
                content=ft.Column([
                    header,
                    ft.Container(
                        content=ft.Stack([
                            dashboard_view,
                            models_view,
                            security_wall_view
                        ]),
                        padding=30,
                        expand=True
                    ),
                    nav_rail
                ]),
                bgcolor=dark_bg,
                expand=True
            )
        )

        threading.Thread(target=self._update_loop, daemon=True).start()

    def _create_stat_card(self, label, value, icon, color):
        return ft.Container(
            content=ft.Column([
                ft.Icon(icon, color=color, size=30),
                ft.Text(value, size=28, weight=ft.FontWeight.BOLD, color=ft.colors.WHITE),
                ft.Text(label, size=10, weight=ft.FontWeight.W_300, color=ft.colors.GREY_500),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
            padding=20, bgcolor=ft.colors.with_opacity(0.03, color), border_radius=15, expand=True,
            border=ft.border.all(1, ft.colors.with_opacity(0.1, color))
        )

    def _start_capture_if_needed(self):
        if self.sniff_thread is None or not self.sniff_thread.is_alive():
            from main import start_sniffing
            self.sniff_thread = threading.Thread(target=start_sniffing, args=(self.ai_agent,), daemon=True)
            self.sniff_thread.start()

    def _toggle_learning_mode(self, e):
        self._start_capture_if_needed()
        self.ai_agent.learning_mode = True
        self._show_info("NEURAL LEARNING ENGAGED")

    def _toggle_protection_mode(self, e):
        self._start_capture_if_needed()
        if self.ai_agent.activate_protection():
            self._show_info("CYBER DEFENSE SHIELDS ACTIVE")
        else:
            self._show_error("INSUFFICIENT DATA FOR DEFENSE MODE")

    def _on_save_agent_click(self, e):
        if self.ai_agent.save_trained_agent("trained_agent.pkl"):
            self._show_info("MODEL SYNCED TO DISK")
        else:
            self._show_error("SYNC FAILED: MODEL NOT READY")

    def _on_file_result(self, e: ft.FilePickerResultEvent):
        if e.files:
            file_path = e.files[0].path
            if self.ai_agent.load_trained_agent(file_path):
                self._show_info(f"MODEL LOADED: {os.path.basename(file_path)}")
                self._start_capture_if_needed()
            self.page.update()

    def _on_duration_change(self, e):
        self.ai_agent.set_learning_duration(int(self.duration_dropdown.value))
        self._show_info(f"LEARNING CYCLE UPDATED: {self.duration_dropdown.value}s")

    def _unblock_ip_clicked(self, ip):
        if self.ai_agent.unblock_ip(ip):
            self._show_info(f"IP {ip} AUTHORIZED")
        self.page.update()

    def _show_info(self, msg):
        self.page.snack_bar = ft.SnackBar(ft.Text(msg), bgcolor=ft.colors.BLUE_700)
        self.page.snack_bar.open = True
        self.page.update()

    def _show_error(self, msg):
        self.page.snack_bar = ft.SnackBar(ft.Text(msg), bgcolor=ft.colors.RED_700)
        self.page.snack_bar.open = True
        self.page.update()

    def _update_loop(self):
        while True:
            try:
                if not self.page:
                    time.sleep(1)
                    continue

                stats = self.ai_agent.get_stats()
                
                # Update Status
                if hasattr(self.ai_agent, 'last_error') and self.ai_agent.last_error:
                    self.status_text.value = "CRITICAL: NETWORK CAPTURE FAILURE"
                    self.status_text.color = ft.colors.RED_400
                elif stats['learning_mode']:
                    self.status_text.value = "NEURAL MAPPING IN PROGRESS..."
                    self.status_text.color = ft.colors.CYAN_400
                    self.learning_progress.value = stats['learning_progress']
                else:
                    self.status_text.value = "ACTIVE DEFENSE SYSTEM ONLINE"
                    self.status_text.color = ft.colors.GREEN_400
                    self.learning_progress.value = 1.0

                # Update Stats
                self.packets_stat.content.controls[1].value = str(stats['total_packets'])
                self.behaviors_stat.content.controls[1].value = str(stats['normal_behaviors'])
                self.alerts_stat.content.controls[1].value = str(stats['alerts_count'])
                self.blocked_stat.content.controls[1].value = str(stats['blocked_ips_count'])

                # Update Alerts
                recent_alerts = self.ai_agent.get_recent_alerts(15)
                self.alerts_list.controls.clear()
                for alert in reversed(recent_alerts):
                    self.alerts_list.controls.append(
                        ft.Container(
                            content=ft.Row([
                                ft.Icon(ft.icons.BOLT, color=ft.colors.RED_400 if alert['score'] < -0.1 else ft.colors.ORANGE_400),
                                ft.Column([
                                    ft.Text(f"INTRUSION ATTEMPT: {alert['source_ip']}", weight=ft.FontWeight.BOLD, size=12),
                                    ft.Text(f"{alert['details']}", size=10, color=ft.colors.GREY_500),
                                ], expand=True),
                                ft.Text(alert['timestamp'][11:19], size=10, color=ft.colors.GREY_600)
                            ]),
                            padding=12, bgcolor=ft.colors.with_opacity(0.05, ft.colors.BLACK), border_radius=10
                        )
                    )

                # Update Security Wall
                self.blocked_ips_list.controls.clear()
                if not self.ai_agent.blocked_ips:
                    self.blocked_ips_list.controls.append(ft.Text("NO ACTIVE THREATS ISOLATED", color=ft.colors.GREY_700, text_align=ft.TextAlign.CENTER))
                else:
                    for ip in list(self.ai_agent.blocked_ips):
                        self.blocked_ips_list.controls.append(
                            ft.Container(
                                content=ft.Row([
                                    ft.Icon(ft.icons.ERROR_OUTLINE, color=ft.colors.ORANGE_ACCENT_700),
                                    ft.Text(f"BLOCKED IP: {ip}", expand=True, weight=ft.FontWeight.BOLD),
                                    ft.ElevatedButton("AUTHORIZE IP", icon=ft.icons.CHECK, on_click=lambda _, i=ip: self._unblock_ip_clicked(i), style=ft.ButtonStyle(bgcolor=ft.colors.GREEN_900))
                                ]),
                                padding=15, bgcolor=ft.colors.with_opacity(0.1, ft.colors.RED_900), border_radius=10
                            )
                        )

                self.page.update()
            except Exception as e:
                print(f"UI Error: {e}")
            time.sleep(1)
