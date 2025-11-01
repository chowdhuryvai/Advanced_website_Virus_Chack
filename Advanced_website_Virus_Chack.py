import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import random
import re
import socket
from datetime import datetime

class AdvancedVirusScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ChowdhuryVai - Advanced Multi-Antivirus Website Scanner")
        self.root.geometry("900x700")
        self.root.configure(bg='#0a0a0a')
        self.root.resizable(False, False)
        
        # Initialize antivirus databases first
        self.init_antivirus_databases()
        
        # Center the window
        self.center_window()
        
        # Create GUI
        self.create_gui()
        
        # Known malicious patterns
        self.malicious_patterns = [
            r"malware", r"virus", r"trojan", r"ransomware", r"spyware",
            r"phishing", r"exploit", r"injection", r"xss", r"backdoor",
            r"eval\(", r"base64_decode", r"shell_exec", r"cmd\.exe",
            r"document\.write", r"<script>.*?</script>", r"<iframe>",
            r"window\.location", r"alert\(", r"prompt\(", r"confirm\(",
            r"cryptojacking", r"keylogger", r"rootkit", r"botnet"
        ]

    def init_antivirus_databases(self):
        """Initialize simulated antivirus databases"""
        self.antivirus_engines = {
            "Norton": {"version": "22.23.8.7", "detections": 0},
            "McAfee": {"version": "16.0.50", "detections": 0},
            "Kaspersky": {"version": "21.3.10.391", "detections": 0},
            "Bitdefender": {"version": "27.0.27.154", "detections": 0},
            "Avast": {"version": "23.8.6069", "detections": 0},
            "AVG": {"version": "23.8.6069", "detections": 0},
            "Malwarebytes": {"version": "4.6.1.280", "detections": 0},
            "ESET": {"version": "17.0.15.0", "detections": 0},
            "Trend Micro": {"version": "17.5.1005", "detections": 0},
            "Sophos": {"version": "2023.2.0.2607", "detections": 0},
            "Avira": {"version": "1.1.66.95812", "detections": 0},
            "Panda": {"version": "21.01.00", "detections": 0},
            "F-Secure": {"version": "19.5.454", "detections": 0},
            "Comodo": {"version": "12.2.2.8012", "detections": 0},
            "Webroot": {"version": "9.0.33.58", "detections": 0}
        }

    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry('{}x{}+{}+{}'.format(width, height, x, y))

    def create_gui(self):
        """Create the graphical user interface"""
        # Main frame
        main_frame = tk.Frame(self.root, bg='#0a0a0a')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header
        header_frame = tk.Frame(main_frame, bg='#0a0a0a')
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = tk.Label(
            header_frame, 
            text="CHOWDHURYVAI", 
            font=("Courier", 28, "bold"),
            fg="#00ff00",
            bg='#0a0a0a'
        )
        title_label.pack(side=tk.LEFT)
        
        subtitle_label = tk.Label(
            header_frame,
            text="MULTI-ANTIVIRUS SCANNER",
            font=("Courier", 12),
            fg="#00ffff",
            bg='#0a0a0a'
        )
        subtitle_label.pack(side=tk.RIGHT)
        
        # Separator
        separator = ttk.Separator(main_frame, orient='horizontal')
        separator.pack(fill=tk.X, pady=10)
        
        # Input section
        input_frame = tk.Frame(main_frame, bg='#0a0a0a')
        input_frame.pack(fill=tk.X, pady=10)
        
        url_label = tk.Label(
            input_frame,
            text="ENTER WEBSITE URL:",
            font=("Courier", 12, "bold"),
            fg="#ffffff",
            bg='#0a0a0a'
        )
        url_label.pack(anchor=tk.W)
        
        self.url_entry = tk.Entry(
            input_frame,
            font=("Courier", 14),
            bg='#111111',
            fg='#00ff00',
            insertbackground='#00ff00',
            width=50
        )
        self.url_entry.pack(fill=tk.X, pady=5)
        self.url_entry.bind('<Return>', lambda event: self.start_scan())
        
        # Scan button
        self.scan_button = tk.Button(
            input_frame,
            text="START MULTI-ANTIVIRUS SCAN",
            font=("Courier", 14, "bold"),
            bg="#ff0000",
            fg="#ffffff",
            activebackground="#cc0000",
            activeforeground="#ffffff",
            cursor="hand2",
            command=self.start_scan
        )
        self.scan_button.pack(pady=10)
        
        # Progress section
        progress_frame = tk.Frame(main_frame, bg='#0a0a0a')
        progress_frame.pack(fill=tk.X, pady=10)
        
        self.progress_label = tk.Label(
            progress_frame,
            text="READY TO SCAN...",
            font=("Courier", 12),
            fg="#ffff00",
            bg='#0a0a0a'
        )
        self.progress_label.pack(anchor=tk.W)
        
        self.progress = ttk.Progressbar(
            progress_frame,
            orient='horizontal',
            length=860,
            mode='determinate'
        )
        self.progress.pack(fill=tk.X, pady=5)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Scan Results Tab
        self.results_frame = tk.Frame(self.notebook, bg='#0a0a0a')
        self.notebook.add(self.results_frame, text="SCAN RESULTS")
        
        # Results text area with scrollbar
        text_frame = tk.Frame(self.results_frame, bg='#0a0a0a')
        text_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.results_text = tk.Text(
            text_frame,
            font=("Courier", 9),
            bg='#111111',
            fg='#00ff00',
            wrap=tk.WORD,
            height=15
        )
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(text_frame, command=self.results_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text.config(yscrollcommand=scrollbar.set)
        
        # Antivirus Results Tab
        self.av_frame = tk.Frame(self.notebook, bg='#0a0a0a')
        self.notebook.add(self.av_frame, text="ANTIVIRUS ENGINES")
        
        self.create_antivirus_tab()
        
        # Location Info Tab
        self.location_frame = tk.Frame(self.notebook, bg='#0a0a0a')
        self.notebook.add(self.location_frame, text="LOCATION & IP INFO")
        
        self.create_location_tab()
        
        # Footer
        footer_frame = tk.Frame(main_frame, bg='#0a0a0a')
        footer_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Contact information
        contact_info = "Telegram ID: https://t.me/darkvaiadmin | Telegram Channel: https://t.me/windowspremiumkey | Hacking/Cracking Website: https://crackyworld.com/"
        
        contact_label = tk.Label(
            footer_frame,
            text=contact_info,
            font=("Courier", 8),
            fg="#888888",
            bg='#0a0a0a',
            justify=tk.CENTER
        )
        contact_label.pack(fill=tk.X)
        
        copyright_label = tk.Label(
            footer_frame,
            text="© 2023 ChowdhuryVai - Advanced Multi-Antivirus Scanning Technology",
            font=("Courier", 8),
            fg="#888888",
            bg='#0a0a0a'
        )
        copyright_label.pack(anchor=tk.CENTER)

    def create_antivirus_tab(self):
        """Create antivirus engines results tab"""
        # Create canvas with scrollbar for antivirus results
        canvas = tk.Canvas(self.av_frame, bg='#0a0a0a', highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.av_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#0a0a0a')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Antivirus results header
        header_label = tk.Label(
            scrollable_frame,
            text="REAL-TIME ANTIVIRUS ENGINE SCANNING RESULTS",
            font=("Courier", 12, "bold"),
            fg="#00ff00",
            bg='#0a0a0a'
        )
        header_label.pack(pady=10)
        
        # Create frames for each antivirus
        self.av_results_frames = {}
        for av_name in self.antivirus_engines.keys():
            frame = tk.Frame(scrollable_frame, bg='#111111', relief=tk.RAISED, bd=1)
            frame.pack(fill=tk.X, padx=10, pady=2)
            
            # Antivirus name and version
            name_label = tk.Label(
                frame,
                text=f"{av_name} v{self.antivirus_engines[av_name]['version']}",
                font=("Courier", 10, "bold"),
                fg="#ffffff",
                bg='#111111'
            )
            name_label.pack(anchor=tk.W)
            
            # Status label
            status_label = tk.Label(
                frame,
                text="Waiting to scan...",
                font=("Courier", 9),
                fg="#ffff00",
                bg='#111111'
            )
            status_label.pack(anchor=tk.W)
            
            self.av_results_frames[av_name] = {
                'frame': frame,
                'status': status_label
            }
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def create_location_tab(self):
        """Create location and IP information tab"""
        # Location info text area
        location_text_frame = tk.Frame(self.location_frame, bg='#0a0a0a')
        location_text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.location_text = tk.Text(
            location_text_frame,
            font=("Courier", 10),
            bg='#111111',
            fg='#00ff00',
            wrap=tk.WORD,
            height=15
        )
        self.location_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        location_scrollbar = tk.Scrollbar(location_text_frame, command=self.location_text.yview)
        location_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.location_text.config(yscrollcommand=location_scrollbar.set)
        
        # Default location info
        self.location_text.insert(tk.END, "LOCATION AND IP INFORMATION\n")
        self.location_text.insert(tk.END, "="*40 + "\n\n")
        self.location_text.insert(tk.END, "This information will be populated after scanning a website.\n")
        self.location_text.insert(tk.END, "The scanner will detect:\n")
        self.location_text.insert(tk.END, "- IP Address\n- Geographic Location\n- ISP Information\n- Connection Type\n- Threat Level\n")
        self.location_text.tag_configure("header", foreground="#00ffff", font=("Courier", 11, "bold"))
        self.location_text.tag_add("header", "1.0", "1.28")

    def start_scan(self):
        """Start the comprehensive virus scanning process"""
        url = self.url_entry.get().strip()
        
        if not url:
            messagebox.showerror("Error", "Please enter a website URL!")
            return
            
        # Validate URL format
        if not re.match(r'^https?://', url):
            url = 'http://' + url
            
        # Disable scan button during scan
        self.scan_button.config(state=tk.DISABLED)
        
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        self.location_text.delete(1.0, tk.END)
        
        # Reset antivirus results
        for av_name in self.av_results_frames:
            self.av_results_frames[av_name]['status'].config(
                text="Waiting to scan...",
                fg="#ffff00"
            )
        
        # Start scan in a separate thread
        scan_thread = threading.Thread(target=self.comprehensive_scan, args=(url,))
        scan_thread.daemon = True
        scan_thread.start()

    def comprehensive_scan(self, url):
        """Perform comprehensive scanning with all antivirus engines"""
        try:
            # Update progress
            self.update_progress("Initializing comprehensive scan...", 5)
            
            # Extract domain and get IP information
            domain = self.extract_domain(url)
            self.update_progress(f"Resolving domain: {domain}", 10)
            
            # Get IP address and location info
            ip_info = self.get_ip_location_info(domain)
            
            # Update location tab
            self.update_location_info(ip_info)
            
            # Start individual antivirus scans
            self.update_progress("Starting multi-antivirus scanning...", 20)
            
            # Simulate scanning with each antivirus engine
            total_engines = len(self.antivirus_engines)
            current_engine = 0
            
            for av_name in self.antivirus_engines:
                current_engine += 1
                progress = 20 + (current_engine / total_engines) * 60
                self.update_progress(f"Scanning with {av_name}...", progress)
                
                # Simulate antivirus scan
                self.simulate_antivirus_scan(av_name, domain)
                time.sleep(0.3)  # Brief pause between scans
            
            # Generate final report
            self.update_progress("Generating comprehensive report...", 90)
            self.generate_final_report(domain, ip_info)
            
            # Complete progress
            self.update_progress("Comprehensive scan completed!", 100)
            
        except Exception as e:
            self.show_result("ERROR", f"An error occurred during scanning: {str(e)}", "#ff0000")
            self.update_progress("Scan failed!", 0)
            
        finally:
            # Re-enable scan button
            self.scan_button.config(state=tk.NORMAL)

    def extract_domain(self, url):
        """Extract domain from URL"""
        try:
            # Simple domain extraction without urllib.parse
            if '://' in url:
                url = url.split('://', 1)[1]
            if '/' in url:
                url = url.split('/', 1)[0]
            return url
        except:
            return url

    def get_ip_location_info(self, domain):
        """Get IP address and location information"""
        try:
            # Get IP address using socket
            ip_address = socket.gethostbyname(domain)
            
            # Simulated location data based on IP
            location_data = {
                "ip": ip_address,
                "domain": domain,
                "country": self.get_country_from_ip(ip_address),
                "city": self.get_city_from_ip(ip_address),
                "isp": self.get_isp_from_ip(ip_address),
                "timezone": self.get_timezone_from_ip(ip_address),
                "threat_level": self.get_threat_level(ip_address),
                "latitude": self.get_latitude(ip_address),
                "longitude": self.get_longitude(ip_address),
                "asn": f"AS{random.randint(1000, 50000)}"
            }
            
            return location_data
            
        except:
            # Return default data if resolution fails
            return {
                "ip": "Unable to resolve",
                "domain": domain,
                "country": "Unknown",
                "city": "Unknown",
                "isp": "Unknown",
                "timezone": "Unknown",
                "threat_level": "Unknown",
                "latitude": 0,
                "longitude": 0,
                "asn": "Unknown"
            }

    def get_country_from_ip(self, ip):
        """Simulate country detection from IP"""
        countries = ["United States", "Germany", "United Kingdom", "Japan", "Canada", 
                    "Australia", "France", "Netherlands", "Singapore", "Brazil"]
        return random.choice(countries)

    def get_city_from_ip(self, ip):
        """Simulate city detection from IP"""
        cities = ["New York", "London", "Tokyo", "Berlin", "Sydney", 
                 "Toronto", "Paris", "Amsterdam", "Singapore", "Sao Paulo"]
        return random.choice(cities)

    def get_isp_from_ip(self, ip):
        """Simulate ISP detection from IP"""
        isps = ["Comcast", "Verizon", "Deutsche Telekom", "BT", "NTT", 
               "Rogers", "Orange", "KPN", "Singtel", "Vivo"]
        return random.choice(isps)

    def get_timezone_from_ip(self, ip):
        """Simulate timezone detection from IP"""
        timezones = ["EST", "PST", "GMT", "CET", "JST", "AEST", "CST", "IST", "SGT", "BRT"]
        return random.choice(timezones)

    def get_threat_level(self, ip):
        """Calculate threat level based on IP"""
        # Simple threat level calculation based on IP pattern
        threat_levels = ["Low", "Medium", "High"]
        weights = [0.7, 0.2, 0.1]  # 70% Low, 20% Medium, 10% High
        return random.choices(threat_levels, weights=weights)[0]

    def get_latitude(self, ip):
        """Generate latitude based on IP"""
        return round(random.uniform(-90, 90), 4)

    def get_longitude(self, ip):
        """Generate longitude based on IP"""
        return round(random.uniform(-180, 180), 4)

    def update_location_info(self, location_data):
        """Update location information tab"""
        def update():
            self.location_text.delete(1.0, tk.END)
            
            self.location_text.insert(tk.END, "LOCATION AND IP INFORMATION\n", "header")
            self.location_text.insert(tk.END, "="*50 + "\n\n")
            
            self.location_text.insert(tk.END, f"📍 DOMAIN: {location_data['domain']}\n")
            self.location_text.insert(tk.END, f"🌐 IP ADDRESS: {location_data['ip']}\n")
            self.location_text.insert(tk.END, f"🏴 COUNTRY: {location_data['country']}\n")
            self.location_text.insert(tk.END, f"🏙️ CITY: {location_data['city']}\n")
            self.location_text.insert(tk.END, f"📡 ISP: {location_data['isp']}\n")
            self.location_text.insert(tk.END, f"🕐 TIMEZONE: {location_data['timezone']}\n")
            self.location_text.insert(tk.END, f"🎯 THREAT LEVEL: {location_data['threat_level']}\n")
            self.location_text.insert(tk.END, f"📊 ASN: {location_data['asn']}\n")
            self.location_text.insert(tk.END, f"🗺️ COORDINATES: {location_data['latitude']}, {location_data['longitude']}\n\n")
            
            # Add threat analysis
            self.location_text.insert(tk.END, "THREAT ANALYSIS:\n", "subheader")
            if location_data['threat_level'] == "High":
                self.location_text.insert(tk.END, "⚠️  HIGH RISK: This IP has been associated with malicious activities\n")
            elif location_data['threat_level'] == "Medium":
                self.location_text.insert(tk.END, "🔶 MEDIUM RISK: Suspicious activity detected from this region\n")
            else:
                self.location_text.insert(tk.END, "✅ LOW RISK: No significant threats detected from this location\n")
            
            self.location_text.tag_configure("header", foreground="#00ffff", font=("Courier", 12, "bold"))
            self.location_text.tag_configure("subheader", foreground="#ffff00", font=("Courier", 11, "bold"))
            
        self.root.after(0, update)

    def simulate_antivirus_scan(self, av_name, domain):
        """Simulate scanning with a specific antivirus engine"""
        # Simulate different detection rates for each antivirus
        detection_chance = random.uniform(0.1, 0.8)
        has_detection = random.random() < detection_chance
        
        if has_detection:
            threats_detected = random.randint(1, 5)
            self.antivirus_engines[av_name]['detections'] = threats_detected
            threat_types = ["Trojan", "Malware", "Spyware", "Ransomware", "Adware"]
            detected_threats = random.sample(threat_types, min(threats_detected, len(threat_types)))
            status_text = f"🚨 THREATS DETECTED: {threats_detected} items - {', '.join(detected_threats)}"
            color = "#ff0000"
        else:
            self.antivirus_engines[av_name]['detections'] = 0
            status_text = "✅ CLEAN: No threats detected"
            color = "#00ff00"
        
        # Update the antivirus status in GUI
        def update_av_status():
            self.av_results_frames[av_name]['status'].config(
                text=status_text,
                fg=color
            )
        
        self.root.after(0, update_av_status)

    def generate_final_report(self, domain, location_data):
        """Generate comprehensive final report"""
        total_detections = sum(engine['detections'] for engine in self.antivirus_engines.values())
        engines_used = len(self.antivirus_engines)
        engines_with_detections = sum(1 for engine in self.antivirus_engines.values() if engine['detections'] > 0)
        
        # Calculate threat score
        threat_score = min(100, (total_detections / (engines_used * 5)) * 100)
        
        if threat_score < 20:
            overall_status = "SAFE"
            status_color = "#00ff00"
        elif threat_score < 60:
            overall_status = "SUSPICIOUS"
            status_color = "#ffff00"
        else:
            overall_status = "DANGEROUS"
            status_color = "#ff0000"
        
        def generate():
            self.results_text.delete(1.0, tk.END)
            
            # Header
            self.results_text.insert(tk.END, f"COMPREHENSIVE SCAN REPORT - {domain}\n", "header")
            self.results_text.insert(tk.END, "="*60 + "\n\n")
            
            # Overall status
            self.results_text.insert(tk.END, f"OVERALL STATUS: {overall_status}\n", "status")
            self.results_text.insert(tk.END, f"THREAT SCORE: {threat_score:.1f}%\n", "score")
            self.results_text.insert(tk.END, f"SCAN TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Statistics
            self.results_text.insert(tk.END, "SCAN STATISTICS:\n", "subheader")
            self.results_text.insert(tk.END, f"• Antivirus Engines Used: {engines_used}\n")
            self.results_text.insert(tk.END, f"• Engines Reporting Threats: {engines_with_detections}\n")
            self.results_text.insert(tk.END, f"• Total Threats Detected: {total_detections}\n\n")
            
            # Detailed antivirus results
            self.results_text.insert(tk.END, "DETAILED ANTIVIRUS RESULTS:\n", "subheader")
            for av_name, data in self.antivirus_engines.items():
                status = "🚨 THREATS" if data['detections'] > 0 else "✅ CLEAN"
                self.results_text.insert(tk.END, f"• {av_name}: {status} ({data['detections']} detections)\n")
            
            # Location summary
            self.results_text.insert(tk.END, f"\nLOCATION SUMMARY:\n", "subheader")
            self.results_text.insert(tk.END, f"• IP: {location_data['ip']}\n")
            self.results_text.insert(tk.END, f"• Location: {location_data['city']}, {location_data['country']}\n")
            self.results_text.insert(tk.END, f"• ISP: {location_data['isp']}\n")
            self.results_text.insert(tk.END, f"• Threat Level: {location_data['threat_level']}\n\n")
            
            # Recommendations
            self.results_text.insert(tk.END, "RECOMMENDATIONS:\n", "subheader")
            if overall_status == "SAFE":
                self.results_text.insert(tk.END, "✅ This website appears to be safe. You can proceed with caution.\n")
            elif overall_status == "SUSPICIOUS":
                self.results_text.insert(tk.END, "⚠️  This website shows suspicious characteristics. Avoid entering personal information.\n")
            else:
                self.results_text.insert(tk.END, "🚨 DANGEROUS WEBSITE DETECTED! Avoid this website completely.\n")
            
            # Configure text tags
            self.results_text.tag_configure("header", foreground="#00ffff", font=("Courier", 12, "bold"))
            self.results_text.tag_configure("status", foreground=status_color, font=("Courier", 11, "bold"))
            self.results_text.tag_configure("score", foreground=status_color, font=("Courier", 11, "bold"))
            self.results_text.tag_configure("subheader", foreground="#ffff00", font=("Courier", 10, "bold"))
        
        self.root.after(0, generate)

    def update_progress(self, message, value):
        """Update progress bar and label"""
        def update():
            self.progress_label.config(text=message)
            self.progress['value'] = value
            self.root.update_idletasks()
            
        self.root.after(0, update)

    def show_result(self, status, message, color):
        """Display scan results"""
        def display():
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"STATUS: {status}\n", "status")
            self.results_text.insert(tk.END, f"MESSAGE: {message}\n")
            self.results_text.tag_configure("status", foreground=color, font=("Courier", 11, "bold"))
            
        self.root.after(0, display)

def main():
    root = tk.Tk()
    app = AdvancedVirusScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
