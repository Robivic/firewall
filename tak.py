import subprocess
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext


class SecurityTool:
    def __init__(self, smtp_server, smtp_user, smtp_password, report_file="security_report.txt"):
        self.vulnerabilities = []
        self.report_file = report_file
        self.smtp_server = smtp_server
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password

    def scan_system(self):
        """Simulate a system scan for vulnerabilities."""
        try:
            print("Scanning for vulnerabilities...")
            result = subprocess.run(['echo', 'Scanning...'], capture_output=True, text=True)
            print(result.stdout)
            self.vulnerabilities.append("Example Vulnerability: Outdated Software")
            self.generate_report()
        except Exception as e:
            print(f"Error during system scan: {e}")

    def generate_report(self):
        """Generate a report of the found vulnerabilities."""
        try:
            with open(self.report_file, 'a') as file:
                file.write(f"Scan Date: {datetime.now()}\n")
                if self.vulnerabilities:
                    file.write("Vulnerabilities Found:\n")
                    for vulnerability in self.vulnerabilities:
                        file.write(f"- {vulnerability}\n")
                else:
                    file.write("No vulnerabilities found.\n")
                file.write("\n")
            return f"Report generated: {self.report_file}"
        except IOError as e:
            return f"Error writing report: {e}"

    def send_alert(self, message):
        """Send an alert email."""
        try:
            msg = MIMEText(message)
            msg['Subject'] = 'Security Alert'
            msg['From'] = self.smtp_user
            msg['To'] = self.smtp_user  # Change to the recipient's email

            with smtplib.SMTP(self.smtp_server) as server:
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            return "Alert sent successfully."
        except Exception as e:
            return f"Error sending alert: {e}"


class SecurityToolGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Security Tool")
        self.tool = SecurityTool('smtp.example.com', 'your_email@example.com', 'your_password')

        # Create widgets
        self.create_widgets()

    def create_widgets(self):
        # Scan button
        self.scan_button = tk.Button(self.master, text="Scan System", command=self.scan)
        self.scan_button.pack(pady=10)

        # Report display area
        self.report_area = scrolledtext.ScrolledText(self.master, width=50, height=15)
        self.report_area.pack(pady=10)

        # Exit button
        self.exit_button = tk.Button(self.master, text="Exit", command=self.master.quit)
        self.exit_button.pack(pady=10)

    def scan(self):
        """Scan the system and display the results."""
        self.tool.scan_system()
        report_message = self.tool.generate_report()
        self.report_area.insert(tk.END, report_message + "\n")
        self.report_area.insert(tk.END, "Vulnerabilities Found:\n")
        for vulnerability in self.tool.vulnerabilities:
            self.report_area.insert(tk.END, f"- {vulnerability}\n")
        self.report_area.insert(tk.END, "\n")

        # Simulate sending an alert
        alert_message = self.tool.send_alert("Alert: Vulnerabilities found during the scan.")
        self.report_area.insert(tk.END, alert_message + "\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityToolGUI(root)
    root.mainloop()
