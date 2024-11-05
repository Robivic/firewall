import os
import subprocess
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

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
            # Simulating a system scan
            result = subprocess.run(['echo', 'Scanning...'], capture_output=True, text=True)
            print(result.stdout)
            
            # Scan all files in the home directory for demonstration
            self.scan_files(os.path.expanduser("~"))  # Scanning the user's home directory
            
            # Example vulnerability for demonstration
            self.vulnerabilities.append("Example Vulnerability: Outdated Software")
            self.generate_report()
        except Exception as e:
            print(f"Error during system scan: {e}")

    def scan_files(self, directory):
        """Scan files in the specified directory for vulnerabilities."""
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Example check: if file is a .txt file, consider it a vulnerability
                    if file.endswith('.txt'):
                        self.vulnerabilities.append(f"Found text file: {file_path}")
            print(f"Completed scanning files in {directory}.")
        except Exception as e:
            print(f"Error scanning files: {e}")

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

    def generate_pdf_report(self):
        """Generate a well-formatted PDF report."""
        pdf_file = "security_report.pdf"
        c = canvas.Canvas(pdf_file, pagesize=letter)
        width, height = letter

        # Add title
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, height - 50, "Security Scan Report")
        c.setFont("Helvetica", 12)
        c.drawString(100, height - 70, f"Scan Date: {datetime.now()}")

        # Add vulnerabilities
        y_position = height - 100
        if self.vulnerabilities:
            c.drawString(100, y_position, "Vulnerabilities Found:")
            y_position -= 20
            for vulnerability in self.vulnerabilities:
                c.drawString(120, y_position, f"- {vulnerability}")
                y_position -= 20
        else:
            c.drawString(100, y_position, "No vulnerabilities found.")
        
        c.save()
        return f"PDF report generated: {pdf_file}"

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
        self.master.geometry("600x400")
        self.master.configure(bg="#f0f0f0")

        # Create a title label
        title_label = tk.Label(self.master, text="Security Tool", font=("Arial", 20), bg="#f0f0f0")
        title_label.pack(pady=10)

        # Create an instance of the SecurityTool
        self.tool = SecurityTool('smtp.example.com', 'your_email@example.com', 'your_password')

        # Create widgets
        self.create_widgets()

    def create_widgets(self):
        # Scan button
        self.scan_button = tk.Button(self.master, text="Scan System", command=self.request_permission, bg="#4CAF50", fg="white", font=("Arial", 14))
        self.scan_button.pack(pady=10)

        # Report display area
        self.report_area = scrolledtext.ScrolledText(self.master, width=70, height=15, wrap=tk.WORD)
        self.report_area.pack(pady=10)

        # PDF Report button
        self.pdf_button = tk.Button(self.master, text="Generate PDF Report", command=self.generate_pdf_report, bg="#2196F3", fg="white", font=("Arial", 14))
        self.pdf_button.pack(pady=10)

        # Exit button
        self.exit_button = tk.Button(self.master, text="Exit", command=self.master.quit, bg="#f44336", fg="white", font=("Arial", 14))
        self.exit_button.pack(pady=10)

    def request_permission(self):
        """Request permission from the user to scan the system."""
        response = messagebox.askyesno("Permission Request", "Do you allow the tool to scan your system for vulnerabilities?")
        if response:
            self.scan()  # Proceed with the scan if permission is granted
        else:
            messagebox.showinfo("Permission Denied", "Scan was not performed.")

    def scan(self):
        """Scan the system and display the results."""
        self.tool.scan_system()
        report_message = self.tool.generate_report()
        self.report_area.insert(tk.END, report_message + "\n")
        self.report_area.insert(tk.END, "Vulnerabilities Found:\n")
        for vulnerability in self.tool.vulnerabilities:
            self.report_area.insert(tk.END, f"- {vulnerability}\n")
        self.report_area.insert(tk.END, "\n")

        # Request permission to resolve vulnerabilities
        resolve_response = messagebox.askyesno("Resolve Vulnerabilities", "Do you want to resolve the found vulnerabilities?")
        if resolve_response:
            self.tool.resolve_vulnerabilities()
            self.report_area.insert(tk.END, "Vulnerabilities resolved.\n")

    def generate_pdf_report(self):
        """Generate a PDF report of the vulnerabilities."""
        pdf_message = self.tool.generate_pdf_report()
        messagebox.showinfo("PDF Report", pdf_message)


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityToolGUI(root)
    root.mainloop()
