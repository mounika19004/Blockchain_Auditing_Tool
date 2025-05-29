import os
import subprocess
from fpdf import FPDF
import fitz
from datetime import datetime

class PDFReport(FPDF):
    def header(self):
        # Title
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Smart Contract Security Audit Report', 0, 1, 'C')
        # Date
        self.set_font('Arial', '', 10)
        self.cell(0, 10, f'Report generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        # Line break
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 6, title, 0, 1, 'L', 1)
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        # Replace common patterns with more readable text
        body = body.replace('INFO:Detectors:', 'Security Finding:')
        body = body.replace('Reference:', '\nReference:')
        body = body.replace('Dangerous calls:', '\nDangerous calls:')
        
        # Split into lines and process each line
        lines = body.split('\n')
        for line in lines:
            if line.startswith('Security Finding:'):
                self.set_font('Arial', 'B', 10)
                self.set_text_color(255, 0, 0)  # Red for findings
                self.cell(0, 6, line, 0, 1)
                self.set_text_color(0, 0, 0)
                self.set_font('Arial', '', 10)
            elif line.startswith('Reference:'):
                self.set_font('Arial', 'I', 9)
                self.set_text_color(0, 0, 255)  # Blue for references
                self.multi_cell(0, 5, line)
                self.set_text_color(0, 0, 0)
                self.set_font('Arial', '', 10)
            else:
                self.multi_cell(0, 5, line)
            self.ln(2)
        self.ln(5)

    def add_summary(self, findings):
        self.chapter_title('Executive Summary')
        self.set_font('Arial', '', 10)
        
        if not findings or all("No critical vulnerabilities found" in f for f in findings):
            self.multi_cell(0, 5, "No critical vulnerabilities found. The contract appears to be secure.")
        else:
            # Filter out non-findings
            actual_findings = [f for f in findings if "No critical vulnerabilities found" not in f]
            self.multi_cell(0, 5, f"The analysis identified {len(actual_findings)} potential security issues:")
            self.ln(3)
            
            for i, finding in enumerate(actual_findings, 1):
                # Extract severity if available
                severity = "Medium"
                if "high risk" in finding.lower() or "high severity" in finding.lower():
                    severity = "High"
                elif "low risk" in finding.lower() or "low severity" in finding.lower():
                    severity = "Low"
                
                self.set_font('Arial', 'B', 10)
                self.cell(0, 5, f"{i}. {severity} Severity: ", 0, 0)
                self.set_font('Arial', '', 10)
                self.multi_cell(0, 5, finding.split('\n')[0])
                self.ln(2)

    def add_contract_code(self, code, filename):
        self.chapter_title('Contract Source Code')
        self.set_font('Courier', '', 8)
        self.multi_cell(0, 5, f"File: {filename}\n\n{code}")
        self.ln(5)

def get_file_content(file_path):
    """Read content from either PDF or Solidity file"""
    if file_path.lower().endswith('.pdf'):
        try:
            doc = fitz.open(file_path)
            code = ""
            for page in doc:
                code += page.get_text()
            doc.close()
            return code
        except Exception as e:
            print(f"[!] Failed to extract code from PDF: {e}")
            return None
    elif file_path.lower().endswith('.sol'):
        try:
            with open(file_path, 'r') as f:
                return f.read()
        except Exception as e:
            print(f"[!] Failed to read Solidity file: {e}")
            return None
    else:
        print(f"[!] Unsupported file format. Please provide a .pdf or .sol file.")
        return None

def save_contract(code, filename="input.sol"):
    with open(filename, "w") as f:
        f.write(code)

def run_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return str(e)

def analyze_with_mythril():
    print("[*] Running Mythril analysis...")
    return run_command(
        'docker run --rm -v "%cd%":/tmp mythril/myth analyze /tmp/input.sol'
    )

def analyze_with_slither():
    print("[*] Running Slither analysis...")
    return run_command(
        'docker run --rm -v "%cd%":/src trailofbits/eth-security-toolbox '
        'bash -c "solc-select install 0.8.6 && solc-select use 0.8.6 && slither /src/input.sol"'
    )

def analyze_with_oyente():
    print("[*] Running Oyente analysis...")
    return run_command(
        'docker run --rm -v "%cd%":/tmp luongnguyen/oyente python oyente/oyente.py -s /tmp/input.sol'
    )

def extract_findings(analysis_output):
    """Extract key findings from analysis output"""
    findings = []
    lines = analysis_output.split('\n')
    
    for line in lines:
        if "Security Finding:" in line or "INFO:Detectors:" in line:
            findings.append(line.split(":")[-1].strip())
        elif "Error:" in line or "Warning:" in line:
            findings.append(line.strip())
        elif "Vulnerability:" in line:  # For Oyente output
            findings.append(line.strip())
    
    return findings if findings else ["No critical vulnerabilities found"]

def generate_pdf_report(contract_code, filename, mythril_output, slither_output, oyente_output, output_file="audit_report.pdf"):
    print("[*] Generating PDF report...")
    
    # Extract key findings for summary
    findings = []
    findings.extend(extract_findings(mythril_output))
    findings.extend(extract_findings(slither_output))
    findings.extend(extract_findings(oyente_output))
    
    # Create PDF
    pdf = PDFReport()
    pdf.add_page()
    
    # Add contract source code
    pdf.add_contract_code(contract_code, filename)
    
    # Add summary
    pdf.add_summary(findings)
    
    # Add detailed analysis sections
    if mythril_output.strip():
        pdf.chapter_title('Detailed Analysis: Mythril')
        pdf.chapter_body(mythril_output)
    
    if slither_output.strip():
        pdf.chapter_title('Detailed Analysis: Slither')
        pdf.chapter_body(slither_output)
    
    if oyente_output.strip():
        pdf.chapter_title('Detailed Analysis: Oyente')
        pdf.chapter_body(oyente_output)
    
    # Save the PDF
    pdf.output(output_file)
    print(f"[+] PDF Report generated: {output_file}")

if __name__ == "__main__":
    print("=== Smart Contract Security Analyzer ===")
    file_path = input("Enter path to PDF or Solidity file (.pdf or .sol): ").strip()
    
    contract_code = get_file_content(file_path)
    if not contract_code:
        print("[!] No code extracted. Exiting.")
        exit(1)
    
    # Get just the filename for display
    filename = os.path.basename(file_path)
    
    save_contract(contract_code)
    
    mythril_result = analyze_with_mythril()
    slither_result = analyze_with_slither()
    oyente_result = analyze_with_oyente()
    
    generate_pdf_report(contract_code, filename, mythril_result, slither_result, oyente_result)o