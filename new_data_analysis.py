import tkinter as tk
from tkinter import filedialog, messagebox
import xml.etree.ElementTree as ET
import os
import re

# --------------------- Parsing Functions ---------------------
def parse_content_xml(input_file):
    """Parses content.xml and extracts rows from the 'data' table."""
    namespaces = {
        'office': 'urn:oasis:names:tc:opendocument:xmlns:office:1.0',
        'table': 'urn:oasis:names:tc:opendocument:xmlns:table:1.0',
        'text': 'urn:oasis:names:tc:opendocument:xmlns:text:1.0'
    }

    tree = ET.parse(input_file)
    root = tree.getroot()

    data_table = root.find('.//table:table[@table:name="data"]', namespaces)

    if data_table is None:
        raise ValueError("No table named 'data' found in the provided content.xml.")

    extracted_data = []
    for row in data_table.findall('table:table-row', namespaces):
        cells = row.findall('table:table-cell', namespaces)
        row_data = []
        for cell in cells:
            text = cell.find('text:p', namespaces)
            row_data.append(text.text if text is not None else '')
        if len(row_data) >= 10:
            extracted_data.append(row_data)

    return extracted_data

# ------------------ Email Domain Loading Function ------------------
def load_disposable_domains(file_path):
    """Loads the list of disposable email domains from the uploaded file."""
    disposable_domains = set()
    try:
        with open(file_path, "r") as file:
            for line in file:
                domain = line.strip().lower()
                if domain:
                    disposable_domains.add(domain)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load disposable domains file: {e}")
    return disposable_domains

# ------------------ Anomaly Detection Functions ------------------
def detect_anomalies(data_rows, disposable_domains):
    """Detects anomalies such as inconsistent addresses and suspicious emails."""
    anomaly_list = []
    company_data = {}

    # Regular expression for validating standard email format
    email_regex = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

    for row in data_rows:
        agency_name = row[0]
        address = row[1]
        email1 = row[4]
        email2 = row[7]

        # Track entries by company name
        if agency_name not in company_data:
            company_data[agency_name] = {"addresses": set(), "emails": set(), "domains": set()}
        
        # Check for inconsistent addresses
        if address not in company_data[agency_name]["addresses"]:
            if len(company_data[agency_name]["addresses"]) > 0:
                anomaly_list.append(f"Inconsistent address for {agency_name}: {address}")
            company_data[agency_name]["addresses"].add(address)

        # Extract domain from email
        def get_domain(email):
            return email.split('@')[1] if '@' in email else ''

        # Validate and analyze emails
        for email in [email1, email2]:
            if email and not email_regex.match(email):
                anomaly_list.append(f"Invalid email format for {agency_name}: {email}")
            else:
                domain = get_domain(email)
                if domain:
                    # Check if domain is consistent with previous entries
                    if domain not in company_data[agency_name]["domains"] and len(company_data[agency_name]["domains"]) > 0:
                        anomaly_list.append(f"Inconsistent domain for {agency_name}: {email}")
                    company_data[agency_name]["domains"].add(domain)

                # Detect suspicious patterns in email addresses
                if re.search(r"\d{5,}", email) or re.search(r"[_%$&*]+", email):
                    anomaly_list.append(f"Suspicious characters in email for {agency_name}: {email}")

                # Check against known disposable or suspicious domains
                if domain in disposable_domains:
                    anomaly_list.append(f"Suspicious email domain for {agency_name}: {email} (Disposable Domain)")

    return anomaly_list

# ------------------- XML Creation Functions -------------------
def create_reformatted_xml(data_rows, output_file):
    """Creates a structured XML file for the reformatted data."""
    root = ET.Element("Agencies")

    for row in data_rows:
        agency = ET.SubElement(root, "Agency")
        ET.SubElement(agency, "AgencyName").text = row[0]
        ET.SubElement(agency, "Address").text = row[1]
        ET.SubElement(agency, "Name1").text = row[2]
        ET.SubElement(agency, "Phone1").text = row[3]
        ET.SubElement(agency, "Email1").text = row[4]
        ET.SubElement(agency, "Name2").text = row[5]
        ET.SubElement(agency, "Phone2").text = row[6]
        ET.SubElement(agency, "Email2").text = row[7]
        ET.SubElement(agency, "OrderID").text = row[8]
        ET.SubElement(agency, "Date").text = row[9]

    tree = ET.ElementTree(root)
    tree.write(output_file, encoding='utf-8', xml_declaration=True)

def create_anomaly_xml(anomalies, output_file):
    """Creates an XML file to log detected anomalies."""
    root = ET.Element("Anomalies")

    for anomaly in anomalies:
        anomaly_element = ET.SubElement(root, "Anomaly")
        anomaly_element.text = anomaly

    tree = ET.ElementTree(root)
    tree.write(output_file, encoding='utf-8', xml_declaration=True)

# ---------------------- File and Folder Selection --------------------
def select_file():
    """Opens a file dialog to select the content.xml file."""
    file_path = filedialog.askopenfilename(
        title="Select the content.xml file",
        filetypes=[("XML Files", "*.xml")],
        initialdir="/"
    )
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

def select_domain_file():
    """Opens a file dialog to select the disposable email domain file."""
    file_path = filedialog.askopenfilename(
        title="Select Disposable Domains File",
        filetypes=[("Text Files", "*.txt")],
        initialdir="/"
    )
    if file_path:
        domain_entry.delete(0, tk.END)
        domain_entry.insert(0, file_path)

def select_save_location():
    """Opens a dialog to select the save location for the output file."""
    folder_selected = filedialog.askdirectory(title="Select Save Folder")
    if folder_selected:
        folder_entry.delete(0, tk.END)
        folder_entry.insert(0, folder_selected)

# ---------------------- Save and Process ------------------------
def save_file():
    """Saves the reformatted XML and anomaly report files."""
    input_file = file_entry.get()
    output_file_name = output_entry.get()
    save_location = folder_entry.get()
    domain_file = domain_entry.get()

    if not input_file or not output_file_name or not save_location or not domain_file:
        messagebox.showwarning("Warning", "Please select all files and enter a name!")
        return

    # Load the disposable email domains from the uploaded file
    disposable_domains = load_disposable_domains(domain_file)

    output_file = os.path.join(save_location, f"{output_file_name}.xml")
    anomaly_file = os.path.join(save_location, f"{output_file_name}_anomalies.xml")

    try:
        # Parse, reformat, and detect anomalies
        data_rows = parse_content_xml(input_file)
        create_reformatted_xml(data_rows, output_file)
        
        anomalies = detect_anomalies(data_rows, disposable_domains)
        create_anomaly_xml(anomalies, anomaly_file)
        
        messagebox.showinfo("Success", f"Reformatted XML saved at {output_file}\nAnomalies saved at {anomaly_file}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# ---------------------- GUI Layout -------------------------
root = tk.Tk()
root.title("XML Formatter with Advanced Anomaly Detection")
root.geometry("600x500")

# File selection frame
file_frame = tk.LabelFrame(root, text="Step 1: Select XML File", padx=10, pady=10)
file_frame.pack(fill="both", expand="yes", padx=20, pady=10)

file_label = tk.Label(file_frame, text="Select content.xml File:")
file_label.grid(row=0, column=0, sticky="w")

file_entry = tk.Entry(file_frame, width=60)
file_entry.grid(row=1, column=0, padx=10, pady=5)

file_button = tk.Button(file_frame, text="Browse", command=select_file, bg="#d1e7dd")
file_button.grid(row=1, column=1, padx=10)

# Domain file selection frame
domain_frame = tk.LabelFrame(root, text="Step 2: Select Disposable Domains File", padx=10, pady=10)
domain_frame.pack(fill="both", expand="yes", padx=20, pady=10)

domain_label = tk.Label(domain_frame, text="Select Disposable Domains (.txt):")
domain_label.grid(row=0, column=0, sticky="w")

domain_entry = tk.Entry(domain_frame, width=60)
domain_entry.grid(row=1, column=0, padx=10, pady=5)

domain_button = tk.Button(domain_frame, text="Browse", command=select_domain_file, bg="#ffeeba")
domain_button.grid(row=1, column=1, padx=10)

# Output file name frame
output_frame = tk.LabelFrame(root, text="Step 3: Enter Output File Name", padx=10, pady=10)
output_frame.pack(fill="both", expand="yes", padx=20, pady=10)

output_label = tk.Label(output_frame, text="Enter Output File Name (without .xml):")
output_label.grid(row=0, column=0, sticky="w")

output_entry = tk.Entry(output_frame, width=60)
output_entry.grid(row=1, column=0, padx=10, pady=5)

# Save location frame
folder_frame = tk.LabelFrame(root, text="Step 4: Select Save Location", padx=10, pady=10)
folder_frame.pack(fill="both", expand="yes", padx=20, pady=10)

folder_label = tk.Label(folder_frame, text="Select Save Location:")
folder_label.grid(row=0, column=0, sticky="w")

folder_entry = tk.Entry(folder_frame, width=60)
folder_entry.grid(row=1, column=0, padx=10, pady=5)

folder_button = tk.Button(folder_frame, text="Select Folder", command=select_save_location, bg="#d1e7dd")
folder_button.grid(row=1, column=1, padx=10)

# Save button frame
button_frame = tk.Frame(root)
button_frame.pack(pady=20)

save_button = tk.Button(button_frame, text="Generate Reformatted XML", command=save_file, bg="lightblue", padx=20, pady=10, font=("Arial", 12, "bold"))
save_button.pack()

root.mainloop()
