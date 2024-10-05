import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import xml.etree.ElementTree as ET
import re
from collections import defaultdict

# Function to check for suspicious patterns
def is_suspicious(value):
    if re.search(r'[^a-zA-Z0-9@.\- ]', value):  # Symbols not typical in names, emails, or addresses
        return True
    if len(value) > 50:  # Excessively long strings might be suspicious
        return True
    if re.search(r'\b(?:000|123|999)\b', value):  # Obvious fake IDs, phones, etc.
        return True
    return False

# Function to parse XML file and extract all fields dynamically
def parse_xml(file_path):
    suspicious_entries = []  # List to store suspicious entries
    organized_data = "Parsed Data:\n"
    company_orders = defaultdict(list)  # To store orders grouped by company
    new_root = ET.Element("Orders")  # Create a new root for the output XML

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for order in root.findall('.//order'):
            order_details = {}
            new_order = ET.SubElement(new_root, "order")  # Create a new 'order' element in the new XML

            # Extract all fields within each order element
            for child in order:
                tag = child.tag
                value = child.text if child.text is not None else "N/A"
                order_details[tag] = value

                # Add to the new XML structure
                new_element = ET.SubElement(new_order, tag)
                new_element.text = value

            # Group by company name
            company_name = order_details.get('company', 'Unknown')
            company_orders[company_name].append(order_details)

            # Append individual order details to the output
            organized_data += f"Order Details:\n"
            for key, value in order_details.items():
                organized_data += f"{key}: {value}\n"
                if is_suspicious(value):
                    suspicious_entries.append(f"{key}: {value} (in Order ID: {order_details.get('orderID', 'Unknown')})")
            organized_data += "\n"

        # Check for discrepancies within each company's orders
        organized_data += "\n\n*** Consistency Analysis ***\n"
        for company, orders in company_orders.items():
            if len(orders) > 1:
                # Identify field patterns for consistency
                field_patterns = defaultdict(list)
                for order in orders:
                    for field, value in order.items():
                        field_patterns[field].append(value)

                # Find deviations in fields
                for field, values in field_patterns.items():
                    # If more than one unique value exists, flag the discrepancies
                    if len(set(values)) > 1:
                        organized_data += f"Company: {company} - Inconsistent {field} values:\n"
                        for order in orders:
                            if order[field] != max(set(values), key=values.count):  # Compare to the most common value
                                suspicious_entries.append(f"{field}: {order[field]} (in Order ID: {order.get('orderID', 'Unknown')})")

                        for value in set(values):
                            organized_data += f"{field}: {value} ({values.count(value)} times)\n"
                        organized_data += "\n"

        # Display suspicious entries if any
        if suspicious_entries:
            organized_data += "\n\n*** Potentially Suspicious Entries Found ***\n"
            for entry in suspicious_entries:
                organized_data += f"{entry}\n"
        else:
            organized_data += "\n\nNo suspicious entries detected."

    except ET.ParseError as e:
        messagebox.showerror("Error", f"Failed to parse XML: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

    return organized_data, new_root

# Function to save the parsed XML data into a new file
def save_new_xml(xml_data):
    save_path = filedialog.asksaveasfilename(defaultextension=".xml", filetypes=[("XML files", "*.xml")])
    if save_path:
        # Create and save the new XML file
        new_tree = ET.ElementTree(xml_data)
        new_tree.write(save_path, encoding='utf-8', xml_declaration=True)
        messagebox.showinfo("Success", f"File saved as: {save_path}")

# Function to select and parse XML file
def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("XML files", "*.xml")])
    if file_path:
        # Parse the XML and get the organized data along with the new XML structure
        parsed_data, new_xml_root = parse_xml(file_path)
        # Display the organized data in the result area
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, parsed_data)

        # Store the parsed XML for saving
        global parsed_xml_data
        parsed_xml_data = new_xml_root

# GUI setup
window = tk.Tk()
window.title("XML Parser and Fraud Detection")

# Frame for file selection
frame = tk.Frame(window)
frame.pack(pady=10)

select_button = tk.Button(frame, text="Select XML File", command=open_file)
select_button.pack()

# ScrolledText widget to display results
result_text = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=100, height=30, font=("Arial", 10))
result_text.pack(pady=20)

# Button to save the results as a new XML file
download_button = tk.Button(window, text="Download Results", command=lambda: save_new_xml(parsed_xml_data))
download_button.pack(pady=10)

# Start the GUI event loop
window.mainloop()
