import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.ttk import Progressbar
from zebra.io.unity._usb import USBConnection
import threading
import os
import time
import json

printer = USBConnection()

printer.send(b'{}{"allconfig":null}')
data = printer.collect(10)

decoded_str = data.decode('utf-8')

json_data = json.loads(decoded_str)["allconfig"]


def browse_firmware():
    messagebox.showinfo("Check your firmware","Ensure you are trying to upload a compatible firmware")
    filepath = filedialog.askopenfilename(
        filetypes=[("Firmware Files","*.zpl")],
        title="Select Firmware File",
    )
    if filepath:
        firmware_entry.delete(0, tk.END)
        firmware_entry.insert(0, filepath)

def validate_firmware(filepath):
    if not os.path.exists(filepath):
        return "File does not exist."
    if not filepath.endswith(".zpl"):
        return "Invalid file type. Only .zpl files are supported."
    if os.path.getsize(filepath) == 0:
        return "File is empty."
    return None

def format_size(size_in_bytes):
    return f"{size_in_bytes / (1024 * 1024):.2f} MB"

def upload_firmware(filepath):
    try:
        file_size = os.path.getsize(filepath)
        progress_bar["value"] = 0
        progress_bar["maximum"] = file_size
        progress_label.config(text=f"0 KB of {format_size(file_size)} (0%)")

        def tx_start_hook(expected_length):
            progress_bar["value"] = 0
            progress_bar["maximum"] = expected_length
            root.update_idletasks()

        def tx_data_hook(data):
            progress_bar["value"] += len(data)
            sent_size = progress_bar["value"]
            percent = (sent_size / file_size) * 100
            progress_label.config(
                text=f"{format_size(sent_size)} of {format_size(file_size)} ({percent:.1f}%)"
            )
            root.update_idletasks()

        def tx_end_hook():
            progress_bar["value"] = file_size
            progress_label.config(
                text=f"{format_size(file_size)} of {format_size(file_size)} (100%)"
            )
            root.update_idletasks()

        printer.tx_data_start_hook = tx_start_hook
        printer.tx_data_hook = tx_data_hook
        printer.tx_data_end_hook = tx_end_hook

        printer.send_file(filepath)

        printer.tx_data_start_hook = None
        printer.tx_data_hook = None
        printer.tx_data_end_hook = None

        messagebox.showinfo("Success", "Firmware successfully uploaded to the printer. Please wait while printer is restarting. ")
        Head_section.config(text = "Please wait while the printer restarts ... ")
        About_section.config(text="")
        printer.wait_for_reset()

        apply_firmware_btn.config(state="normal")
        configure_btn.config(state="normal")
        sgd_submit.config(state="normal")
        sgd_button.config(state="normal")

        Head_section.config(text = f"You are using a {printer.getvar('device.product_name')}")
        print(printer.connected)
        # About_section.config(text=f"{printer.getvar('ip.dhcp.vendor_class_id')}")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to upload firmware: {e}")

def apply_firmware():
    filepath = firmware_entry.get()
    validation_error = validate_firmware(filepath)

    apply_firmware_btn.config(state="disabled")
    configure_btn.config(state="disabled")
    sgd_submit.config(state="disabled")
    sgd_button.config(state="disabled")

    if validation_error:
        messagebox.showerror("Error", validation_error)
        return

    # Run the upload process in a separate thread to prevent GUI freezing
    upload_thread = threading.Thread(target=upload_firmware, args=(filepath,))
    upload_thread.start()

def configure_wifi():
    essid = essid_entry.get()
    security = security_entry.get()
    psk = psk_entry.get()

    if not essid or not security or not psk:
        messagebox.showerror("Error", "Please fill in all Wi-Fi configuration fields.")
        return

    try:
        printer.send(b"~WR")
        printer.setvar("wlan.essid", essid)
        printer.setvar("wlan.security", security)
        printer.setvar("wlan.wpa.psk", psk)
        # printer.setvar("wlan.enable", "on")
        messagebox.showinfo("Success", "Wi-Fi configuration sent to the printer. Checking connection...")
        check_connection()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to configure Wi-Fi: {e}")

def check_connection():
    def monitor_connection():
        while True:
            try:
                status = printer.getvar("wlan.associated")
                connection_status.set("Connected" if status == "yes" else "Not Connected")
                root.update_idletasks()
                if status == "yes":
                    break  # Stop checking once connected
            except Exception as e:
                connection_status.set("Error checking status")
                break
            time.sleep(1)  # Check every 2 seconds

    threading.Thread(target=monitor_connection, daemon=True).start()

def handle_sgd():
    sgd = sgd_entry.get()

    try:
        data = json_data[sgd]
        access = data["access"]
        value = data["value"]
        range_value = data["range"]
        sgd_type = data["type"]

        # Reset previous widgets in the input_frame
        for widget in input_frame.winfo_children():
            widget.destroy()

        if access == "R":
            validate_label.config(text=f"Value: {value}. (This SGD is read-only).")
            # change_sgd_entry.config(state="disabled")
            sgd_submit.config(state="disabled")

        elif access == "W":
            messagebox.showinfo("Error", "This SGD is write-only. ")
            # change_sgd_entry.config(state="disabled")
            sgd_submit.config(state="disabled")

        elif access == "RW":
            # change_sgd_entry.config(state="normal")
            sgd_submit.config(state="normal")

            if sgd_type == "bool":
                validate_label.config(text=f"Value: {value}. (This SGD can be edited - Boolean)")
                # change_sgd_entry.config(state="disabled")
                values = range_value.split(",")
                var = tk.StringVar(value=value)
                for option in values:
                    rb = tk.Radiobutton(input_frame, text=option, variable=var, value=option)
                    rb.pack(anchor=tk.W)

                def update_bool():
                    selected_value = var.get()
                    if selected_value in values:
                        printer.setvar(sgd,selected_value)
                        data["value"] = selected_value
                        validate_label.config(text=f"Updated {sgd} to {selected_value}.")
                    else:
                        validate_label.config(text="Invalid selection.")

                sgd_submit.config(command=update_bool)

            elif sgd_type == "enum":
                # change_sgd_entry.config(state="disabled")
                validate_label.config(text=f"Value: {value}. (This SGD can be edited - ENUM)")
                values = range_value.split(",")

                var = tk.StringVar(value=value)
                dropdown = tk.OptionMenu(input_frame, var, *values)
                dropdown.pack()

                def update_enum():
                    selected_value = var.get()
                    if selected_value in values:
                        printer.setvar(sgd,selected_value)
                        data["value"] = selected_value
                        validate_label.config(text=f"Updated {sgd} to {selected_value}.")
                    else:
                        validate_label.config(text="Invalid selection.")

                sgd_submit.config(command=update_enum)

            elif sgd_type == "integer":
                # Integer type: Display a spinbox or entry widget
                min_value, max_value = map(int, range_value.split("-"))
                validate_label.config(text=f"Value: {value}. (This SGD can be edited). Enter a value between {min_value} and {max_value}.")
                spinbox = tk.Spinbox(input_frame, from_=min_value, to=max_value, font=("Arial", 12))
                spinbox.pack()

                def update_integer():
                    try:
                        selected_value = int(spinbox.get())
                        if min_value <= selected_value <= max_value:
                            printer.setvar(sgd,str(selected_value))
                            data["value"] = selected_value
                            validate_label.config(text=f"Updated {sgd} to {selected_value}.")
                        else:
                            messagebox.showerror(title="Error",message=f"Value out of range! Must be between {min_value} and {max_value}.")
                    except ValueError:
                        messagebox.showerror(title="Error",message="Invalid input. Please enter a valid integer.")

                sgd_submit.config(command=update_integer)

            else:
                validate_label.config(text=f"Unsupported SGD type: {sgd_type}.")
                # change_sgd_entry.config(state="disabled")
                sgd_submit.config(state="disabled")

    except KeyError:
        validate_label.config(text="SGD does not exist.")


root = tk.Tk()
root.title("Printer Interaction Software ")
root.geometry("700x600")


Head_section=tk.Label(root,text=f"You are using a {printer.getvar('device.product_name')}", font=("Arial",14,"bold"))
Head_section.pack(fill = tk.X, pady=10)

About_section=tk.Label(root,text=f"{printer.getvar('ip.dhcp.vendor_class_id')}", font=("Arial",14))
About_section.pack(fill = tk.X, pady=10)

firmware_frame = tk.LabelFrame(root, text="Firmware Download", font=("Arial", 14, "bold"))
firmware_frame.pack(fill=tk.X, padx=10, pady=10)

firmware_label = tk.Label(firmware_frame, text="Firmware File:", font=("Arial", 12))
firmware_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

firmware_entry = tk.Entry(firmware_frame, width=40, font=("Arial", 12))
firmware_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

browse_btn = tk.Button(firmware_frame, text="Browse", command=browse_firmware, font=("Arial", 12))
browse_btn.grid(row=0, column=2, padx=5, pady=5)

apply_firmware_btn = tk.Button(firmware_frame, text="Apply Firmware", command=apply_firmware, font=("Arial", 12))
apply_firmware_btn.grid(row=1, column=1, padx=5, pady=10)

progress_bar = Progressbar(firmware_frame, length=400, mode="determinate")
progress_bar.grid(row=2, column=0, columnspan=3, pady=10)

progress_label = tk.Label(firmware_frame, text="Progress is displayed here", font=("Arial", 12))
progress_label.grid(row=3, column=0, columnspan=3, pady=5)

wifi_frame = tk.LabelFrame(root, text="Wi-Fi Configuration", font=("Arial", 14, "bold"))
wifi_frame.pack(fill=tk.X, padx=10, pady=10)

essid_label = tk.Label(wifi_frame, text="ESSID:", font=("Arial", 12))
essid_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

essid_entry = tk.Entry(wifi_frame, width=30, font=("Arial", 12))
essid_entry.grid(row=0, column=1, padx=5, pady=5)

security_label = tk.Label(wifi_frame, text="Security:", font=("Arial", 12))
security_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

security_entry = tk.Entry(wifi_frame, width=30, font=("Arial", 12))
security_entry.grid(row=1, column=1, padx=5, pady=5)

psk_label = tk.Label(wifi_frame, text="Password:", font=("Arial", 12))
psk_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")

psk_entry = tk.Entry(wifi_frame, width=30, show="*", font=("Arial", 12))
psk_entry.grid(row=2, column=1, padx=5, pady=5)

configure_btn = tk.Button(wifi_frame, text="Configure Wi-Fi", command=configure_wifi, font=("Arial", 12))
configure_btn.grid(row=3, column=1, pady=10)

connection_status = tk.StringVar(value="Not Connected")
status_label = tk.Label(root, text="Connection Status:", font=("Arial", 14))
status_label.pack(pady=5)

status_value = tk.Label(root, textvariable=connection_status, font=("Arial", 14, "bold"))
status_value.pack(pady=5)

SGD_Validation = tk.LabelFrame(root, text="SGD Validation", font=("Arial", 14, "bold"))
SGD_Validation.pack(fill=tk.X, padx=10, pady=10)

sgd_label = tk.Label(SGD_Validation, text="Enter an SGD:", font=("Arial", 12))
sgd_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

sgd_entry = tk.Entry(SGD_Validation, width=30, font=("Arial", 12))
sgd_entry.grid(row=0, column=1, padx=5, pady=5)

sgd_button = tk.Button(SGD_Validation, text="Validate", command=handle_sgd, font=("Arial", 12))
sgd_button.grid(row=0, column=2, padx=5, pady=5)

validate_label = tk.Label(SGD_Validation, text="", font=("Arial", 12))
validate_label.grid(row = 1, column = 0,padx=5, pady=5)

# change_sgd = tk.Label(SGD_Validation,text="Enter value to change in the sgd : ", font = ("Arial",12))
# change_sgd.grid(row = 2, column = 0,padx=5, pady=5)

# change_sgd_entry = tk.Entry(SGD_Validation, width = 30, font=("Arial",12),state="disabled")
# change_sgd_entry.grid(row=2,column=1,padx=5, pady=5)

input_frame = tk.Frame(SGD_Validation)
input_frame.grid(row=2,column=1,padx=5, pady=5)

sgd_submit = tk.Button(SGD_Validation, text="Submit",  font=("Arial",12), state="disabled")
sgd_submit.grid(row=2,column=2,padx=5,pady=5,)



check_connection()

root.mainloop()
