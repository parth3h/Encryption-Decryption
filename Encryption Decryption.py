import tkinter as tk
from tkinter import messagebox, ttk
import base64
import codecs
import urllib.parse
import binascii
import pyperclip

#caesar cipher 
def encode_letter(message, shift_number):
    encoded_message = ""
    for letter in message:
        # Get the ASCII value of the character
        original_position = ord(letter)
        # Apply the shift
        encoded_position = original_position + shift_number
        # Wrap around using 256 to stay within byte range
        if encoded_position > 255:
            encoded_position -= 256
        encoded_letter = chr(encoded_position)
        encoded_message += encoded_letter
    return encoded_message

def decode_letter(message, shift_number):
    decoded_message = ""
    for letter in message:
        # Get the ASCII value of the character
        encoded_position = ord(letter)
        # Reverse the shift
        original_position = encoded_position - shift_number
        # Wrap around using 256
        if original_position < 0:
            original_position += 256
        original_letter = chr(original_position)
        decoded_message += original_letter
    return decoded_message

def encode_base64(message):
    message_bytes = message.encode('utf-8')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('utf-8')
    return base64_message

def decode_base64(message):
    base64_bytes = message.encode('utf-8')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('utf-8')
    return message

def encode_rot13(message):
    return codecs.encode(message, 'rot_13')

def decode_rot13(message):
    return codecs.decode(message, 'rot_13')

def encode_hex(message):
    return binascii.hexlify(message.encode()).decode()

def decode_hex(message):
    return binascii.unhexlify(message.encode()).decode()

def encode_url(message):
    return urllib.parse.quote(message)

def decode_url(message):
    return urllib.parse.unquote(message)

def process_input():
    operation = operation_var.get()
    encoding_type = encoding_var.get()
    message = message_entry.get()
    shift_number = shift_entry.get()

    if encoding_type == "Caesar Cipher":
        if not shift_number.isdigit() or int(shift_number) < 1 or int(shift_number) > 255:
            messagebox.showerror("Invalid Input", "Please type a shift number between 1 and 255.")
            return

        shift_number = int(shift_number)

        if operation == "encode":
            encoded_message = encode_letter(message, shift_number)
            result_label.config(text=f"Encoded message is: {encoded_message}")
            add_to_history(f"Encoded (Caesar Cipher): {encoded_message}")
        else:
            decoded_message = decode_letter(message, shift_number)
            result_label.config(text=f"The original message is: {decoded_message}")
            add_to_history(f"Decoded (Caesar Cipher): {decoded_message}")
    elif encoding_type == "Base64":
        if operation == "encode":
            encoded_message = encode_base64(message)
            result_label.config(text=f"Encoded message is: {encoded_message}")
            add_to_history(f"Encoded (Base64): {encoded_message}")
        else:
            try:
                decoded_message = decode_base64(message)
                result_label.config(text=f"The original message is: {decoded_message}")
                add_to_history(f"Decoded (Base64): {decoded_message}")
            except Exception as e:
                messagebox.showerror("Error", f"Invalid Base64 string: {e}")
    elif encoding_type == "ROT13":
        if operation == "encode":
            encoded_message = encode_rot13(message)
            result_label.config(text=f"Encoded message is: {encoded_message}")
            add_to_history(f"Encoded (ROT13): {encoded_message}")
        else:
            decoded_message = decode_rot13(message)
            result_label.config(text=f"The original message is: {decoded_message}")
            add_to_history(f"Decoded (ROT13): {decoded_message}")
    elif encoding_type == "Hex":
        if operation == "encode":
            encoded_message = encode_hex(message)
            result_label.config(text=f"Encoded message is: {encoded_message}")
            add_to_history(f"Encoded (Hex): {encoded_message}")
        else:
            try:
                decoded_message = decode_hex(message)
                result_label.config(text=f"The original message is: {decoded_message}")
                add_to_history(f"Decoded (Hex): {decoded_message}")
            except Exception as e:
                messagebox.showerror("Error", f"Invalid Hex string: {e}")
    elif encoding_type == "URL":
        if operation == "encode":
            encoded_message = encode_url(message)
            result_label.config(text=f"Encoded message is: {encoded_message}")
            add_to_history(f"Encoded (URL): {encoded_message}")
        else:
            decoded_message = decode_url(message)
            result_label.config(text=f"The original message is: {decoded_message}")
            add_to_history(f"Decoded (URL): {decoded_message}")

def reset():
    message_entry.delete(0, tk.END)
    shift_entry.delete(0, tk.END)
    result_label.config(text="")

def create_tooltip(widget, text):
    tooltip = tk.Toplevel(widget)
    tooltip.wm_overrideredirect(True)
    tooltip.wm_geometry("+0+0")
    label = tk.Label(tooltip, text=text)
    label.pack(ipadx=1)
    def on_enter(event):
        x, y, cx, cy = widget.bbox("insert")
        x += widget.winfo_rootx() + 25
        y += widget.winfo_rooty() + 25
        tooltip.wm_geometry(f"+{x}+{y}")
        tooltip.deiconify()
    def on_leave(event):
        tooltip.withdraw()
    widget.bind("<Enter>", on_enter)
    widget.bind("<Leave>", on_leave)

def on_encoding_type_change(*args):
    encoding_type = encoding_var.get()
    if encoding_type == "Caesar Cipher":
        shift_frame.grid()
    else:
        shift_frame.grid_remove()

def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(result_label.cget("text").split(": ", 1)[1])
    messagebox.showinfo("Copied", "Encoded/Decoded message copied to clipboard!")

def add_to_history(message):
    history_listbox.insert(tk.END, message)
    history_listbox.yview(tk.END)

# Main Application Window
root = tk.Tk()
root.title("Caesar Cipher")
root.geometry("800x600")

# Configure grid weights for responsive design
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

# Canvas for scrolling
canvas = tk.Canvas(root)
canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Scrollbar for canvas
scrollbar = ttk.Scrollbar(root, orient="vertical", command=canvas.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
canvas.configure(yscrollcommand=scrollbar.set)

# Frame for the main content
main_frame = ttk.Frame(canvas, padding="20")
canvas.create_window((0, 0), window=main_frame, anchor="nw")

# Configure frame to expand
main_frame.columnconfigure(0, weight=1)

# Configure style
style = ttk.Style()
style.configure("TFrame", background="#FFFFFF")
style.configure("TLabel", background="#FFFFFF")
style.configure("TButton", background="#E0E0E0", foreground="black")
style.configure("TRadiobutton", background="#FFFFFF")
style.configure("TEntry", background="#FFFFFF", foreground="#000000")
style.map('TButton', background=[('active', '#D0D0D0')])

operation_var = tk.StringVar(value="encode")
encoding_var = tk.StringVar(value="Caesar Cipher")

encoding_var.trace("w", on_encoding_type_change)

# Operation Selection
operation_frame = ttk.Labelframe(main_frame, text="Operation", padding="10")
operation_frame.grid(row=0, column=0, pady=10, padx=10, sticky=tk.W+tk.E)

encode_radio = ttk.Radiobutton(operation_frame, text="Encode", variable=operation_var, value="encode")
encode_radio.grid(row=0, column=0, padx=10, pady=5)

decode_radio = ttk.Radiobutton(operation_frame, text="Decode", variable=operation_var, value="decode")
decode_radio.grid(row=0, column=1, padx=10, pady=5)

# Encoding Type Selection
encoding_frame = ttk.Labelframe(main_frame, text="Encoding Type", padding="10")
encoding_frame.grid(row=1, column=0, pady=10, padx=10, sticky=tk.W+tk.E)

caesar_cipher_radio = ttk.Radiobutton(encoding_frame, text="Caesar Cipher", variable=encoding_var, value="Caesar Cipher")
caesar_cipher_radio.grid(row=0, column=0, padx=10, pady=5)

base64_radio = ttk.Radiobutton(encoding_frame, text="Base64", variable=encoding_var, value="Base64")
base64_radio.grid(row=0, column=1, padx=10, pady=5)

rot13_radio = ttk.Radiobutton(encoding_frame, text="ROT13", variable=encoding_var, value="ROT13")
rot13_radio.grid(row=1, column=0, padx=10, pady=5)

hex_radio = ttk.Radiobutton(encoding_frame, text="Hex", variable=encoding_var, value="Hex")
hex_radio.grid(row=1, column=1, padx=10, pady=5)

url_radio = ttk.Radiobutton(encoding_frame, text="URL", variable=encoding_var, value="URL")
url_radio.grid(row=2, column=0, padx=10, pady=5)

# Shift Entry for Caesar Cipher
shift_frame = ttk.Frame(main_frame)
shift_frame.grid(row=2, column=0, pady=10, padx=10, sticky=tk.W)

shift_label = ttk.Label(shift_frame, text="Shift Number (1-255):")
shift_label.grid(row=0, column=0, padx=10)

shift_entry = ttk.Entry(shift_frame)
shift_entry.grid(row=0, column=1, padx=10)

# Message Entry
message_frame = ttk.Labelframe(main_frame, text="Message", padding="10")
message_frame.grid(row=3, column=0, pady=10, padx=10, sticky=tk.W+tk.E)

message_label = ttk.Label(message_frame, text="Enter Message:")
message_label.grid(row=0, column=0, padx=10)

message_entry = ttk.Entry(message_frame, width=50)
message_entry.grid(row=0, column=1, padx=10)

# Process Button
process_button = ttk.Button(main_frame, text="Process", command=process_input)
process_button.grid(row=4, column=0, pady=10)

# Result Label
result_label = ttk.Label(main_frame, text="", wraplength=700)
result_label.grid(row=5, column=0, pady=10)

# Copy to Clipboard Button
copy_button = ttk.Button(main_frame, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.grid(row=6, column=0, pady=10)

# History Listbox
history_frame = ttk.Labelframe(main_frame, text="History", padding="10")
history_frame.grid(row=7, column=0, pady=10, padx=10, sticky=tk.W+tk.E)

history_listbox = tk.Listbox(history_frame, height=10, width=80)
history_listbox.pack(side=tk.LEFT, fill=tk.BOTH)

history_scrollbar = ttk.Scrollbar(history_frame, orient="vertical", command=history_listbox.yview)
history_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
history_listbox.configure(yscrollcommand=history_scrollbar.set)

# Reset Button
reset_button = ttk.Button(main_frame, text="Reset", command=reset)
reset_button.grid(row=8, column=0, pady=10)

# Main loop
root.mainloop()
