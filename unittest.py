import unittest
import hashlib
import tkinter as tk
from tkinter import filedialog


class EncryptionTool:
    def __init__(self, user_file, user_key, user_salt):
        self.user_file = user_file
        self.user_key = user_key
        self.user_salt = user_salt
        self.hashed_key_salt = {}

    def hash_key_salt(self):
        # Hash the user key and salt
        key_hash = hashlib.pbkdf2_hmac('sha256', self.user_key.encode(), self.user_salt.encode(), 100000)
        self.hashed_key_salt["key"] = key_hash
        self.hashed_key_salt["salt"] = self.user_salt.encode()

    def encrypt(self):
        # Encryption logic here
        pass

    def decrypt(self):
        # Decryption logic here
        pass

def save_hashes_to_file(hashes, output_file_name):
    with open(output_file_name, 'w') as file:
        for hashed_value in hashes:
            file.write(hashed_value + '\n')

class TestEncryptionTool(unittest.TestCase):
    # ... (Your existing test case)

# Create the main window
 root = tk.Tk()
 root.title("Hash Saving Tool")

# Function to browse and save hashes
def save_hashes():
    user_key = "mysecretkey"
    user_salt = "mysalt"

    tool = EncryptionTool("", user_key, user_salt)
    tool.hash_key_salt()

    hashes = []
    with open("test.txt", "rb") as test_file:
        content = test_file.read()
        hash_value = hashlib.sha256(content).hexdigest()
        hashes.append(hash_value)

    output_file_name = filedialog.asksaveasfilename(defaultextension=".txt")
    if output_file_name:
        save_hashes_to_file(hashes, output_file_name)
        result_label.config(text="Hashes have been saved successfully.", fg="green")
    else:
        result_label.config(text="Error: No file selected for saving.", fg="red")

# Create and configure frames
input_frame = tk.Frame(root, padx=20, pady=20)
input_frame.pack(pady=10)

# Input elements
hash_button = tk.Button(input_frame, text="Save Hashes", command=save_hashes)
hash_button.pack()

# Result element
result_label = tk.Label(root, text="", fg="green")
result_label.pack()

# Run the GUI main loop
root.mainloop()

if __name__ == '__main__':
    unittest.main()
