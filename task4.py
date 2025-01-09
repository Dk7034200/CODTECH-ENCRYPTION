import os
from tkinter import *
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# --- Encryption and Decryption Functions ---
def encrypt_file(file_path, password):
    """Encrypt a file using AES-256 CBC encryption."""
    try:
        # Generate AES key from password using PBKDF2
        key = PBKDF2(password, salt=b"some_salt", dkLen=32)  # AES-256 requires a 32-byte key

        # Read the file data
        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Pad the data to be a multiple of 16 bytes (AES block size)
        padded_data = pad(file_data, AES.block_size)

        # Create AES cipher object with a random IV
        cipher = AES.new(key, AES.MODE_CBC)

        # Encrypt the padded data
        encrypted_data = cipher.encrypt(padded_data)

        # Save the encrypted data along with the IV (Initialization Vector)
        with open(file_path + ".enc", 'wb') as enc_file:
            enc_file.write(cipher.iv)  # Save the IV for decryption
            enc_file.write(encrypted_data)

        messagebox.showinfo("Success", "File encrypted successfully!")

    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")


def decrypt_file(file_path, password):
    """Decrypt an AES-256 CBC encrypted file."""
    try:
        # Generate AES key from password using PBKDF2
        key = PBKDF2(password, salt=b"some_salt", dkLen=32)

        # Read the encrypted file data
        with open(file_path, 'rb') as file:
            iv = file.read(16)  # First 16 bytes are the IV (Initialization Vector)
            encrypted_data = file.read()

        # Create AES cipher object with the same IV used for encryption
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)

        # Decrypt the file data
        decrypted_data = cipher.decrypt(encrypted_data)

        # Unpad the decrypted data (remove the padding added during encryption)
        unpadded_data = unpad(decrypted_data, AES.block_size)

        # Save the decrypted data to a new file
        decrypted_file_path = file_path.replace(".enc", "_decrypted")
        with open(decrypted_file_path, 'wb') as dec_file:
            dec_file.write(unpadded_data)

        messagebox.showinfo("Success", "File decrypted successfully!")

    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")


# --- File Selection Functions ---
def browse_file_to_encrypt(file_to_encrypt_entry):
    """Open file dialog for selecting a file to encrypt."""
    file_path = filedialog.askopenfilename()
    if file_path:
        file_to_encrypt_entry.delete(0, END)
        file_to_encrypt_entry.insert(0, file_path)


def browse_file_to_decrypt(file_to_decrypt_entry):
    """Open file dialog for selecting a file to decrypt."""
    file_path = filedialog.askopenfilename()
    if file_path:
        file_to_decrypt_entry.delete(0, END)
        file_to_decrypt_entry.insert(0, file_path)


# --- GUI Setup ---
def create_gui():
    """Create the GUI interface using tkinter."""
    root = Tk()
    root.title("AES-256 File Encryption/Decryption Tool")
    root.geometry("500x300")

    # --- Encrypt Section ---
    encrypt_frame = LabelFrame(root, text="Encrypt File", padx=10, pady=10)
    encrypt_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

    file_to_encrypt_label = Label(encrypt_frame, text="Select File to Encrypt:")
    file_to_encrypt_label.grid(row=0, column=0, pady=5)
    file_to_encrypt_entry = Entry(encrypt_frame, width=40)
    file_to_encrypt_entry.grid(row=0, column=1, pady=5)

    browse_button_encrypt = Button(encrypt_frame, text="Browse", command=lambda: browse_file_to_encrypt(file_to_encrypt_entry))
    browse_button_encrypt.grid(row=0, column=2, padx=5)

    password_encrypt_label = Label(encrypt_frame, text="Enter Password:")
    password_encrypt_label.grid(row=1, column=0, pady=5)
    password_encrypt_entry = Entry(encrypt_frame, width=40, show="*")
    password_encrypt_entry.grid(row=1, column=1, pady=5)

    encrypt_button = Button(encrypt_frame, text="Encrypt File", command=lambda: encrypt_file(file_to_encrypt_entry.get(), password_encrypt_entry.get()))
    encrypt_button.grid(row=2, column=0, columnspan=3, pady=10)

    # --- Decrypt Section ---
    decrypt_frame = LabelFrame(root, text="Decrypt File", padx=10, pady=10)
    decrypt_frame.grid(row=1, column=0, padx=20, pady=20, sticky="nsew")

    file_to_decrypt_label = Label(decrypt_frame, text="Select File to Decrypt:")
    file_to_decrypt_label.grid(row=0, column=0, pady=5)
    file_to_decrypt_entry = Entry(decrypt_frame, width=40)
    file_to_decrypt_entry.grid(row=0, column=1, pady=5)

    browse_button_decrypt = Button(decrypt_frame, text="Browse", command=lambda: browse_file_to_decrypt(file_to_decrypt_entry))
    browse_button_decrypt.grid(row=0, column=2, padx=5)

    password_decrypt_label = Label(decrypt_frame, text="Enter Password:")
    password_decrypt_label.grid(row=1, column=0, pady=5)
    password_decrypt_entry = Entry(decrypt_frame, width=40, show="*")
    password_decrypt_entry.grid(row=1, column=1, pady=5)

    decrypt_button = Button(decrypt_frame, text="Decrypt File", command=lambda: decrypt_file(file_to_decrypt_entry.get(), password_decrypt_entry.get()))
    decrypt_button.grid(row=2, column=0, columnspan=3, pady=10)

    # --- Run the GUI Loop ---
    root.mainloop()


# --- Run the Application ---
if __name__ == "__main__":
    create_gui()
