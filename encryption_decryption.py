import os
import time
import tkinter as tk
from tkinter import filedialog, messagebox, StringVar
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hashlib import sha256
from PIL import Image, ImageTk, ImageDraw

class EncryptionManager:
    def __init__(self, password):
        self.key = self.generate_key(password)

    @staticmethod
    def generate_key(password):
        if not password:
            raise ValueError("Password cannot be empty.")
        return sha256(password.encode()).digest()

    @staticmethod
    def aes_encrypt(key, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        return iv + encryptor.update(plaintext) + encryptor.finalize()

    @staticmethod
    def aes_decrypt(key, ciphertext):
        iv = ciphertext[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext[16:]) + decryptor.finalize()

    @staticmethod
    def fernet_encrypt(key, plaintext):
        fernet = Fernet(key)
        return fernet.encrypt(plaintext)

    @staticmethod
    def fernet_decrypt(key, ciphertext):
        fernet = Fernet(key)
        return fernet.decrypt(ciphertext)


class FileProcessor:
    def __init__(self, encryption_manager, method="AES"):
        self.encryption_manager = encryption_manager
        self.method = method

    def process_file(self, file_path, action):
        try:
            with open(file_path, "rb") as file:
                data = file.read()

            if self.method == "AES":
                if action == "encrypt":
                    processed_data = self.encryption_manager.aes_encrypt(self.encryption_manager.key, data)
                else:
                    processed_data = self.encryption_manager.aes_decrypt(self.encryption_manager.key, data)
            elif self.method == "Fernet":
                key_file_path = f"{file_path}.key"
                if action == "encrypt":
                    key = Fernet.generate_key()
                    with open(key_file_path, "wb") as key_file:
                        key_file.write(key)
                    processed_data = self.encryption_manager.fernet_encrypt(key, data)
                else:
                    if not os.path.exists(key_file_path):
                        print(f"Error: Key file not found for {file_path}.")
                        return False
                    with open(key_file_path, "rb") as key_file:
                        key = key_file.read()
                    try:
                        processed_data = self.encryption_manager.fernet_decrypt(key, data)
                    except InvalidToken:
                        messagebox.showerror("Error", "Nice Try!! Better luck next time.")
                        return False
                    os.remove(key_file_path)

            with open(file_path, "wb") as file:
                file.write(processed_data)
        except Exception as e:
            print(f"Error {action}ing {file_path}: {e}")
            return False
        return True

    def process_files(self, path, action):
        success = True
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if not self.process_file(file_path, action):
                        success = False
                    else:
                        self.log_metadata(action, file_path)
        else:
            if not self.process_file(path, action):
                success = False
            else:
                self.log_metadata(action, path)
        return success

    @staticmethod
    def log_metadata(action, file_path):
        with open("encryption_log.txt", "a") as log_file:
            log_file.write(f"{time.ctime()} - {action.upper()} - {file_path}\n")


class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Encryption App")
        self.root.configure(bg='#1E1E1E')
        self.root.geometry("600x400")
        self.root.resizable(False, False)

        self.add_logo()

        self.file_path = StringVar()
        self.password = StringVar()
        self.method = StringVar(value="AES")

        self.configure_layout()
        self.create_widgets()

    def add_logo(self):
        logo_image = Image.open("icons/logo.webp")
        logo_image = logo_image.resize((50, 50), Image.LANCZOS)
        logo_image = self.create_rounded_image(logo_image, 5)
        self.logo_photo = ImageTk.PhotoImage(logo_image)
        logo_label = tk.Label(self.root, image=self.logo_photo, bg='#1E1E1E')
        logo_label.grid(row=0, column=1, sticky="ne", padx=(0, 10), pady=(10, 0))

    @staticmethod
    def create_rounded_image(image, border_width):
        width, height = image.size
        rounded_image = Image.new('RGBA', (width + border_width * 2, height + border_width * 2), (255, 255, 255, 0))
        draw = ImageDraw.Draw(rounded_image)
        draw.ellipse((0, 0, width + border_width * 2, height + border_width * 2), fill=(255, 215, 0))
        mask = Image.new('L', (width, height), 0)
        mask_draw = ImageDraw.Draw(mask)
        mask_draw.ellipse((0, 0, width, height), fill=255)
        rounded_image.paste(image, (border_width, border_width), mask)
        return rounded_image

    def configure_layout(self):
        for i in range(6):
            self.root.grid_rowconfigure(i, weight=1)
        for j in range(2):
            self.root.grid_columnconfigure(j, weight=1)

    def create_widgets(self):
        self.create_custom_label("Select File or Folder:", 0, 0)
        self.create_custom_button("Select File", self.select_file, "icons/file_icon.png", 1, 0)
        self.create_custom_button("Select Folder", self.select_folder, "icons/folder_icon.png", 1, 1)

        self.create_custom_label("Enter Password:", 2, 0)
        tk.Entry(self.root, textvariable=self.password, show="*", width=30).grid(row=2, column=1, padx=10, pady=5)

        self.create_custom_label("Select Encryption Method:", 3, 0)
        self.create_method_selection()

        self.create_custom_button("Encrypt", lambda: self.process("encrypt"), "icons/encrypt.png", 4, 0)
        self.create_custom_button("Decrypt", lambda: self.process("decrypt"), "icons/decrypt.png", 4, 1)

        self.create_footer()

    def create_custom_label(self, text, row, col):
        label = tk.Label(self.root, text=text, bg='#1E1E1E', fg="gold", font=("Arial", 12, "bold"))
        label.grid(row=row, column=col, padx=10, pady=5, sticky="w")

    def create_custom_button(self, text, command, icon_path, row, col):
        original_image = Image.open(icon_path)
        resized_image = original_image.resize((25, 25), Image.LANCZOS)
        button_image = ImageTk.PhotoImage(resized_image)
        button = tk.Button(self.root, text=text, command=command, bg='#4C4C4C', fg='gold', font=('Arial', 12, 'bold'), image=button_image, compound=tk.LEFT)
        button.image = button_image
        button.grid(row=row, column=col, padx=5, pady=5, sticky="ew")

    def create_method_selection(self):
        method_frame = tk.Frame(self.root, bg='#1E1E1E')
        method_frame.grid(row=3, column=1, padx=10, pady=5, sticky="ew")
        method_options = ["AES", "Fernet"]
        method_menu = tk.OptionMenu(method_frame, self.method, *method_options)
        method_menu.config(bg='#4C4C4C', fg='gold', font=('Arial', 12, 'bold'))
        method_menu.grid(row=0, column=0, padx=10, pady=5)

    def create_footer(self):
        footer_label = tk.Label(self.root, text="Made by Redwan Hasan", bg='#1E1E1E', fg='gold', font=("Arial", 10, "italic"))
        footer_label.grid(row=5, column=0, columnspan=2, pady=(10, 0))

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path.set(file_path)

    def select_folder(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.file_path.set(folder_path)

    def process(self, action):
        if not self.file_path.get():
            messagebox.showwarning("Warning", "Please select a file or folder.")
            return
        if not self.password.get():
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        encryption_manager = EncryptionManager(self.password.get())
        file_processor = FileProcessor(encryption_manager, self.method.get())
        
        success = file_processor.process_files(self.file_path.get(), action)
        if success:
            messagebox.showinfo("Success", f"Files {action}ed successfully.")


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()