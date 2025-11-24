import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken 
import base64
import hashlib
import os
import threading

CHUNK_SIZE = 67108864
class FileLockerApp:
    def __init__(self, master):
        self.master = master
        master.title("Secure File Locker (.en)")
        master.configure(bg="#f0f0f0")

        self.file_path = tk.StringVar()
        self.password = tk.StringVar()
        self.status_text = tk.StringVar()
        self.status_text.set("Ready. Select a file to begin.")
        self.password_visible = False
        self.is_processing = False
        self.delete_source = tk.IntVar()

        self.bg_color = "#2c3e50"
        self.fg_color = "white"
        self.button_color = "#3498db"
        self.active_color = "#2980b9"
        
        master.columnconfigure(0, weight=1)
        master.columnconfigure(1, weight=1)

        title_label = tk.Label(master, text="AES File Encryption/Decryption", bg=self.bg_color, fg=self.fg_color, font=("Arial", 16, "bold"), padx=10, pady=10)
        title_label.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 20))

        tk.Label(master, text="File Path:", bg="#f0f0f0", font=("Arial", 10)).grid(row=1, column=0, sticky="w", padx=(10, 0), pady=5)
        
        file_entry = tk.Entry(master, textvariable=self.file_path, width=40, relief="flat", borderwidth=2, highlightthickness=1)
        file_entry.grid(row=2, column=0, sticky="ew", padx=10, pady=5)
        
        browse_button = tk.Button(master, text="Browse", command=self.browse_file, bg=self.button_color, fg=self.fg_color, activebackground=self.active_color, relief="flat", font=("Arial", 10, "bold"))
        browse_button.grid(row=2, column=1, sticky="w", padx=(0, 10), pady=5)

        tk.Label(master, text="Password:", bg="#f0f0f0", font=("Arial", 10)).grid(row=3, column=0, sticky="w", padx=(10, 0), pady=5)
        
        password_frame = tk.Frame(master, bg="#f0f0f0")
        password_frame.grid(row=4, column=0, columnspan=2, sticky="ew", padx=10, pady=5)
        password_frame.columnconfigure(0, weight=1)

        self.password_entry = tk.Entry(password_frame, textvariable=self.password, show="*", relief="flat", borderwidth=2, highlightthickness=1, font=("Arial", 10))
        self.password_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))

        self.show_hide_button = tk.Button(
            password_frame, 
            text="👁️", 
            command=self.toggle_password_visibility, 
            width=3, 
            bg="#bdc3c7", 
            activebackground="#95a5a6", 
            relief="flat", 
            font=("Arial", 10)
        )
        self.show_hide_button.grid(row=0, column=1, sticky="e")
        delete_checkbox = tk.Checkbutton(master, 
                                         text="Delete Source File after Successful Operation", 
                                         variable=self.delete_source,
                                         bg="#f0f0f0", 
                                         font=("Arial", 10))
        delete_checkbox.grid(row=5, column=0, columnspan=2, sticky="w", padx=10, pady=10) 
        encrypt_button = tk.Button(master, text="🔒 ENCRYPT (.en)", command=lambda: self.start_action(self.encrypt_file_threaded), bg="#27ae60", fg=self.fg_color, activebackground="#2ecc71", relief="flat", font=("Arial", 12, "bold"), padx=10, pady=5)
        encrypt_button.grid(row=6, column=0, sticky="ew", padx=10, pady=15)

        decrypt_button = tk.Button(master, text="🔓 DECRYPT (Original)", command=lambda: self.start_action(self.decrypt_file_threaded), bg="#e74c3c", fg=self.fg_color, activebackground="#c0392b", relief="flat", font=("Arial", 12, "bold"), padx=10, pady=15)
        decrypt_button.grid(row=6, column=1, sticky="ew", padx=10, pady=15)
        
        self.progress_bar = ttk.Progressbar(master, orient="horizontal", length=300, mode="determinate")
        self.progress_bar.grid(row=7, column=0, columnspan=2, sticky="ew", padx=10, pady=5)

        status_label = tk.Label(master, textvariable=self.status_text, bd=1, relief="sunken", anchor="w", bg="#ecf0f1", fg="#7f8c8d", font=("Arial", 9))
        status_label.grid(row=8, column=0, columnspan=2, sticky="ew", padx=0, pady=0)


    def toggle_password_visibility(self):
        if self.password_visible:
            self.password_entry.config(show="*")
            self.show_hide_button.config(text="👁️")
            self.password_visible = False
        else:
            self.password_entry.config(show="")
            self.show_hide_button.config(text="🙈")
            self.password_visible = True

    def generate_fernet_key(self, password: str) -> bytes:
        hash_object = hashlib.sha256(password.encode())
        key_bytes = hash_object.digest()
        return base64.urlsafe_b64encode(key_bytes)

    def browse_file(self):
        if self.is_processing:
            messagebox.showinfo("Wait", "Please wait for the current operation to complete.")
            return

        filepath = filedialog.askopenfilename()
        if filepath:
            self.file_path.set(filepath)
            self.status_text.set(f"File selected: {os.path.basename(filepath)}")
            self.progress_bar['value'] = 0

    def start_action(self, action_func):
        if self.is_processing:
            messagebox.showinfo("Wait", "An operation is already in progress.")
            return
            
        filepath = self.file_path.get()
        password = self.password.get()

        if not filepath or not os.path.exists(filepath):
            messagebox.showerror("Error", "Please select a valid file.")
            return
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return
            
        self.is_processing = True
        self.progress_bar['value'] = 0
        self.status_text.set("Starting process... Reading file in chunks.")
        
        threading.Thread(target=action_func, args=(filepath, password)).start()
        
    def encrypt_file_threaded(self, filepath: str, password: str):
        key = self.generate_fernet_key(password)
        output_filepath = filepath + ".en"
        
        if os.path.exists(output_filepath):
            if not messagebox.askyesno("Confirm Overwrite", 
                f"The file '{os.path.basename(output_filepath)}' already exists. Do you want to overwrite it?"):
                self.cleanup(success=False, message="Encryption cancelled by user.")
                return

        try:
            self.encrypt_file(filepath, key, output_filepath)
            # Pass original filepath for deletion check
            self.cleanup(success=True, message=f"SUCCESS: File encrypted and saved to {os.path.basename(output_filepath)}", original_filepath=filepath)
        except Exception as e:
            self.cleanup(success=False, error_title="Encryption Failed", error_message=f"An error occurred: {e}")

    def decrypt_file_threaded(self, filepath: str, password: str):
        key = self.generate_fernet_key(password)
        
        decrypted_filepath = filepath.rsplit('.', 1)[0] if filepath.lower().endswith('.en') else filepath + "_decrypted"
        
        if os.path.exists(decrypted_filepath):
            if not messagebox.askyesno("Confirm Overwrite", 
                f"The file '{os.path.basename(decrypted_filepath)}' already exists. Do you want to overwrite it?"):
                self.cleanup(success=False, message="Decryption cancelled by user.")
                return

        try:
            self.decrypt_file(filepath, key, decrypted_filepath)
            self.cleanup(success=True, message=f"SUCCESS: File decrypted and saved to {os.path.basename(decrypted_filepath)}", original_filepath=filepath)
        except InvalidToken:
            self.cleanup(success=False, error_title="Decryption Failed", error_message="Invalid password or corrupted file. Decryption aborted.")
        except Exception as e:
            self.cleanup(success=False, error_title="Decryption Failed", error_message=f"An error occurred: {e}")
            
    def encrypt_file(self, filepath: str, key: bytes, output_filepath: str):
        file_size = os.path.getsize(filepath)
        bytes_processed = 0

        self.status_text.set(f"Encrypting... 0% ({self.format_bytes(file_size)})")

        with open(filepath, "rb") as infile, open(output_filepath, "wb") as outfile:
            
            while True:
                chunk = infile.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                f = Fernet(key) 
                
                encrypted_chunk_token = f.encrypt(chunk)
                outfile.write(encrypted_chunk_token)
                
                bytes_processed += len(chunk)
                progress = int((bytes_processed / file_size) * 100)
                
                self.master.after(0, self.update_progress, progress, f"Encrypting... {progress}%")

    def decrypt_file(self, filepath: str, key: bytes, output_filepath: str):
        file_size = os.path.getsize(filepath)
        bytes_processed = 0
        
        self.status_text.set(f"Decrypting... 0% ({self.format_bytes(file_size)})")

        with open(filepath, "rb") as infile, open(output_filepath, "wb") as outfile:
            
            while True:
                token_data = infile.read(CHUNK_SIZE + 56) 
                
                if not token_data:
                    break
                
                f = Fernet(key)
                
                decrypted_chunk = f.decrypt(token_data)
                
                outfile.write(decrypted_chunk)
                
                bytes_processed += len(token_data)
                progress = int((infile.tell() / file_size) * 100)
                
                self.master.after(0, self.update_progress, progress, f"Decrypting... {progress}%")
            
    def cleanup(self, success: bool, message: str = "", error_title: str = None, error_message: str = None, original_filepath: str = None):
        self.is_processing = False
        self.password.set("")
        self.password_entry.config(show="*")
        self.show_hide_button.config(text="👁️")
        self.password_visible = False
        
        if success:
            self.master.after(0, self.status_text.set, message)
            self.master.after(0, self.progress_bar.stop)
            self.master.after(0, self.progress_bar.config, {'value': 100})
            if self.delete_source.get() == 1 and original_filepath and os.path.exists(original_filepath):
                try:
                    os.remove(original_filepath)
                    messagebox.showinfo("Deleted", f"Source file '{os.path.basename(original_filepath)}' deleted successfully.")
                except Exception as e:
                    messagebox.showwarning("Deletion Failed", f"Could not delete the source file: {e}")
        else:
            self.master.after(0, self.status_text.set, "Ready. Operation failed or cancelled.")
            self.master.after(0, self.progress_bar.config, {'value': 0})
            if error_title and error_message:
                self.master.after(0, messagebox.showerror, error_title, error_message)

    def update_progress(self, value, text):
        self.progress_bar['value'] = value
        self.status_text.set(text)

    def format_bytes(self, size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:3.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
if __name__ == "__main__":
    root = tk.Tk()
    root.style = ttk.Style()
    root.iconbitmap("icon.ico")
    root.style.configure("TProgressbar", thickness=15) 
    app = FileLockerApp(root)
    root.update_idletasks()
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    window_width = root.winfo_width()
    window_height = root.winfo_height()
    position_right = int(screen_width / 2 - window_width / 2)
    position_down = int(screen_height / 2 - window_height / 2)
    root.geometry(f"+{position_right}+{position_down}")
    root.mainloop()