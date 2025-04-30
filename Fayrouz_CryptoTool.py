import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from Crypto.Cipher import AES, DES, DES3
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA1, SHA224, SHA512, MD5
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import base64
from Crypto.Util.Padding import pad, unpad
import os
BG_COLOR = "#ECECEC"       
FG_COLOR = "#2F2F33"      
ACCENT_COLOR = "#A7C7E7"  
SECONDARY_COLOR = "#D5A6BD" 
TEXT_BG = "#E2E2E7"        
ERROR_COLOR = "#FF8A80"    
BUTTON_BG = "#D3D3D8"            
class CryptoToolWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Fayrouz_CryptoTool")
        self.root.geometry("1000x800")
        self.root.configure(bg=BG_COLOR)
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TNotebook', background=BG_COLOR)
        self.style.configure('TNotebook.Tab', background=BG_COLOR, foreground=FG_COLOR)
        self.style.map('TNotebook.Tab', background=[('selected', SECONDARY_COLOR)])
        self.tabs = ttk.Notebook(root)
        self.tabs.pack(expand=1, fill="both", padx=10, pady=10)
        self.create_symmetric_tab()
        self.create_asymmetric_tab()
        self.create_hashing_tab()
        self.create_signature_tab()
        self.status_var = tk.StringVar()
        self.status_bar = tk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, bg=BG_COLOR, fg=FG_COLOR)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
        self.status_var.set("Ready - Select an operation")
        tk.Button(root, text="Exit", command=root.quit, bg=ERROR_COLOR, fg=FG_COLOR,font=('Helvetica', 10, 'bold')).pack(side=tk.RIGHT, padx=10, pady=5)
    def create_symmetric_tab(self):
        self.symmetric_tab = ttk.Frame(self.tabs)
        self.tabs.add(self.symmetric_tab, text="Symmetric Encryption")
        self.symmetric_notebook = ttk.Notebook(self.symmetric_tab)
        self.symmetric_notebook.pack(expand=1, fill="both", padx=5, pady=5)      
        self.block_tab = ttk.Frame(self.symmetric_notebook)
        self.symmetric_notebook.add(self.block_tab, text="Block Ciphers")
        self.stream_tab = ttk.Frame(self.symmetric_notebook)
        self.symmetric_notebook.add(self.stream_tab, text="Stream Ciphers")
        self.create_block_cipher_ui()
        self.create_stream_cipher_ui()
    def create_block_cipher_ui(self):
        algo_frame = tk.LabelFrame(self.block_tab, text="Algorithm Selection", bg=BG_COLOR, fg=FG_COLOR)
        algo_frame.pack(fill=tk.X, padx=10, pady=5)
        self.block_algo = tk.StringVar(value="AES")       
        tk.Radiobutton(algo_frame, text="AES", variable=self.block_algo, value="AES",command=self.update_block_ui, bg=BG_COLOR, fg=FG_COLOR,selectcolor=BG_COLOR, activebackground=BG_COLOR).pack(side=tk.LEFT, padx=10)        
        tk.Radiobutton(algo_frame, text="DES", variable=self.block_algo, value="DES",command=self.update_block_ui, bg=BG_COLOR, fg=FG_COLOR,selectcolor=BG_COLOR, activebackground=BG_COLOR).pack(side=tk.LEFT, padx=10)    
        self.options_frame = tk.Frame(self.block_tab, bg=BG_COLOR)
        self.options_frame.pack(fill=tk.X, padx=10, pady=5)
        self.key_frame = tk.LabelFrame(self.block_tab, text="Key Management", bg=BG_COLOR, fg=FG_COLOR)
        self.key_frame.pack(fill=tk.X, padx=10, pady=5)   
        op_frame = tk.LabelFrame(self.block_tab, text="Operation", bg=BG_COLOR, fg=FG_COLOR)
        op_frame.pack(fill=tk.X, padx=10, pady=5)    
        self.block_operation = ttk.Combobox(op_frame, values=["Encrypt", "Decrypt"], state="readonly")
        self.block_operation.current(0)
        self.block_operation.pack(pady=5)
        self.block_operation.bind("<<ComboboxSelected>>", self.update_block_ui)
        input_frame = tk.LabelFrame(self.block_tab, text="Input", bg=BG_COLOR, fg=FG_COLOR)
        input_frame.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)       
        self.block_input = scrolledtext.ScrolledText(input_frame, height=8, bg=TEXT_BG, fg=FG_COLOR)
        self.block_input.pack(fill=tk.BOTH, expand=1, padx=5, pady=5)
        file_btn_frame = tk.Frame(input_frame, bg=BG_COLOR)
        file_btn_frame.pack(fill=tk.X, pady=5)
        tk.Button(file_btn_frame, text="Upload File", command=self.upload_block_file,bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        tk.Button(file_btn_frame, text="Clear", command=self.clear_block_input,bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        output_frame = tk.LabelFrame(self.block_tab, text="Output", bg=BG_COLOR, fg=FG_COLOR)
        output_frame.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)
        self.block_output = scrolledtext.ScrolledText(output_frame, height=8, state=tk.DISABLED, bg=TEXT_BG, fg=FG_COLOR)
        self.block_output.pack(fill=tk.BOTH, expand=1, padx=5, pady=5)
        action_frame = tk.Frame(self.block_tab, bg=BG_COLOR)
        action_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Button(action_frame, text="Execute", command=self.execute_block_operation,bg=ACCENT_COLOR, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="Save Output", command=self.save_block_output,bg=SECONDARY_COLOR, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        self.update_block_ui()
    def create_stream_cipher_ui(self):
        algo_frame = tk.LabelFrame(self.stream_tab, text="Algorithm Selection", bg=BG_COLOR, fg=FG_COLOR)
        algo_frame.pack(fill=tk.X, padx=10, pady=5)
        self.stream_algo = tk.StringVar(value="Caesar")
        tk.Radiobutton(algo_frame, text="Caesar Cipher", variable=self.stream_algo, value="Caesar",command=self.update_stream_ui, bg=BG_COLOR, fg=FG_COLOR,selectcolor=BG_COLOR, activebackground=BG_COLOR).pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(algo_frame, text="Vigenère Cipher", variable=self.stream_algo, value="Vigenere",command=self.update_stream_ui, bg=BG_COLOR, fg=FG_COLOR,selectcolor=BG_COLOR, activebackground=BG_COLOR).pack(side=tk.LEFT, padx=10)
        self.stream_options_frame = tk.Frame(self.stream_tab, bg=BG_COLOR)
        self.stream_options_frame.pack(fill=tk.X, padx=10, pady=5)
        self.stream_key_frame = tk.LabelFrame(self.stream_tab, text="Key", bg=BG_COLOR, fg=FG_COLOR)
        self.stream_key_frame.pack(fill=tk.X, padx=10, pady=5)
        op_frame = tk.LabelFrame(self.stream_tab, text="Operation", bg=BG_COLOR, fg=FG_COLOR)
        op_frame.pack(fill=tk.X, padx=10, pady=5)
        self.stream_operation = ttk.Combobox(op_frame, values=["Encrypt", "Decrypt"], state="readonly")
        self.stream_operation.current(0)
        self.stream_operation.pack(pady=5)
        input_frame = tk.LabelFrame(self.stream_tab, text="Input", bg=BG_COLOR, fg=FG_COLOR)
        input_frame.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)
        self.stream_input = scrolledtext.ScrolledText(input_frame, height=8, bg=TEXT_BG, fg=FG_COLOR)
        self.stream_input.pack(fill=tk.BOTH, expand=1, padx=5, pady=5)
        file_btn_frame = tk.Frame(input_frame, bg=BG_COLOR)
        file_btn_frame.pack(fill=tk.X, pady=5)
        tk.Button(file_btn_frame, text="Upload File", command=self.upload_stream_file,bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        tk.Button(file_btn_frame, text="Clear", command=self.clear_stream_input,bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        output_frame = tk.LabelFrame(self.stream_tab, text="Output", bg=BG_COLOR, fg=FG_COLOR)
        output_frame.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)
        self.stream_output = scrolledtext.ScrolledText(output_frame, height=8, state=tk.DISABLED,bg=TEXT_BG, fg=FG_COLOR)
        self.stream_output.pack(fill=tk.BOTH, expand=1, padx=5, pady=5)
        action_frame = tk.Frame(self.stream_tab, bg=BG_COLOR)
        action_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Button(action_frame, text="Execute", command=self.execute_stream_operation,bg=ACCENT_COLOR, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="Save Output", command=self.save_stream_output,bg=SECONDARY_COLOR, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        self.update_stream_ui()
    def update_block_ui(self, event=None):
        for widget in self.options_frame.winfo_children():
            widget.destroy()
        for widget in self.key_frame.winfo_children():
            widget.destroy()
        algo = self.block_algo.get()
        operation = self.block_operation.get()
        if algo == "AES":
            tk.Label(self.options_frame, text="AES Key Size:", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT)
            self.aes_key_size = ttk.Combobox(self.options_frame, values=["128-bit", "192-bit", "256-bit"], state="readonly")
            self.aes_key_size.current(2)  # Default to 256-bit
            self.aes_key_size.pack(side=tk.LEFT, padx=5)
            tk.Label(self.key_frame, text="Key (Base64):", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT) 
            self.aes_key_entry = tk.Entry(self.key_frame, width=50, bg=TEXT_BG, fg=FG_COLOR)
            self.aes_key_entry.pack(side=tk.LEFT, padx=5)
            tk.Button(self.key_frame, text="Generate", command=self.generate_aes_key,bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
            if operation == "Decrypt":
                tk.Label(self.key_frame, text="IV (Base64):", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT)
                self.aes_iv_entry = tk.Entry(self.key_frame, width=40, bg=TEXT_BG, fg=FG_COLOR)
                self.aes_iv_entry.pack(side=tk.LEFT, padx=5)
        elif algo == "DES":
            tk.Label(self.options_frame, text="DES Type:", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT)
            self.des_type = ttk.Combobox(self.options_frame, values=["Standard DES", "Double DES", "Triple DES"], state="readonly")
            self.des_type.current(0)
            self.des_type.pack(side=tk.LEFT, padx=5)
            self.des_type.bind("<<ComboboxSelected>>", self.update_des_ui)
            self.update_des_ui()
    def update_des_ui(self, event=None):
        for widget in self.key_frame.winfo_children():
            widget.destroy()
        des_type = self.des_type.get()
        operation = self.block_operation.get()
        if des_type == "Standard DES":
            tk.Label(self.key_frame, text="Key (8 bytes, Base64):", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT)
            self.des_key_entry = tk.Entry(self.key_frame, width=50, bg=TEXT_BG, fg=FG_COLOR)
            self.des_key_entry.pack(side=tk.LEFT, padx=5)
            tk.Button(self.key_frame, text="Generate", command=self.generate_des_key,bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
            if operation == "Decrypt":
                tk.Label(self.key_frame, text="IV (Base64):", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT)
                self.des_iv_entry = tk.Entry(self.key_frame, width=40, bg=TEXT_BG, fg=FG_COLOR)
                self.des_iv_entry.pack(side=tk.LEFT, padx=5)
        elif des_type == "Double DES":
            tk.Label(self.key_frame, text="Key 1 (8 bytes, Base64):", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT)
            self.des_key1_entry = tk.Entry(self.key_frame, width=30, bg=TEXT_BG, fg=FG_COLOR)
            self.des_key1_entry.pack(side=tk.LEFT, padx=5)
            tk.Label(self.key_frame, text="Key 2 (8 bytes, Base64):", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT)
            self.des_key2_entry = tk.Entry(self.key_frame, width=30, bg=TEXT_BG, fg=FG_COLOR)
            self.des_key2_entry.pack(side=tk.LEFT, padx=5)
            tk.Button(self.key_frame, text="Generate", command=self.generate_double_des_keys,bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
            if operation == "Decrypt":
                iv_frame = tk.Frame(self.key_frame, bg=BG_COLOR)
                iv_frame.pack(fill=tk.X, pady=5)
                tk.Label(iv_frame, text="IV 1 (Base64):", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT)
                self.des_iv1_entry = tk.Entry(iv_frame, width=25, bg=TEXT_BG, fg=FG_COLOR)
                self.des_iv1_entry.pack(side=tk.LEFT, padx=5)
                tk.Label(iv_frame, text="IV 2 (Base64):", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT)
                self.des_iv2_entry = tk.Entry(iv_frame, width=25, bg=TEXT_BG, fg=FG_COLOR)
                self.des_iv2_entry.pack(side=tk.LEFT, padx=5)
        elif des_type == "Triple DES":
            tk.Label(self.key_frame, text="Key (24 bytes, Base64):", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT)
            self.des3_key_entry = tk.Entry(self.key_frame, width=50, bg=TEXT_BG, fg=FG_COLOR)
            self.des3_key_entry.pack(side=tk.LEFT, padx=5)
            tk.Button(self.key_frame, text="Generate", command=self.generate_triple_des_key,bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
            if operation == "Decrypt":
                tk.Label(self.key_frame, text="IV (Base64):", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT)
                self.des3_iv_entry = tk.Entry(self.key_frame, width=40, bg=TEXT_BG, fg=FG_COLOR)
                self.des3_iv_entry.pack(side=tk.LEFT, padx=5)
    def update_stream_ui(self, event=None):
        for widget in self.stream_options_frame.winfo_children():
            widget.destroy()
        for widget in self.stream_key_frame.winfo_children():
            widget.destroy()
        algo = self.stream_algo.get()
        if algo == "Caesar":
            tk.Label(self.stream_options_frame, text="Shift Value:", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT)
            self.caesar_shift = tk.Spinbox(self.stream_options_frame, from_=1, to=25, width=5,bg=TEXT_BG, fg=FG_COLOR)
            self.caesar_shift.pack(side=tk.LEFT, padx=5)
            self.caesar_shift.delete(0, tk.END)
            self.caesar_shift.insert(0, "3")  # Default shift
        elif algo == "Vigenere":
            tk.Label(self.stream_key_frame, text="Key (letters only):", bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT)
            self.vigenere_key_entry = tk.Entry(self.stream_key_frame, width=30, bg=TEXT_BG, fg=FG_COLOR)
            self.vigenere_key_entry.pack(side=tk.LEFT, padx=5)
            self.vigenere_key_entry.insert(0, "SECRET")  # Default key
    def create_asymmetric_tab(self):
        self.asymmetric_tab = ttk.Frame(self.tabs)
        self.tabs.add(self.asymmetric_tab, text="Asymmetric Encryption")
        key_frame = tk.LabelFrame(self.asymmetric_tab, text="RSA Key Pair", bg=BG_COLOR, fg=FG_COLOR)
        key_frame.pack(fill=tk.X, padx=10, pady=5)
        key_btn_frame = tk.Frame(key_frame, bg=BG_COLOR)
        key_btn_frame.pack(fill=tk.X, pady=5)
        tk.Button(key_btn_frame, text="Generate Keys", command=self.generate_rsa_keys,bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        tk.Button(key_btn_frame, text="Load Public Key", command=lambda: self.load_rsa_key("public"),bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        tk.Button(key_btn_frame, text="Load Private Key", command=lambda: self.load_rsa_key("private"),bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        key_display_frame = tk.Frame(self.asymmetric_tab, bg=BG_COLOR)
        key_display_frame.pack(fill=tk.X, padx=10, pady=5)
        pub_key_frame = tk.LabelFrame(key_display_frame, text="Public Key", bg=BG_COLOR, fg=FG_COLOR)
        pub_key_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=1, padx=5)
        self.public_key_text = scrolledtext.ScrolledText(pub_key_frame, height=6, bg=TEXT_BG, fg=FG_COLOR)
        self.public_key_text.pack(fill=tk.BOTH, expand=1, padx=5, pady=5)
        priv_key_frame = tk.LabelFrame(key_display_frame, text="Private Key", bg=BG_COLOR, fg=FG_COLOR)
        priv_key_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=1, padx=5)
        self.private_key_text = scrolledtext.ScrolledText(priv_key_frame, height=6, bg=TEXT_BG, fg=FG_COLOR)
        self.private_key_text.pack(fill=tk.BOTH, expand=1, padx=5, pady=5)
        op_frame = tk.LabelFrame(self.asymmetric_tab, text="Operation", bg=BG_COLOR, fg=FG_COLOR)
        op_frame.pack(fill=tk.X, padx=10, pady=5)
        self.asym_operation = ttk.Combobox(op_frame, values=["Encrypt", "Decrypt"], state="readonly")
        self.asym_operation.current(0)
        self.asym_operation.pack(pady=5)
        input_frame = tk.LabelFrame(self.asymmetric_tab, text="Input", bg=BG_COLOR, fg=FG_COLOR)
        input_frame.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)
        self.asym_input = scrolledtext.ScrolledText(input_frame, height=8, bg=TEXT_BG, fg=FG_COLOR)
        self.asym_input.pack(fill=tk.BOTH, expand=1, padx=5, pady=5)
        file_btn_frame = tk.Frame(input_frame, bg=BG_COLOR)
        file_btn_frame.pack(fill=tk.X, pady=5)
        tk.Button(file_btn_frame, text="Upload File", command=self.upload_asym_file,bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        tk.Button(file_btn_frame, text="Clear", command=self.clear_asym_input,bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        output_frame = tk.LabelFrame(self.asymmetric_tab, text="Output", bg=BG_COLOR, fg=FG_COLOR)
        output_frame.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)
        self.asym_output = scrolledtext.ScrolledText(output_frame, height=8, state=tk.DISABLED,bg=TEXT_BG, fg=FG_COLOR)
        self.asym_output.pack(fill=tk.BOTH, expand=1, padx=5, pady=5)
        action_frame = tk.Frame(self.asymmetric_tab, bg=BG_COLOR)
        action_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Button(action_frame, text="Execute", command=self.execute_asym_operation,bg=ACCENT_COLOR, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="Save Output", command=self.save_asym_output,bg=SECONDARY_COLOR, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
    def create_hashing_tab(self):
        self.hashing_tab = ttk.Frame(self.tabs)
        self.tabs.add(self.hashing_tab, text="Hashing")
        algo_frame = tk.LabelFrame(self.hashing_tab, text="Hash Algorithm", bg=BG_COLOR, fg=FG_COLOR)
        algo_frame.pack(fill=tk.X, padx=10, pady=5)
        self.hash_algo = ttk.Combobox(algo_frame, values=["MD5", "SHA1", "SHA224", "SHA256", "SHA512"], state="readonly")
        self.hash_algo.current(3)  # Default to SHA256
        self.hash_algo.pack(pady=5)
        input_frame = tk.LabelFrame(self.hashing_tab, text="Input", bg=BG_COLOR, fg=FG_COLOR)
        input_frame.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)
        self.hash_input = scrolledtext.ScrolledText(input_frame, height=8, bg=TEXT_BG, fg=FG_COLOR)
        self.hash_input.pack(fill=tk.BOTH, expand=1, padx=5, pady=5)
        file_btn_frame = tk.Frame(input_frame, bg=BG_COLOR)
        file_btn_frame.pack(fill=tk.X, pady=5)
        tk.Button(file_btn_frame, text="Upload File", command=self.upload_hash_file,bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        tk.Button(file_btn_frame, text="Clear", command=self.clear_hash_input,bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        output_frame = tk.LabelFrame(self.hashing_tab, text="Hash Output", bg=BG_COLOR, fg=FG_COLOR)
        output_frame.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)
        self.hash_output = scrolledtext.ScrolledText(output_frame, height=8, state=tk.DISABLED,bg=TEXT_BG, fg=FG_COLOR)
        self.hash_output.pack(fill=tk.BOTH, expand=1, padx=5, pady=5)
        action_frame = tk.Frame(self.hashing_tab, bg=BG_COLOR)
        action_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Button(action_frame, text="Generate Hash", command=self.generate_hash,bg=ACCENT_COLOR, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="Save Output", command=self.save_hash_output,bg=SECONDARY_COLOR, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
    def create_signature_tab(self):
        self.signature_tab = ttk.Frame(self.tabs)
        self.tabs.add(self.signature_tab, text="Digital Signature")
        sig_frame = tk.LabelFrame(self.signature_tab, text="Signature Type", bg=BG_COLOR, fg=FG_COLOR)
        sig_frame.pack(fill=tk.X, padx=10, pady=5)
        self.sig_type = ttk.Combobox(sig_frame, values=["Standard Digital Signature", "Blind Signature"], state="readonly")
        self.sig_type.current(0)
        self.sig_type.pack(pady=5)
        self.sig_type.bind("<<ComboboxSelected>>", self.update_signature_ui)
        op_frame = tk.LabelFrame(self.signature_tab, text="Operation", bg=BG_COLOR, fg=FG_COLOR)
        op_frame.pack(fill=tk.X, padx=10, pady=5)
        self.sig_operation = ttk.Combobox(op_frame, values=["Sign", "Verify"], state="readonly")
        self.sig_operation.current(0)
        self.sig_operation.pack(pady=5)
        self.sig_operation.bind("<<ComboboxSelected>>", self.update_signature_ui)
        input_frame = tk.LabelFrame(self.signature_tab, text="Message", bg=BG_COLOR, fg=FG_COLOR)
        input_frame.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)
        self.sig_message = scrolledtext.ScrolledText(input_frame, height=8, bg=TEXT_BG, fg=FG_COLOR)
        self.sig_message.pack(fill=tk.BOTH, expand=1, padx=5, pady=5)
        file_btn_frame = tk.Frame(input_frame, bg=BG_COLOR)
        file_btn_frame.pack(fill=tk.X, pady=5)
        tk.Button(file_btn_frame, text="Upload File", command=self.upload_sig_file,bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        tk.Button(file_btn_frame, text="Clear", command=self.clear_sig_input,bg=BUTTON_BG, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        self.sig_input_frame = tk.LabelFrame(self.signature_tab, text="Signature", bg=BG_COLOR, fg=FG_COLOR)
        self.sig_input = scrolledtext.ScrolledText(self.sig_input_frame, height=4, bg=TEXT_BG, fg=FG_COLOR)
        self.sig_input.pack(fill=tk.BOTH, expand=1, padx=5, pady=5)
        output_frame = tk.LabelFrame(self.signature_tab, text="Output", bg=BG_COLOR, fg=FG_COLOR)
        output_frame.pack(fill=tk.BOTH, expand=1, padx=10, pady=5)
        self.sig_output = scrolledtext.ScrolledText(output_frame, height=8, state=tk.DISABLED,bg=TEXT_BG, fg=FG_COLOR)
        self.sig_output.pack(fill=tk.BOTH, expand=1, padx=5, pady=5)
        action_frame = tk.Frame(self.signature_tab, bg=BG_COLOR)
        action_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Button(action_frame, text="Execute", command=self.execute_sig_operation,bg=ACCENT_COLOR, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="Save Output", command=self.save_sig_output,bg=SECONDARY_COLOR, fg=FG_COLOR).pack(side=tk.LEFT, padx=5)
        self.update_signature_ui()
    def update_signature_ui(self, event=None):
        if self.sig_operation.get() == "Verify":
            self.sig_input_frame.pack(fill=tk.X, padx=10, pady=5)
        else:
            self.sig_input_frame.pack_forget()
        if self.sig_type.get() == "Blind Signature":
            self.status_var.set("Note: Blind signature implementation is simplified for demonstration")
    def generate_aes_key(self):
        size = self.aes_key_size.get()
        if size == "128-bit":
            key = get_random_bytes(16)
        elif size == "192-bit":
            key = get_random_bytes(24)
        else:  # 256-bit
            key = get_random_bytes(32)
        self.aes_key_entry.delete(0, tk.END)
        self.aes_key_entry.insert(0, base64.b64encode(key).decode('utf-8'))
        self.status_var.set(f"Generated {size} AES key")
    def generate_des_key(self):
        key = get_random_bytes(8)
        self.des_key_entry.delete(0, tk.END)
        self.des_key_entry.insert(0, base64.b64encode(key).decode('utf-8'))
        self.status_var.set("Generated 64-bit DES key")
    def generate_double_des_keys(self):
        key1 = get_random_bytes(8)
        key2 = get_random_bytes(8)
        self.des_key1_entry.delete(0, tk.END)
        self.des_key1_entry.insert(0, base64.b64encode(key1).decode('utf-8'))
        self.des_key2_entry.delete(0, tk.END)
        self.des_key2_entry.insert(0, base64.b64encode(key2).decode('utf-8'))
        self.status_var.set("Generated two 64-bit DES keys")
    def generate_triple_des_key(self):
        key = get_random_bytes(24)
        self.des3_key_entry.delete(0, tk.END)
        self.des3_key_entry.insert(0, base64.b64encode(key).decode('utf-8'))
        self.status_var.set("Generated 192-bit Triple DES key")
    def generate_rsa_keys(self):
        try:
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            self.private_key_text.config(state=tk.NORMAL)
            self.private_key_text.delete("1.0", tk.END)
            self.private_key_text.insert("1.0", private_key.decode('utf-8'))
            self.private_key_text.config(state=tk.DISABLED)
            self.public_key_text.config(state=tk.NORMAL)
            self.public_key_text.delete("1.0", tk.END)
            self.public_key_text.insert("1.0", public_key.decode('utf-8'))
            self.public_key_text.config(state=tk.DISABLED)
            self.status_var.set("Generated 2048-bit RSA key pair")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate RSA keys: {str(e)}")
            self.status_var.set("Key generation failed")
    def load_rsa_key(self, key_type):
        try:
            file_path = filedialog.askopenfilename(title=f"Select {key_type.capitalize()} Key File")
            if file_path:
                with open(file_path, "r") as f:
                    key_data = f.read()
                if key_type == "public":
                    self.public_key_text.config(state=tk.NORMAL)
                    self.public_key_text.delete("1.0", tk.END)
                    self.public_key_text.insert("1.0", key_data)
                    self.public_key_text.config(state=tk.DISABLED)
                else:
                    self.private_key_text.config(state=tk.NORMAL)
                    self.private_key_text.delete("1.0", tk.END)
                    self.private_key_text.insert("1.0", key_data)
                    self.private_key_text.config(state=tk.DISABLED)
                self.status_var.set(f"Loaded {key_type} key from file")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load {key_type} key: {str(e)}")
            self.status_var.set(f"Failed to load {key_type} key")
    def upload_block_file(self):
        self.upload_file(self.block_input, "block")
    def upload_stream_file(self):
        self.upload_file(self.stream_input, "stream")
    def upload_asym_file(self):
        self.upload_file(self.asym_input, "asymmetric")
    def upload_hash_file(self):
        self.upload_file(self.hash_input, "hash")
    def upload_sig_file(self):
        self.upload_file(self.sig_message, "signature")
    def upload_file(self, target_widget, operation_type):
        try:
            file_path = filedialog.askopenfilename(title=f"Select File for {operation_type.capitalize()}")
            if file_path:
                with open(file_path, "rb") as f:
                    content = f.read()
                try:
                    text_content = content.decode('utf-8')
                except UnicodeDecodeError:
                    text_content = base64.b64encode(content).decode('utf-8')
                target_widget.delete("1.0", tk.END)
                target_widget.insert("1.0", text_content)
                self.status_var.set(f"Loaded file: {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")
            self.status_var.set("File upload failed")
    def clear_block_input(self):
        self.block_input.delete("1.0", tk.END)
        self.status_var.set("Block cipher input cleared")
    def clear_stream_input(self):
        self.stream_input.delete("1.0", tk.END)
        self.status_var.set("Stream cipher input cleared")
    def clear_asym_input(self):
        self.asym_input.delete("1.0", tk.END)
        self.status_var.set("Asymmetric input cleared")
    def clear_hash_input(self):
        self.hash_input.delete("1.0", tk.END)
        self.status_var.set("Hash input cleared")
    def clear_sig_input(self):
        self.sig_message.delete("1.0", tk.END)
        if self.sig_operation.get() == "Verify":
            self.sig_input.delete("1.0", tk.END)
        self.status_var.set("Signature input cleared")
    def save_block_output(self):
        self.save_output(self.block_output, "block_cipher")
    def save_stream_output(self):
        self.save_output(self.stream_output, "stream_cipher")
    def save_asym_output(self):
        self.save_output(self.asym_output, "asymmetric")
    def save_hash_output(self):
        self.save_output(self.hash_output, "hash")
    def save_sig_output(self):
        self.save_output(self.sig_output, "signature")
    def save_output(self, source_widget, operation_type):
        try:
            content = source_widget.get("1.0", tk.END)
            if not content.strip():
                messagebox.showwarning("Warning", "No output to save")
                return
            file_path = filedialog.asksaveasfilename(
                title=f"Save {operation_type.replace('_', ' ').title()} Output",
                defaultextension=".txt",
                filetypes=[("Text files", ".txt"), ("All files", ".*")])
            if file_path:
                with open(file_path, "w") as f:
                    f.write(content)
                self.status_var.set(f"Output saved to {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save output: {str(e)}")
            self.status_var.set("Output save failed")
    def execute_block_operation(self):
        algo = self.block_algo.get()
        operation = self.block_operation.get()
        input_text = self.block_input.get("1.0", tk.END).strip()
        if not input_text:
            messagebox.showwarning("Warning", "Please enter input text")
            return
        try:
            if algo == "AES":
                self.execute_aes_operation(operation, input_text)
            elif algo == "DES":
                self.execute_des_operation(operation, input_text)
        except Exception as e:
            messagebox.showerror("Error", f"Operation failed: {str(e)}")
            self.status_var.set(f"{algo} operation failed")
    def execute_aes_operation(self, operation, input_text):
        key_b64 = self.aes_key_entry.get().strip()
        if not key_b64:
            messagebox.showwarning("Warning", "Please enter or generate a key")
            return
        try:
            key = base64.b64decode(key_b64)
            if len(key) not in [16, 24, 32]:
                messagebox.showerror("Error", "Invalid AES key length (must be 16, 24, or 32 bytes)")
                return
            if operation == "Encrypt":
                iv, ct = aes_encrypt(key, input_text)
                output = f"IV (Base64): {iv}\nCiphertext (Base64): {ct}"
                self.status_var.set("AES encryption successful")
            else:
                iv_b64 = self.aes_iv_entry.get().strip()
                if not iv_b64:
                    messagebox.showwarning("Warning", "Please enter IV for decryption")
                    return
                pt = aes_decrypt(key, iv_b64, input_text)
                output = f"Plaintext: {pt}"
                self.status_var.set("AES decryption successful")
            self.display_output(self.block_output, output)
        except Exception as e:
            raise Exception(f"AES {operation.lower()} failed: {str(e)}")
    def execute_des_operation(self, operation, input_text):
        des_type = self.des_type.get()      
        try:
            if des_type == "Standard DES":
                self.execute_standard_des(operation, input_text)
            elif des_type == "Double DES":
                self.execute_double_des(operation, input_text)
            elif des_type == "Triple DES":
                self.execute_triple_des(operation, input_text)
        except Exception as e:
            raise Exception(f"{des_type} {operation.lower()} failed: {str(e)}")

    def execute_standard_des(self, operation, input_text):
        """Execute standard DES encryption/decryption"""
        key_b64 = self.des_key_entry.get().strip()
        if not key_b64:
            messagebox.showwarning("Warning", "Please enter or generate a key")
            return
        
        try:
            key = base64.b64decode(key_b64)
            
            # Validate key length (8 bytes for DES)
            if len(key) != 8:
                messagebox.showerror("Error", "Invalid DES key length (must be 8 bytes)")
                return
            
            if operation == "Encrypt":
                iv, ct = des_encrypt(key, input_text)
                output = f"IV (Base64): {iv}\nCiphertext (Base64): {ct}"
                self.status_var.set("DES encryption successful")
            else:
                iv_b64 = self.des_iv_entry.get().strip()
                if not iv_b64:
                    messagebox.showwarning("Warning", "Please enter IV for decryption")
                    return
                
                pt = des_decrypt(key, iv_b64, input_text)
                output = f"Plaintext: {pt}"
                self.status_var.set("DES decryption successful")
            
            self.display_output(self.block_output, output)
        except Exception as e:
            raise Exception(f"Standard DES {operation.lower()} failed: {str(e)}")
    def execute_double_des(self, operation, input_text):
        """Execute double DES encryption/decryption"""
        key1_b64 = self.des_key1_entry.get().strip()
        key2_b64 = self.des_key2_entry.get().strip()
        
        if not key1_b64 or not key2_b64:
            messagebox.showwarning("Warning", "Please enter or generate both keys")
            return
        
        try:
            key1 = base64.b64decode(key1_b64)
            key2 = base64.b64decode(key2_b64)
            
            # Validate key lengths (8 bytes each)
            if len(key1) != 8 or len(key2) != 8:
                messagebox.showerror("Error", "Invalid DES key length (must be 8 bytes each)")
                return
            
            if operation == "Encrypt":
                iv1, iv2, ct = double_des_encrypt(key1, key2, input_text)
                output = f"IV1 (Base64): {iv1}\nIV2 (Base64): {iv2}\nCiphertext (Base64): {ct}"
                self.status_var.set("Double DES encryption successful")
            else:
                iv1_b64 = self.des_iv1_entry.get().strip()
                iv2_b64 = self.des_iv2_entry.get().strip()
                if not iv1_b64 or not iv2_b64:
                    messagebox.showwarning("Warning", "Please enter both IVs for decryption")
                    return
                
                pt = double_des_decrypt(key1, key2, iv1_b64, iv2_b64, input_text)
                output = f"Plaintext: {pt}"
                self.status_var.set("Double DES decryption successful")
            
            self.display_output(self.block_output, output)
        except Exception as e:
            raise Exception(f"Double DES {operation.lower()} failed: {str(e)}")
    def execute_triple_des(self, operation, input_text):
        """Execute triple DES encryption/decryption"""
        key_b64 = self.des3_key_entry.get().strip()
        if not key_b64:
            messagebox.showwarning("Warning", "Please enter or generate a key")
            return
        try:
            key = base64.b64decode(key_b64)
            
            # Validate key length (24 bytes for 3DES)
            if len(key) != 24:
                messagebox.showerror("Error", "Invalid Triple DES key length (must be 24 bytes)")
                return
            
            if operation == "Encrypt":
                iv, ct = des3_encrypt(key, input_text)
                output = f"IV (Base64): {iv}\nCiphertext (Base64): {ct}"
                self.status_var.set("Triple DES encryption successful")
            else:
                iv_b64 = self.des3_iv_entry.get().strip()
                if not iv_b64:
                    messagebox.showwarning("Warning", "Please enter IV for decryption")
                    return
                pt = des3_decrypt(key, iv_b64, input_text)
                output = f"Plaintext: {pt}"
                self.status_var.set("Triple DES decryption successful")
            self.display_output(self.block_output, output)
        except Exception as e:
            raise Exception(f"Triple DES {operation.lower()} failed: {str(e)}")
    def execute_stream_operation(self):
        algo = self.stream_algo.get()
        operation = self.stream_operation.get()
        input_text = self.stream_input.get("1.0", tk.END).strip()
        if not input_text:
            messagebox.showwarning("Warning", "Please enter input text")
            return
        try:
            if algo == "Caesar":
                self.execute_caesar_cipher(operation, input_text)
            elif algo == "Vigenere":
                self.execute_vigenere_cipher(operation, input_text)
        except Exception as e:
            messagebox.showerror("Error", f"Operation failed: {str(e)}")
            self.status_var.set(f"{algo} cipher operation failed")
    def execute_caesar_cipher(self, operation, input_text):
        """Execute Caesar cipher encryption/decryption"""
        try:
            shift = int(self.caesar_shift.get())
            if not 1 <= shift <= 25:
                raise ValueError("Shift must be between 1 and 25")
            result = []
            for char in input_text:
                if char.isalpha():
                    if operation == "Encrypt":
                        if char.isupper():
                            result.append(chr((ord(char) - 65 + shift) % 26 + 65))
                        else:
                            result.append(chr((ord(char) - 97 + shift) % 26 + 97))
                    else:  # Decrypt
                        if char.isupper():
                            result.append(chr((ord(char) - 65 - shift) % 26 + 65))
                        else:
                            result.append(chr((ord(char) - 97 - shift) % 26 + 97))
                else:
                    result.append(char)
            output = ''.join(result)
            self.display_output(self.stream_output, output)
            self.status_var.set(f"Caesar cipher {operation.lower()} successful (shift={shift})")
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid shift value: {str(e)}")
            self.status_var.set("Caesar cipher failed - invalid shift")
    def execute_vigenere_cipher(self, operation, input_text):
        key = self.vigenere_key_entry.get().strip().upper()
        if not key or not key.isalpha():
            messagebox.showwarning("Warning", "Please enter a valid key (letters only)")
            return
        try:
            result = []
            key_len = len(key)
            key_index = 0
            for char in input_text:
                if char.isalpha():
                    key_char = key[key_index % key_len]
                    key_shift = ord(key_char) - 65
                    if operation == "Encrypt":
                        if char.isupper():
                            result.append(chr((ord(char) - 65 + key_shift) % 26 + 65))
                        else:
                            result.append(chr((ord(char) - 97 + key_shift) % 26 + 97))
                    else:  # Decrypt
                        if char.isupper():
                            result.append(chr((ord(char) - 65 - key_shift) % 26 + 65))
                        else:
                            result.append(chr((ord(char) - 97 - key_shift) % 26 + 97))
                    key_index += 1
                else:
                    result.append(char)
            output = ''.join(result)
            self.display_output(self.stream_output, output)
            self.status_var.set(f"Vigenère cipher {operation.lower()} successful (key={key})")
        except Exception as e:
            messagebox.showerror("Error", f"Vigenère cipher failed: {str(e)}")
            self.status_var.set("Vigenère cipher failed")
    def execute_asym_operation(self):
        operation = self.asym_operation.get()
        input_text = self.asym_input.get("1.0", tk.END).strip()     
        if not input_text:
            messagebox.showwarning("Warning", "Please enter input text")
            return
        try:
            if operation == "Encrypt":
                self.execute_rsa_encryption(input_text)
            else:
                self.execute_rsa_decryption(input_text)
        except Exception as e:
            messagebox.showerror("Error", f"RSA operation failed: {str(e)}")
            self.status_var.set(f"RSA {operation.lower()} failed")
    def execute_rsa_encryption(self, input_text):
        public_key = self.public_key_text.get("1.0", tk.END).strip()
        if not public_key:
            messagebox.showwarning("Warning", "Please load or generate a public key")
            return
        try:
            if len(input_text.encode()) > 200:  # Rough estimate for 2048-bit RSA
                messagebox.showwarning("Warning", "Message too long for RSA encryption. Using first 200 bytes.")
                input_text = input_text[:200]
            encrypted = rsa_encrypt(public_key, input_text)
            output = f"Encrypted (Base64): {encrypted}"
            self.display_output(self.asym_output, output)
            self.status_var.set("RSA encryption successful")
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    def execute_rsa_decryption(self, input_text):
        private_key = self.private_key_text.get("1.0", tk.END).strip()
        if not private_key:
            messagebox.showwarning("Warning", "Please load or generate a private key")
            return 
        try:
            decrypted = rsa_decrypt(private_key, input_text)
            output = f"Decrypted: {decrypted}"
            self.display_output(self.asym_output, output)
            self.status_var.set("RSA decryption successful")
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
    def generate_hash(self):
        algo = self.hash_algo.get()
        input_text = self.hash_input.get("1.0", tk.END).strip()
        if not input_text:
            messagebox.showwarning("Warning", "Please enter input text")
            return
        try:
            hash_value = hash_message(input_text, algo)
            output = f"{algo} hash: {hash_value}"
            self.display_output(self.hash_output, output)
            self.status_var.set(f"{algo} hash generated")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate hash: {str(e)}")
            self.status_var.set("Hash generation failed")
    def execute_sig_operation(self):
        operation = self.sig_operation.get()
        message = self.sig_message.get("1.0", tk.END).strip()
        sig_type = self.sig_type.get()
        if not message:
            messagebox.showwarning("Warning", "Please enter a message")
            return
        try:
            if operation == "Sign":
                self.execute_signature_generation(message, sig_type)
            else:
                self.execute_signature_verification(message, sig_type)
        except Exception as e:
            messagebox.showerror("Error", f"Signature operation failed: {str(e)}")
            self.status_var.set(f"Signature {operation.lower()} failed")
    def execute_signature_generation(self, message, sig_type):
        private_key = self.private_key_text.get("1.0", tk.END).strip()
        if not private_key:
            messagebox.showwarning("Warning", "Please load or generate a private key")
            return
        try:
            if sig_type == "Standard Digital Signature":
                signature = sign_message(private_key, message)
                output = f"Signature (Base64): {signature}"
                self.status_var.set("Standard digital signature created")
            else:  # Blind Signature
                signature = blind_sign_message(private_key, message)
                output = f"Blind Signature (Base64): {signature}"
                self.status_var.set("Blind signature created ")
            self.display_output(self.sig_output, output)
        except Exception as e:
            raise Exception(f"Signature generation failed: {str(e)}")
    def execute_signature_verification(self, message, sig_type):
        public_key = self.public_key_text.get("1.0", tk.END).strip()
        if not public_key:
            messagebox.showwarning("Warning", "Please load or generate a public key")
            return
        signature = self.sig_input.get("1.0", tk.END).strip()
        if not signature:
            messagebox.showwarning("Warning", "Please enter a signature to verify")
            return
        try:
            if sig_type == "Standard Digital Signature":
                is_valid = verify_signature(public_key, message, signature)
                output = f"Signature is {'VALID' if is_valid else 'INVALID'}"
                self.status_var.set("Standard signature verification completed")
            else:  # Blind Signature
                # Simplified verification
                is_valid = verify_signature(public_key, message, signature)
                output = f"Blind Signature is {'VALID' if is_valid else 'INVALID'}"
                self.status_var.set("Blind signature verification completed ")
            self.display_output(self.sig_output, output)
        except Exception as e:
            raise Exception(f"Signature verification failed: {str(e)}")
    def display_output(self, output_widget, text):
        output_widget.config(state=tk.NORMAL)
        output_widget.delete("1.0", tk.END)
        output_widget.insert("1.0", text)
        output_widget.config(state=tk.DISABLED)
def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct
def aes_decrypt(key, iv, ct):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return pt
def double_des_encrypt(key1, key2, data):
    cipher1 = DES.new(key1, DES.MODE_CBC)
    ct_bytes1 = cipher1.encrypt(pad(data.encode(), DES.block_size))
    iv1 = base64.b64encode(cipher1.iv).decode('utf-8')
    cipher2 = DES.new(key2, DES.MODE_CBC)
    ct_bytes2 = cipher2.encrypt(pad(ct_bytes1, DES.block_size))
    iv2 = base64.b64encode(cipher2.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes2).decode('utf-8')
    return iv1, iv2, ct
def double_des_decrypt(key1, key2, iv1, iv2, ct):
    iv1 = base64.b64decode(iv1)
    iv2 = base64.b64decode(iv2)
    ct = base64.b64decode(ct)
    cipher2 = DES.new(key2, DES.MODE_CBC, iv=iv2)
    ct_bytes2 = unpad(cipher2.decrypt(ct), DES.block_size)
    cipher1 = DES.new(key1, DES.MODE_CBC, iv=iv1)
    pt = unpad(cipher1.decrypt(ct_bytes2), DES.block_size).decode('utf-8')
    return pt
def des_encrypt(key, data):
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), DES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct
def des_decrypt(key, iv, ct):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), DES.block_size).decode('utf-8')
    return pt
def des3_encrypt(key, data):
    cipher = DES3.new(key, DES3.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), DES3.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct
def des3_decrypt(key, iv, ct):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), DES3.block_size).decode('utf-8')
    return pt
def rsa_encrypt(public_key, message):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted).decode('utf-8')
def rsa_decrypt(private_key, ciphertext):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext))
    return decrypted.decode('utf-8')
def sign_message(private_key, message):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode('utf-8')
def verify_signature(public_key, message, signature):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False
def blind_sign_message(private_key, message):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode('utf-8')
def hash_message(message, algo):
    if algo == "MD5":
        return MD5.new(message.encode()).hexdigest()
    elif algo == "SHA1":
        return SHA1.new(message.encode()).hexdigest()
    elif algo == "SHA224":
        return SHA224.new(message.encode()).hexdigest()
    elif algo == "SHA256":
        return SHA256.new(message.encode()).hexdigest()
    elif algo == "SHA512":
        return SHA512.new(message.encode()).hexdigest()
if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoToolWindow(root)
    root.mainloop()