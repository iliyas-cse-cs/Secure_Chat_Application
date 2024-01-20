import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import tkinter as tk
from tkinter import scrolledtext
import threading

class SecureChatGUI:
    def __init__(self, master, server_public_key):
        self.master = master
        self.master.title("Secure Chat")
        
        self.chat_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=40, height=15)
        self.chat_text.pack(padx=10, pady=10)

        self.input_entry = tk.Entry(master, width=40)
        self.input_entry.pack(padx=10, pady=10)

        self.send_button = tk.Button(master, text="Send", command=self.send_message)
        self.send_button.pack(padx=10, pady=10)

        self.server_public_key = server_public_key
        self.client = None

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def send_message(self):
        message = self.input_entry.get()
        if message.lower() == 'exit':
            self.master.destroy()
            return

        if message:
            send_message(self.client, self.server_public_key, message)
            self.input_entry.delete(0, tk.END)

    def receive_messages(self):
        while True:
            try:
                receive_message(self.client, self.server_public_key, self.chat_text)
            except Exception as e:
                print(f"Error: {e}")
                break

def receive_message(client_socket, server_public_key, chat_text_widget):
    encrypted_msg = client_socket.recv(1024)
    decrypted_msg = server_public_key.decrypt(
        encrypted_msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    chat_text_widget.insert(tk.END, f"Friend: {decrypted_msg.decode()}\n")
    chat_text_widget.see(tk.END)

def send_message(client_socket, server_public_key, message):
    encrypted_msg = server_public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    client_socket.send(encrypted_msg)

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('192.168.217.93', 5555))

    # Receive the server's public key
    server_public_key_bytes = client.recv(4096)
    server_public_key = serialization.load_pem_public_key(
        server_public_key_bytes,
        backend=None
    )

    root = tk.Tk()
    gui = SecureChatGUI(root, server_public_key)
    gui.client = client

    root.mainloop()

if __name__ == "__main__":
    main()
