import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import tkinter as tk
from tkinter import scrolledtext

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('192.168.217.93', 5555))
server.listen()

clients = []
public_keys = {}


class ServerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Server")

        self.chat_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=40, height=15)
        self.chat_text.pack(padx=10, pady=10)

        self.encrypted_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=40, height=10)
        self.encrypted_text.pack(padx=10, pady=10)

        self.message_entry = tk.Entry(master, width=40)
        self.message_entry.pack(padx=10, pady=10)

        self.send_button = tk.Button(master, text="Send", command=self.send_message)
        self.send_button.pack(padx=10, pady=10)

        self.start_server_button = tk.Button(master, text="Start Server", command=self.start_server)
        self.start_server_button.pack(padx=10, pady=10)

    def start_server(self):
        threading.Thread(target=self.accept_connections, daemon=True).start()

    def accept_connections(self):
        while True:
            client, addr = server.accept()
            clients.append(client)

            # Generate RSA key pair for the client
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            public_key = private_key.public_key()

            # Send the public key to the client
            client.send(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            # Store the public key for later use
            public_keys[addr] = public_key

            # Create a new thread to handle the client's communication
            thread = threading.Thread(target=self.handle_client, args=(client, addr, private_key))
            thread.start()

    def handle_client(self, client, addr, private_key):
        print(f"New connection from {addr}")

        while True:
            encrypted_msg = client.recv(1024)
            if not encrypted_msg:
                break

            # Decrypt the received message using the server's private key
            decrypted_msg = private_key.decrypt(
                encrypted_msg,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Broadcast the decrypted message to all connected clients
            for c in clients:
                if c != client:
                    c.send(decrypted_msg)

            self.chat_text.insert(tk.END, f"Client {addr}: {decrypted_msg.decode()}\n")
            self.chat_text.see(tk.END)

            # Display the encrypted message in the separate area
            self.encrypted_text.insert(tk.END, f"{addr}: {encrypted_msg}\n")
            self.encrypted_text.see(tk.END)

        print(f"Connection from {addr} closed.")
        clients.remove(client)
        public_keys.pop(addr, None)
        client.close()

    def send_message(self):
        message = self.message_entry.get()
        if message:
            encrypted_message = self.encrypt_message(message)
            for client in clients:
                client.send(encrypted_message)

            self.chat_text.insert(tk.END, f"You: {message}\n")
            self.chat_text.see(tk.END)

            # Display the encrypted message in the separate area
            self.encrypted_text.insert(tk.END, f"You: {encrypted_message}\n")
            self.encrypted_text.see(tk.END)

            self.message_entry.delete(0, tk.END)

    def encrypt_message(self, message):
        # Encrypt the message using the public keys of all connected clients
        encrypted_message = b""
        for public_key in public_keys.values():
            encrypted_message += public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        return encrypted_message


def main():
    root = tk.Tk()
    server_gui = ServerGUI(root)

    root.mainloop()


if __name__ == "__main__":
    main()
