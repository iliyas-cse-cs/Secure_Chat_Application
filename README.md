# Secure_Chat_Application
Secure Chat Application in Python featuring end-to-end RSA encryption with SHA-256 hashing, a user-friendly GUI, and real-time multi-client communication for confidential and tamper-proof messaging.


# Secure Chat Application with Python

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)

## Overview

This repository contains the source code for a secure chat application developed in Python. The application ensures end-to-end encryption using the RSA algorithm with SHA-256 hashing, providing a secure and confidential communication channel.

## Features

- **End-to-End Encryption:** Utilizes RSA algorithm with SHA-256 hashing for secure end-to-end encryption of messages.
- **Multi-Client Support:** The server can handle multiple clients concurrently, allowing for seamless communication.
- **Graphical User Interface (GUI):** User-friendly GUIs for both the server and clients enhance accessibility and ease of use.
- **Real-Time Message Display:** Messages are displayed in real-time, providing an interactive communication experience.
- **Dynamic Key Generation:** RSA key pairs are generated dynamically for each client, enhancing communication security.
- **Message Integrity:** Ensures message integrity through the use of SHA-256 hashing.
- **Scalability:** Designed to be scalable, accommodating an increasing number of clients without compromising performance.
- **Cross-Platform Compatibility:** Works on various operating systems, making it versatile and accessible.

## Getting Started

### Prerequisites

- Python 3.8 or higher

### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/iliyas-cse-cs/Secure_Chat_Application
    ```

2. Navigate to the project directory:

    ```bash
    cd secure-chat-application
    ```

3. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

### Usage

#### Server

Run the server:

```bash
python server.py

#### Client

Run a client:

python client.py

### Contributing ###
Contributions are welcome! Feel free to open issues or pull requests.
