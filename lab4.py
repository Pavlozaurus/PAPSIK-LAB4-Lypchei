import socket
import ssl
import threading
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

# Налаштування сервера
HOST = '127.0.0.1'
PORT = 65432
CERTFILE = 'server.crt'
KEYFILE = 'server.key'

# Генерація сертифікатів, якщо вони відсутні
def generate_certificates():
    print("\nГенерація сертифікатів...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Kyiv"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Obolon"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KSUBG"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "FITM"),
        x509.NameAttribute(NameOID.COMMON_NAME, HOST),
    ])

    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(HOST),
            x509.IPAddress(ip_address(HOST))
        ]),
        critical=False
    ).sign(private_key, hashes.SHA256())

    with open(KEYFILE, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ))

    with open(CERTFILE, "wb") as cert_file:
        cert_file.write(cert.public_bytes(Encoding.PEM))

    print("Сертифікати згенеровано успішно.\n")

if not os.path.exists(CERTFILE) or not os.path.exists(KEYFILE):
    generate_certificates()

# Обробка клієнта (для сервера)
def handle_client(conn, addr):
    print(f"\nЗ'єднання встановлено з {addr}.")
    conn.sendall("Підказка: для завершення сеансу введіть 'exit'.\n".encode('utf-8'))
    try:
        def receive_messages():
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                message = data.decode('utf-8')
                if message.lower() == 'exit':
                    print(f"\nКлієнт {addr} завершив з'єднання.")
                    break
                print(f"\nПовідомлення від {addr}: {message}")

        threading.Thread(target=receive_messages, daemon=True).start()

        while True:
            server_message = input("Сервер: ")
            if server_message.lower() == 'exit':
                conn.sendall(server_message.encode('utf-8'))
                print("\nСеанс завершено.")
                os._exit(0)
            conn.sendall(server_message.encode('utf-8'))
    except Exception as e:
        print(f"\nПомилка з'єднання з {addr}: {e}")
    finally:
        conn.close()
        print(f"\nЗ'єднання з {addr} закрито.")

# Серверна частина
def server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"\nСервер очікує підключення на {HOST}:{PORT}.")

        with context.wrap_socket(server_socket, server_side=True) as ssl_server_socket:
            while True:
                client_conn, client_addr = ssl_server_socket.accept()
                threading.Thread(target=handle_client, args=(client_conn, client_addr)).start()

# Клієнтська частина
def client():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(CERTFILE)

    with socket.create_connection((HOST, PORT)) as client_socket:
        with context.wrap_socket(client_socket, server_hostname=HOST) as ssl_client_socket:
            print("\nБезпечне з'єднання встановлено.")
            ssl_client_socket.sendall("Підказка: для завершення сеансу введіть 'exit'.\n".encode('utf-8'))
            try:
                def receive_messages():
                    while True:
                        data = ssl_client_socket.recv(1024)
                        if not data:
                            break
                        message = data.decode('utf-8')
                        if message.lower() == 'exit':
                            print("\nСервер завершив сеанс.")
                            os._exit(0)
                        print(f"\nСервер: {message}")

                threading.Thread(target=receive_messages, daemon=True).start()

                while True:
                    client_message = input("Клієнт: ")
                    if client_message.lower() == 'exit':
                        ssl_client_socket.sendall(client_message.encode('utf-8'))
                        print("\nСеанс завершено.")
                        break
                    ssl_client_socket.sendall(client_message.encode('utf-8'))
            except Exception as e:
                print(f"\nПомилка: {e}")

# Вибір режиму роботи
def main():
    mode = input("Розпочати як (server/client): ").strip().lower()
    if mode == "server":
        server()
    elif mode == "client":
        client()
    else:
        print("\nБудь ласка обирайте між 'server' або 'client'.")

if __name__ == "__main__":
    main()