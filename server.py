import threading
import socket
import ssl
import json
import hashlib

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile='server.crt', keyfile='server.key')

# Створення серверного сокету
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 65433))
server.listen()
print("Сервер очікує з'єднань...")

# Обгортання серверного сокету в SSL
secure_server = context.wrap_socket(server, server_side=True)

clients = []
nicknames = []

# Завантаження або ініціалізація бази даних користувачів
try:
    with open("users.json", "r") as file:
        users = json.load(file)
except FileNotFoundError:
    users = {}

def hash_password(password):
    """Хешування пароля за допомогою SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate(client):
    """Обробка автентифікації користувача (вхід або реєстрація)."""
    while True:
        client.send("LOGIN_OR_REGISTER".encode("utf-8"))
        choice = client.recv(1024).decode("utf-8").strip().lower()

        if choice == "login":
            client.send("USERNAME".encode("utf-8"))
            username = client.recv(1024).decode("utf-8").strip()

            client.send("PASSWORD".encode("utf-8"))
            password = client.recv(1024).decode("utf-8").strip()

            if username in users and users[username] == hash_password(password):
                client.send("LOGIN_SUCCESS".encode("utf-8"))
                return username
            else:
                client.send("LOGIN_FAILED".encode("utf-8"))

        elif choice == "register":
            client.send("USERNAME".encode("utf-8"))
            username = client.recv(1024).decode("utf-8").strip()

            if username in users:
                client.send("USERNAME_TAKEN".encode("utf-8"))
                continue

            client.send("PASSWORD".encode("utf-8"))
            password = client.recv(1024).decode("utf-8").strip()
            users[username] = hash_password(password)

            # Збереження оновленої бази даних користувачів
            with open("users.json", "w") as file:
                json.dump(users, file)

            client.send("REGISTER_SUCCESS".encode("utf-8"))
            return username
        else:
            client.send("INVALID_OPTION".encode("utf-8"))

def broadcast(message, sender=None):
    """Надсилання повідомлення всім клієнтам, крім відправника."""
    for client in clients:
        try:
            # Додаємо нік тільки якщо відправник вказаний
            if sender is not None:
                index = clients.index(sender)
                sender_nickname = nicknames[index]

                # Перевіряємо, чи повідомлення ще не містить ніка
                if not message.decode('utf-8').startswith(f"{sender_nickname}: "):
                    message = f"{sender_nickname}: {message.decode('utf-8')}".encode('utf-8')

            client.send(message)
        except:
            remove_client(client)

def handle(client):
    """Обробка зв'язку з конкретним клієнтом."""
    while True:
        try:
            message = client.recv(1024)
            if not message:
                raise ConnectionResetError("Клієнт закрив з'єднання")
            broadcast(message, sender=client)
        except (ConnectionResetError, ConnectionAbortedError):
            print("Клієнт відключився.")
            remove_client(client)
            break
        except Exception as e:
            print(f"Помилка у клієнта: {e}")
            remove_client(client)
            break

def remove_client(client):
    """Видалення клієнта із сервера."""
    if client in clients:
        index = clients.index(client)
        nickname = nicknames[index]
        clients.remove(client)
        client.close()
        nicknames.remove(nickname)
        broadcast(f"{nickname} залишив чат".encode('utf-8'))
        print(f"{nickname} відключився")

def receive():
    """Прийом та обробка нових з'єднань клієнтів."""
    while True:
        try:
            client, address = secure_server.accept()
            print(f"Підключено з {str(address)}")

            # Автентифікація користувача
            nickname = authenticate(client)
            nicknames.append(nickname)
            clients.append(client)

            print(f"Нікнейм клієнта: {nickname}")
            broadcast(f"{nickname} приєднався до чату".encode("utf-8"))
            client.send("Ви підключилися до сервера".encode("utf-8"))

            # Запуск обробки клієнта в новому потоці
            thread = threading.Thread(target=handle, args=(client,), daemon=True)
            thread.start()
        except Exception as e:
            print(f"Помилка під час прийому з'єднання: {e}")

try:
    receive()
except KeyboardInterrupt:
    print("Сервер завершує роботу...")
finally:
    secure_server.close()
    with open("users.json", "w") as file:
        json.dump(users, file)  # Збереження бази даних користувачів
    print("Сервер вимкнено")

# генерація сертифікатів, якщо їх немає
# openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365 -config
