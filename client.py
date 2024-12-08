import socket
import threading
import ssl
import signal
import sys

# Створення SSL-контексту
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_verify_locations('server.crt')

# Створення клієнтського сокету та обгортання його в SSL
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
secure_client = context.wrap_socket(client, server_hostname='localhost')

try:
    secure_client.connect(("localhost", 65433))
    print("Підключено до сервера")
except Exception as e:
    print(f"Не вдалося підключитися до сервера: {e}")
    exit()

# Функція для коректного завершення програми
def exit_gracefully(signal_received, frame):
    print("\nВихід з програми...")
    secure_client.close()
    sys.exit(0)

# Підключення обробника сигналу SIGINT
signal.signal(signal.SIGINT, exit_gracefully)

def authenticate():
    """Обробка автентифікації користувача за запитами сервера."""
    while True:
        response = secure_client.recv(1024).decode("utf-8")
        if response == "LOGIN_OR_REGISTER":
            print("Бажаєте (login) увійти чи (register) зареєструватися?")
            choice = input("> ").strip().lower()
            secure_client.send(choice.encode("utf-8"))
        elif response == "USERNAME":
            username = input("Введіть ім'я користувача: ").strip()
            secure_client.send(username.encode("utf-8"))
        elif response == "PASSWORD":
            password = input("Введіть ваш пароль: ").strip()
            secure_client.send(password.encode("utf-8"))
        elif response == "USERNAME_TAKEN":
            print("Це ім'я користувача вже зайнятий. Спробуйте інший.")
        elif response == "LOGIN_SUCCESS":
            print("Вхід виконано успішно!")
            return
        elif response == "REGISTER_SUCCESS":
            print("Реєстрація успішна! Ви увійшли.")
            return
        elif response == "LOGIN_FAILED":
            print("Помилка входу. Перевірте дані.")
        elif response == "INVALID_OPTION":
            print("Неправильний вибір. Введіть 'login' або 'register'.")
        else:
            print("Неочікувана відповідь сервера.")

def receive():
    """Отримання повідомлень від сервера."""
    while True:
        try:
            message = secure_client.recv(1024).decode("utf-8")
            print(message)  # Виведення повідомлень з ім'ям користувача
        except:
            print("Сталася помилка. Відключення...")
            secure_client.close()
            break

def write():
    """Надсилання повідомлень серверу."""
    while True:
        try:
            message = input("")
            secure_client.send(message.encode("utf-8"))
        except:
            print("Сталася помилка при надсиланні повідомлення.")
            break

# Автентифікація користувача
authenticate()

# Запуск потоків для отримання та надсилання повідомлень
receive_thread = threading.Thread(target=receive, daemon=True)
receive_thread.start()

write_thread = threading.Thread(target=write, daemon=True)
write_thread.start()

# Очікування завершення потоків
receive_thread.join()
write_thread.join()



