import logging
import re
import os
import paramiko
import docker
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import (
    Updater,
    CommandHandler,
    ConversationHandler,
    MessageHandler,
    Filters
)
import psycopg2
from psycopg2 import Error

load_dotenv()

host = os.getenv('RM_HOST')
port = os.getenv('RM_PORT')
username = os.getenv('RM_USERNAME')
password = os.getenv('RM_PASSWORD')
TOKEN = os.getenv("TOKEN")

DB_HOST = os.getenv('DB_HOST')
DB_PORT = os.getenv('DB_PORT')
DB_NAME = os.getenv('DB_DATABASE')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')

# Подключаем логирование
logging.basicConfig(
    filename='app.log',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    encoding="utf-8"
)

logger = logging.getLogger(__name__)

def start(update: Update, context):
    user = update.effective_user
    update.message.reply_text(f'Привет {user.full_name}!')
    logger.info(f"/start вызван пользователем: {user.full_name}")

def helpCommand(update: Update, context):
    update.message.reply_text('Help!')
    logger.info("/help вызван")

def findEmailsCommand(update: Update, context):
    update.message.reply_text('Введите текст для поиска email-адресов: ')
    logger.info("/find_email вызван")
    return 'findEmails'

def verifyPasswordCommand(update: Update, context):
    update.message.reply_text('Введите пароль, который хотите проверить: ')
    logger.info("/verify_password вызван")
    return 'verifyPass'

def findPhoneNumbersCommand(update: Update, context):
    update.message.reply_text('Введите текст для поиска телефонных номеров: ')
    logger.info("/findPhoneNumbers вызван")
    return 'findPhoneNumbers'

def verifyPass(update: Update, context):
    password = update.message.text
    passwordRegex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()])[A-Za-z\d!@#$%^&*()]{8,}$')
    if passwordRegex.match(password):
        update.message.reply_text('Пароль сложный')
    else:
        update.message.reply_text('Пароль простой')
    logger.info(f"Пароль проверен: {password}")
    return ConversationHandler.END

def find_emails(update: Update, context):
    update.message.reply_text('Введите текст для поиска email-адресов: ')
    logger.info("Начат процесс поиска email-адресов")
    return 'handle_found_emails'

def handle_found_emails(update: Update, context):
    user_input = update.message.text
    email_regex = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')
    email_list = email_regex.findall(user_input)

    if not email_list:
        update.message.reply_text('Email-адреса не найдены')
        logger.info("Email-адреса не найдены")
        return ConversationHandler.END

    emails_str = '\n'.join(email_list)
    update.message.reply_text(f"Найденные email-адреса:\n{emails_str}")
    logger.info(f"Найденные email-адреса: {emails_str}")

    update.message.reply_text("Записать найденные email-адреса в базу данных? (Да/Нет)")
    context.user_data['emails'] = email_list
    return 'confirm_email_save'

def confirm_email_save(update: Update, context):
    user_answer = update.message.text.lower()
    if user_answer in ['да', 'yes']:
        try:
            connection = psycopg2.connect(
                user=DB_USER,
                password=DB_PASSWORD,
                host=DB_HOST,
                port=DB_PORT,
                database=DB_NAME
            )
            cursor = connection.cursor()

            emails_to_insert = [(email,) for email in context.user_data['emails']]
            cursor.executemany("INSERT INTO emails (email) VALUES (%s) ON CONFLICT DO NOTHING;", emails_to_insert)
            connection.commit()

            update.message.reply_text("Email-адреса успешно добавлены в базу данных.")
            logger.info("Email-адреса успешно добавлены в базу данных")
        except (Exception, Error) as error:
            logger.error(f"Ошибка при работе с PostgreSQL: {error}")
            update.message.reply_text(f"Ошибка при записи email-адресов в базу данных: {error}")
        finally:
            if connection:
                cursor.close()
                connection.close()
    else:
        update.message.reply_text("Отмена записи email-адресов.")
        logger.info("Отмена записи email-адресов")

    return ConversationHandler.END

def find_phone_numbers(update: Update, context):
    update.message.reply_text('Введите текст для поиска телефонных номеров: ')
    logger.info("Начат процесс поиска телефонных номеров")
    return 'handle_found_phone_numbers'

def handle_found_phone_numbers(update: Update, context):
    user_input = update.message.text
    phone_num_regex = re.compile(r'(?:\+7|8)[-\s\(]*(\d{3})[-\)\s]*(\d{3})[-\s]*(\d{2})[-\s]*(\d{2})')
    phone_number_list = phone_num_regex.findall(user_input)

    if not phone_number_list:
        update.message.reply_text('Телефонные номера не найдены')
        logger.info("Телефонные номера не найдены")
        return ConversationHandler.END

    formatted_phone_numbers = ['+7' + ''.join(parts) for parts in phone_number_list]
    phone_numbers_str = '\n'.join(formatted_phone_numbers)
    update.message.reply_text(f"Найденные номера телефонов:\n{phone_numbers_str}")
    logger.info(f"Найденные номера телефонов: {phone_numbers_str}")

    update.message.reply_text("Записать найденные номера телефонов в базу данных? (Да/Нет)")
    context.user_data['phone_numbers'] = formatted_phone_numbers
    return 'confirm_phone_number_save'

def confirm_phone_number_save(update: Update, context):
    user_answer = update.message.text.lower()
    if user_answer in ['да', 'yes']:
        try:
            connection = psycopg2.connect(
                user=DB_USER,
                password=DB_PASSWORD,
                host=DB_HOST,
                port=DB_PORT,
                database=DB_NAME
            )
            cursor = connection.cursor()

            phone_numbers_to_insert = [(number,) for number in context.user_data['phone_numbers']]
            cursor.executemany("INSERT INTO phone_numbers (phone_number) VALUES (%s) ON CONFLICT DO NOTHING;", phone_numbers_to_insert)
            connection.commit()

            update.message.reply_text("Номера телефонов успешно добавлены в базу данных.")
            logger.info("Номера телефонов успешно добавлены в базу данных")
        except (Exception, Error) as error:
            logger.error(f"Ошибка при работе с PostgreSQL: {error}")
            update.message.reply_text(f"Ошибка при записи номеров телефонов в базу данных: {error}")
        finally:
            if connection:
                cursor.close()
                connection.close()
    else:
        update.message.reply_text("Отмена записи номеров телефонов.")
        logger.info("Отмена записи номеров телефонов")

    return ConversationHandler.END

def ssh_command(update, context, command):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, username=username, password=password, port=port)
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        if error:
            update.message.reply_text(f"Ошибка: {error}")
        else:
            update.message.reply_text(f"```\n{output}\n```")
        logger.info(f"SSH команда '{command}' выполнена с результатом: {output}")
        return output
    except Exception as e:
        logger.error(f"Ошибка подключения: {e}")
        update.message.reply_text(f"Ошибка подключения: {e}")
    finally:
        if client:
            client.close()

def get_auths(update, context):
    ssh_command(update, context, "last -n 10")

def get_critical(update, context):
    ssh_command(update, context, "journalctl -p err -n 5")

def get_ps(update, context):
    ssh_command(update, context, "ps aux | head -n 20")

def get_ss(update, context):
    ssh_command(update, context, "ss -tuln")

def get_apt_list_command(update: Update, context):
    update.message.reply_text("Напиши 'all', если хочешь увидеть все пакеты, либо укажи какой именно ")
    logger.info("/get_apt_list вызван")
    return 'get_apt_list'

def get_apt_list(update: Update, context):
    package_name = update.message.text.strip()
    if package_name.lower() == 'all':
        command = "dpkg -l | head -n 30"
    else:
        command = f"apt-cache policy {package_name}"
    output = ssh_command(update, context, command)
    logger.info(f"Выполнена команда apt: {command}")
    return ConversationHandler.END

def get_services(update, context):
    ssh_command(update, context, "service --status-all")

def echo(update: Update, context):
    update.message.reply_text(update.message.text)

def get_release(update, context):
    ssh_command(update, context, "cat /etc/os-release")

def get_uname(update, context):
    ssh_command(update, context, "uname -a")

def get_uptime(update, context):
    ssh_command(update, context, "uptime")

def get_df(update, context):
    ssh_command(update, context, "df -h")

def get_free(update, context):
    ssh_command(update, context, "free -m")

def get_mpstat(update, context):
    ssh_command(update, context, "mpstat")

def get_w(update, context):
    ssh_command(update, context, "w")

def get_repl_logs(update, context):
    try:
        logging.info(f"Пользователь {update.message.from_user.id} запросил информацию логов о репликации")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, username=username, password=password, port=int(port))

        # Выполнение команды для получения имени последнего лог-файла
        find_command = "docker exec db_container sh -c 'ls -1t /var/lib/postgresql/data/log | head -n 1'"
        stdin, stdout, stderr = client.exec_command(find_command)
        latest_log_file = stdout.read().strip().decode('utf-8')

        error = stderr.read().decode('utf-8')
        if error:
            update.message.reply_text(f"Ошибка при получении имени последнего лог-файла: {error}")
            logger.error(f"Ошибка при получении имени последнего лог-файла: {error}")
            return

        # Проверка, что имя файла было получено
        if not latest_log_file:
            update.message.reply_text("Не удалось получить имя последнего лог-файла.")
            logger.error("Не удалось получить имя последнего лог-файла.")
            return

        # Выполнение команды для получения логов из последнего лог-файла
        command = f"docker exec db_container tail -n 10 /var/lib/postgresql/data/log/{latest_log_file}"
        stdin, stdout, stderr = client.exec_command(command)
        logs = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
        client.close()

        if not logs:
            logs = "Логи репликации не найдены."

        update.message.reply_text(f"```\n{logs}\n```")
        logger.info(f"Логи репликации: {logs}")

    except Exception as e:
        logger.error(f"Ошибка подключения по SSH: {e}")
        update.message.reply_text(f"Ошибка подключения по SSH: {e}")

def get_pg_logs(update, context):
    try:
        logging.info(f"Пользователь {update.message.from_user.id} запросил информацию логов PostgreSQL")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, username=username, password=password, port=int(port))

        # Команда для получения последнего лог-файла
        command = "ls -t /var/lib/postgresql/14/main/log/*.log | head -1 | xargs tail -10"
        
        stdin, stdout, stderr = client.exec_command(command)
        logs = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        client.close()

        if error:
            update.message.reply_text(f"Ошибка при получении логов: {error}")
            logger.error(f"Ошибка при получении логов: {error}")
            return

        if not logs:
            logs = "Логи не найдены."

        update.message.reply_text(f"```\n{logs}\n```")
        logger.info(f"Логи: {logs}")

    except Exception as e:
        logger.error(f"Ошибка подключения по SSH: {e}")
        update.message.reply_text(f"Ошибка подключения по SSH: {e}")
            
def get_emails(update, context):
    try:
        connection = psycopg2.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME
        )
        cursor = connection.cursor()

        cursor.execute("SELECT email FROM emails;")
        rows = cursor.fetchall()

        if rows:
            message = "Email-адреса:\n\n"
            for row in rows:
                message += row[0] + "\n"
        else:
            message = "Таблица emails пуста."

        update.message.reply_text(message)
        logger.info(f"Получены email-адреса: {message}")

    except (Exception, Error) as error:
        logger.error(f"Ошибка при работе с PostgreSQL: {error}")
        update.message.reply_text("Ошибка при получении email-адресов.")
    finally:
        if connection:
            cursor.close()
            connection.close()

def get_phone_numbers(update, context):
    try:
        connection = psycopg2.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME
        )
        cursor = connection.cursor()

        cursor.execute("SELECT phone_number FROM phone_numbers;")
        rows = cursor.fetchall()

        if rows:
            message = "Номера телефонов:\n\n"
            for row in rows:
                message += row[0] + "\n"
        else:
            message = "Таблица phone_numbers пуста."

        update.message.reply_text(message)
        logger.info(f"Получены номера телефонов: {message}")

    except (Exception, Error) as error:
        logger.error(f"Ошибка при работе с PostgreSQL: {error}")
        update.message.reply_text("Ошибка при получении номеров телефонов.")
    finally:
        if connection:
            cursor.close()
            connection.close()

def main():
    updater = Updater(TOKEN, use_context=True)

    # Получаем диспетчер для регистрации обработчиков
    dp = updater.dispatcher

    # Логгирование для репликаций и все что связано с бд здесь
    dp.add_handler(CommandHandler("get_pg_logs", get_pg_logs))
    dp.add_handler(CommandHandler("get_repl_logs", get_repl_logs))
    dp.add_handler(CommandHandler("get_emails", get_emails))
    dp.add_handler(CommandHandler("get_phone_numbers", get_phone_numbers))

    conv_handler_find_emails = ConversationHandler(
        entry_points=[CommandHandler('find_email', find_emails)],
        states={
            'handle_found_emails': [MessageHandler(Filters.text & ~Filters.command, handle_found_emails)],
            'confirm_email_save': [MessageHandler(Filters.text & ~Filters.command, confirm_email_save)],
        },
        fallbacks=[]
    )
    conv_handler_find_phone_numbers = ConversationHandler(
        entry_points=[CommandHandler('findPhoneNumbers', find_phone_numbers)],
        states={
            'handle_found_phone_numbers': [MessageHandler(Filters.text & ~Filters.command, handle_found_phone_numbers)],
            'confirm_phone_number_save': [MessageHandler(Filters.text & ~Filters.command, confirm_phone_number_save)],
        },
        fallbacks=[]
    )

    # Регистрация обработчиков диалогов
    dp.add_handler(conv_handler_find_emails)
    dp.add_handler(conv_handler_find_phone_numbers)

    # Обработчики команд для сбора информации о системе
    dp.add_handler(CommandHandler("get_release", get_release))
    dp.add_handler(CommandHandler("get_uname", get_uname))
    dp.add_handler(CommandHandler("get_uptime", get_uptime))

    # Обработчики команд для сбора информации о ресурсах
    dp.add_handler(CommandHandler("get_df", get_df))
    dp.add_handler(CommandHandler("get_free", get_free))
    dp.add_handler(CommandHandler("get_mpstat", get_mpstat))
    dp.add_handler(CommandHandler("get_w", get_w))

    # Обработчики команд для сбора логов
    dp.add_handler(CommandHandler("get_auths", get_auths))
    dp.add_handler(CommandHandler("get_critical", get_critical))

    # Обработчики команд для сбора информации о процессах и портах
    dp.add_handler(CommandHandler("get_ps", get_ps))
    dp.add_handler(CommandHandler("get_ss", get_ss))

    # Обработчик диалога для команды /get_apt_list
    conv_handler_apt = ConversationHandler(
        entry_points=[CommandHandler('get_apt_list', get_apt_list_command)],
        states={
            'get_apt_list': [MessageHandler(Filters.text & ~Filters.command, get_apt_list)],
        },
        fallbacks=[]
    )
    dp.add_handler(conv_handler_apt)

    # Обработчик команды для сбора информации о сервисах
    dp.add_handler(CommandHandler("get_services", get_services))

    # Обработчик диалога для пароля
    convHandlerVerifyPass = ConversationHandler(
        entry_points=[CommandHandler('verify_password', verifyPasswordCommand)],
        states={
            'verifyPass': [MessageHandler(Filters.text & ~Filters.command, verifyPass)],
        },
        fallbacks=[]
    )
    # Регистрируем обработчики команд
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("help", helpCommand))
    dp.add_handler(convHandlerVerifyPass)

    # Регистрируем обработчик текстовых сообщений
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, echo))

    # Запускаем бота
    updater.start_polling()

    # Останавливаем бота при нажатии Ctrl+C
    updater.idle()

if __name__ == '__main__':
    main()

