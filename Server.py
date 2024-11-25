import socket
import threading
import json
import os
from datetime import datetime
import argparse
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad

# Dizionario per memorizzare gli utenti connessi
utenti_connessi = {}  # username: { 'conn': connessione, 'indirizzo': indirizzo, 'chiave_pubblica': chiave_pubblica, 'group': gruppo, 'mode': 'broadcast'/'multicast', 'encrypt': True/False }

# Dizionario per memorizzare i gruppi
gruppi = {}  # group_name: { 'psk': psk, 'users': set([usernames]) }

# Percorsi dei file delle chiavi RSA del server
SERVER_PRIVATE_KEY_FILE = 'server_private.pem'
SERVER_PUBLIC_KEY_FILE = 'server_public.pem'

# Funzione per generare o caricare le chiavi RSA del server
def carica_o_genera_chiavi():
    if os.path.exists(SERVER_PRIVATE_KEY_FILE) and os.path.exists(SERVER_PUBLIC_KEY_FILE):
        # Carica le chiavi esistenti
        with open(SERVER_PRIVATE_KEY_FILE, 'rb') as f:
            chiave_privata = RSA.import_key(f.read())
        with open(SERVER_PUBLIC_KEY_FILE, 'rb') as f:
            chiave_pubblica = RSA.import_key(f.read())
    else:
        # Genera nuove chiavi
        chiave = RSA.generate(2048)
        chiave_privata = chiave
        chiave_pubblica = chiave.publickey()
        # Salva le chiavi
        with open(SERVER_PRIVATE_KEY_FILE, 'wb') as f:
            f.write(chiave_privata.export_key('PEM'))
        with open(SERVER_PUBLIC_KEY_FILE, 'wb') as f:
            f.write(chiave_pubblica.export_key('PEM'))
    return chiave_privata, chiave_pubblica

# Funzione per inizializzare il contatore del file di log
def inizializza_contatore_log():
    contatore_log = 1
    while os.path.exists(f"chat_{contatore_log}.txt"):
        contatore_log += 1
    return contatore_log

# Funzione per gestire i messaggi dei client
def gestisci_client(conn, indirizzo, contatore_log, chiave_privata):
    try:
        # Invia la chiave pubblica del server al client
        with open(SERVER_PUBLIC_KEY_FILE, 'rb') as f:
            chiave_pubblica_server = f.read()
        conn.sendall(chiave_pubblica_server)

        # Riceve le informazioni iniziali dal client
        dati_iniziali_bytes = conn.recv(4096)
        info = json.loads(dati_iniziali_bytes.decode())
        username = info['username']
        chiave_pubblica = info['chiave_pubblica']
        group_name = info['group_name']
        psk_encrypted = bytes.fromhex(info['psk_encrypted'])

        # Decripta il PSK usando la chiave privata del server
        cipher_rsa = PKCS1_OAEP.new(chiave_privata)
        psk = cipher_rsa.decrypt(psk_encrypted)

        psk = psk.decode()

        # Verifica se l'username è già in uso
        if username in utenti_connessi:
            conn.sendall(f"Errore: L'username '{username}' è già in uso. Scegli un altro username.".encode())
            conn.close()
            return

        # Gestione del gruppo
        if group_name in gruppi:
            # Il gruppo esiste già, verifica il PSK
            if gruppi[group_name]['psk'] != psk:
                conn.sendall(f"Errore: PSK errata per il gruppo '{group_name}'.".encode())
                conn.close()
                return
        else:
            # Crea un nuovo gruppo
            gruppi[group_name] = {
                'psk': psk,
                'users': set()
            }

        # Aggiunge l'utente al gruppo
        gruppi[group_name]['users'].add(username)
    except Exception as e:
        print(f"Errore nella ricezione dei dati iniziali: {e}")
        conn.close()
        return

    # Memorizza l'utente
    utenti_connessi[username] = {
        'conn': conn,
        'indirizzo': indirizzo,
        'chiave_pubblica': chiave_pubblica,
        'group': group_name,
        'mode': 'broadcast',
        'encrypt': True  # Di default la crittografia è attiva
    }

    # Invia messaggio di benvenuto al client
    conn.sendall("Connesso al server. Benvenuto! per info sui comandi /help".encode())

    # Invia messaggio di broadcast agli altri utenti
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    messaggio_broadcast = f"[{timestamp}] {username} si è connesso."
    for user in utenti_connessi:
        if user != username:
            utenti_connessi[user]['conn'].sendall(messaggio_broadcast.encode())

    # Salva l'evento di connessione nel log
    with open(f"chat_{contatore_log}.txt", "a", encoding='utf-8') as f:
        f.write(f"[{timestamp}] {indirizzo[0]}:{indirizzo[1]} {username} si è connesso al gruppo {group_name}.\n")

    # Loop per ricevere messaggi dal client
    while True:
        try:
            messaggio = conn.recv(4096)
            if not messaggio:
                break

            messaggio_decodificato = messaggio.decode(errors='ignore')

            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Salva il messaggio nel log con IP, porta, username e timestamp
            with open(f"chat_{contatore_log}.txt", "a", encoding='utf-8') as f:
                f.write(f"[{timestamp}] {indirizzo[0]}:{indirizzo[1]} {username}: {messaggio_decodificato}\n")

            if messaggio_decodificato.startswith('/'):
                # Comando
                comandi = messaggio_decodificato.strip().split()
                comando = comandi[0]

                if comando == '/whisper':
                    destinatario = comandi[1]
                    contenuto_messaggio = messaggio_decodificato.partition(destinatario)[2].strip()
                    # Inoltra il messaggio privato al destinatario
                    if destinatario in utenti_connessi:
                        messaggio_privato = f"[{timestamp}] [Whisper da {username}]: {contenuto_messaggio}"
                        utenti_connessi[destinatario]['conn'].sendall(messaggio_privato.encode())
                    else:
                        conn.sendall(f"Errore: utente {destinatario} non trovato.".encode())

                elif comando == '/encrypt':
                    if len(comandi) < 2:
                        conn.sendall("Uso corretto: /encrypt <on/off>".encode())
                        continue
                    stato = comandi[1]
                    if stato == 'on':
                        utenti_connessi[username]['encrypt'] = True
                        conn.sendall("Crittografia abilitata.".encode())
                    elif stato == 'off':
                        utenti_connessi[username]['encrypt'] = False
                        conn.sendall("Crittografia disabilitata.".encode())
                    else:
                        conn.sendall("Comando non riconosciuto.".encode())

                elif comando == '/get_pubkey':
                    target_username = comandi[1]
                    if target_username in utenti_connessi:
                        chiave_pubblica_target = utenti_connessi[target_username]['chiave_pubblica']
                        # Invia la chiave pubblica con un prefisso per il client
                        conn.sendall(f"/pubkey_response {target_username} {chiave_pubblica_target}".encode())
                    else:
                        conn.sendall(f"Errore: utente {target_username} non trovato.".encode())

                elif comando == '/multicast':
                    utenti_connessi[username]['mode'] = 'multicast'
                    conn.sendall("Modalità multicast attivata.".encode())

                elif comando == '/broadcast':
                    utenti_connessi[username]['mode'] = 'broadcast'
                    conn.sendall("Modalità broadcast attivata.".encode())

                elif comando == '/help':
                    help_message = """
Comandi disponibili:
/help - Mostra questo messaggio di aiuto
/multicast - Passa alla modalità multicast (messaggi al gruppo)
/broadcast - Passa alla modalità broadcast (messaggi a tutti)
/encrypt <on/off> - Abilita o disabilita la crittografia per i messaggi di gruppo e privati
"""
                    conn.sendall(help_message.encode())

                else:
                    conn.sendall("Comando non riconosciuto.".encode())

            else:
                # Messaggio normale
                user_mode = utenti_connessi[username]['mode']
                user_encrypt = utenti_connessi[username]['encrypt']

                if user_mode == 'multicast':
                    group_name = utenti_connessi[username]['group']
                    psk = gruppi[group_name]['psk']

                    if user_encrypt:
                        # Decripta il messaggio usando il PSK
                        try:
                            psk_bytes = psk.encode()
                            cipher_aes = AES.new(psk_bytes.ljust(32)[:32], AES.MODE_CBC, iv=psk_bytes.ljust(16)[:16])
                            messaggio_decriptato = unpad(cipher_aes.decrypt(bytes.fromhex(messaggio_decodificato)), AES.block_size).decode()
                        except Exception as e:
                            print(f"Errore nella decriptazione del messaggio: {e}")
                            continue
                    else:
                        messaggio_decriptato = messaggio_decodificato

                    formatted_message = f"[{timestamp}] [Gruppo {group_name}] {username}: {messaggio_decriptato}"

                    # Salva il messaggio nel log
                    with open(f"chat_{contatore_log}.txt", "a", encoding='utf-8') as f:
                        f.write(f"{formatted_message}\n")

                    # Invia il messaggio agli utenti del gruppo
                    for user in gruppi[group_name]['users']:
                        if user != username:
                            conn_dest = utenti_connessi[user]['conn']
                            if utenti_connessi[user]['encrypt']:
                                # Cripta il messaggio con il PSK
                                psk_bytes = psk.encode()
                                cipher_aes = AES.new(psk_bytes.ljust(32)[:32], AES.MODE_CBC, iv=psk_bytes.ljust(16)[:16])
                                messaggio_criptato = cipher_aes.encrypt(pad(messaggio_decriptato.encode(), AES.block_size))
                                messaggio_hex = messaggio_criptato.hex()
                                conn_dest.sendall(f"[{timestamp}] [Gruppo {group_name}] {messaggio_hex}".encode())
                            else:
                                conn_dest.sendall(formatted_message.encode())
                else:
                    # Messaggio broadcast
                    formatted_message = f"[{timestamp}] {username}: {messaggio_decodificato}"
                    for user in utenti_connessi:
                        # Invia il messaggio a tutti, compreso il mittente
                        utenti_connessi[user]['conn'].sendall(formatted_message.encode())

        except Exception as e:
            print(f"Errore: {e}")
            break

    # Rimuove l'utente dalla lista quando si disconnette
    del utenti_connessi[username]
    conn.close()

    # Rimuove l'utente dal gruppo
    gruppi[group_name]['users'].remove(username)

    # Informa gli altri utenti che l'utente si è disconnesso
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    messaggio_disconnessione = f"[{timestamp}] {username} si è disconnesso."
    for user in utenti_connessi:
        utenti_connessi[user]['conn'].sendall(messaggio_disconnessione.encode())

    # Salva l'evento di disconnessione nel log
    with open(f"chat_{contatore_log}.txt", "a", encoding='utf-8') as f:
        f.write(f"[{timestamp}] {indirizzo[0]}:{indirizzo[1]} {username} si è disconnesso.\n")

# Configurazione del server
def avvia_server():
    parser = argparse.ArgumentParser(description='Avvia il server di chat.')
    parser.add_argument('-p', '--port', type=int, default=8000, help='Porta su cui il server ascolterà.')
    args = parser.parse_args()

    host = '0.0.0.0'
    port = args.port  # Porta specificata con il parametro -p

    # Inizializza il contatore del file di log
    contatore_log = inizializza_contatore_log()
    print(f"Il server utilizzerà il file di log: chat_{contatore_log}.txt")

    # Carica o genera le chiavi RSA del server
    chiave_privata, chiave_pubblica = carica_o_genera_chiavi()
    print("Chiavi RSA del server caricate o generate.")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()

    print(f"Server in ascolto sulla porta {port}...")

    while True:
        conn, indirizzo = server_socket.accept()
        threading.Thread(target=gestisci_client, args=(conn, indirizzo, contatore_log, chiave_privata), daemon=True).start()

if __name__ == "__main__":
    avvia_server()
