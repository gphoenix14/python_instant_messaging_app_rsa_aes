import socket
import threading
import json
import os
from datetime import datetime
import argparse
from Crypto.PublicKey import RSA

# Dizionario per memorizzare gli utenti connessi
utenti_connessi = {}  # username: { 'conn': connessione, 'indirizzo': indirizzo, 'chiave_pubblica': chiave_pubblica }

# Funzione per inizializzare il contatore del file di log
def inizializza_contatore_log():
    contatore_log = 1
    while os.path.exists(f"chat_{contatore_log}.txt"):
        contatore_log += 1
    return contatore_log

# Funzione per gestire i messaggi dei client
def gestisci_client(conn, indirizzo, contatore_log):
    try:
        # Riceve le informazioni iniziali dal client
        dati_iniziali_bytes = conn.recv(4096)
        dati_iniziali = dati_iniziali_bytes.decode()
        info = json.loads(dati_iniziali)
        username = info['username']
        chiave_pubblica = info['chiave_pubblica']

        # Verifica se l'username è già in uso
        if username in utenti_connessi:
            conn.sendall(f"Errore: L'username '{username}' è già in uso. Scegli un altro username.".encode())
            conn.close()
            return
    except Exception as e:
        print(f"Errore nella ricezione dei dati iniziali: {e}")
        conn.close()
        return

    # Memorizza l'utente
    utenti_connessi[username] = {
        'conn': conn,
        'indirizzo': indirizzo,
        'chiave_pubblica': chiave_pubblica,
        'encrypt': False
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
        f.write(f"[{timestamp}] {indirizzo[0]}:{indirizzo[1]} {username} si è connesso.\n")

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

                else:
                    conn.sendall("Comando non riconosciuto.".encode())

            else:
                # Messaggio normale
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

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()

    print(f"Server in ascolto sulla porta {port}...")

    while True:
        conn, indirizzo = server_socket.accept()
        threading.Thread(target=gestisci_client, args=(conn, indirizzo, contatore_log), daemon=True).start()

if __name__ == "__main__":
    avvia_server()
