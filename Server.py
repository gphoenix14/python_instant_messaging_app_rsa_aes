import socket
import threading
import json
from Crypto.PublicKey import RSA
import os

# Dizionario per memorizzare gli utenti connessi
utenti_connessi = {}  # username: { 'conn': connessione, 'indirizzo': indirizzo, 'chiave_pubblica': chiave_pubblica, 'gruppo': gruppo, 'psk': psk, 'mode': 'broadcast' o 'multicast' }

# Contatore per i file di log
contatore_log = 1

# Memorizza i gruppi e le loro PSK
gruppi = {}

# Funzione per gestire i messaggi dei client
def gestisci_client(conn, indirizzo):
    global contatore_log
    # Riceve le informazioni iniziali dal client
    dati_iniziali = conn.recv(4096).decode()
    info = json.loads(dati_iniziali)
    username = info['username']
    chiave_pubblica = info['chiave_pubblica']
    gruppo = info['gruppo']
    psk_gruppo = info['psk_gruppo']

    # Controlla se il gruppo esiste già e verifica la PSK
    if gruppo in gruppi:
        if gruppi[gruppo] != psk_gruppo:
            conn.sendall("Errore: PSK del gruppo non corretta.".encode())
            conn.close()
            return
    else:
        gruppi[gruppo] = psk_gruppo

    # Memorizza l'utente
    utenti_connessi[username] = {'conn': conn, 'indirizzo': indirizzo, 'chiave_pubblica': chiave_pubblica, 'gruppo': gruppo, 'psk': psk_gruppo, 'mode': 'broadcast', 'encrypt': False}

    # Invia messaggio di broadcast agli altri utenti
    messaggio_broadcast = f"{username} si è connesso."
    for user in utenti_connessi:
        if user != username:
            utenti_connessi[user]['conn'].sendall(messaggio_broadcast.encode())

    # Loop per ricevere messaggi dal client
    while True:
        try:
            messaggio = conn.recv(4096)
            if not messaggio:
                break

            # Salva il messaggio nel log
            with open(f"chat_{contatore_log}.txt", "ab") as f:
                f.write(messaggio + b"\n")
            contatore_log += 1

            messaggio_decodificato = messaggio.decode(errors='ignore')

            if messaggio_decodificato.startswith('/'):
                # Comando
                comandi = messaggio_decodificato.strip().split()
                comando = comandi[0]

                if comando == '/whisper':
                    destinatario = comandi[1]
                    contenuto_messaggio = messaggio_decodificato.partition(destinatario)[2].strip()
                    # Inoltra il messaggio privato al destinatario
                    if destinatario in utenti_connessi:
                        utenti_connessi[destinatario]['conn'].sendall(f"[Whisper da {username}]: {contenuto_messaggio}".encode())
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

                elif comando == '/broadcast':
                    utenti_connessi[username]['mode'] = 'broadcast'
                    conn.sendall("Modalità broadcast attivata.".encode())

                elif comando == '/multicast':
                    utenti_connessi[username]['mode'] = 'multicast'
                    conn.sendall("Modalità multicast attivata.".encode())

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
                mode = utenti_connessi[username]['mode']
                if mode == 'broadcast':
                    for user in utenti_connessi:
                        if utenti_connessi[user]['mode'] == 'broadcast':
                            utenti_connessi[user]['conn'].sendall(f"{username}: {messaggio_decodificato}".encode())
                elif mode == 'multicast':
                    # Invia messaggio al gruppo
                    for user in utenti_connessi:
                        if utenti_connessi[user]['gruppo'] == utenti_connessi[username]['gruppo']:
                            utenti_connessi[user]['conn'].sendall(messaggio)
                else:
                    conn.sendall("Modalità non riconosciuta.".encode())

        except Exception as e:
            print(f"Errore: {e}")
            break

    # Rimuove l'utente dalla lista quando si disconnette
    del utenti_connessi[username]
    conn.close()

# Configurazione del server
def avvia_server():
    host = '0.0.0.0'
    port = 8000  # Usa la porta che preferisci

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()

    print("Server in ascolto...")

    while True:
        conn, indirizzo = server_socket.accept()
        threading.Thread(target=gestisci_client, args=(conn, indirizzo), daemon=True).start()

if __name__ == "__main__":
    avvia_server()
