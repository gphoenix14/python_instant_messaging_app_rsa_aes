import socket
import threading
import json
import sys
import queue
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def ricevi_messaggi(sock, chiave_privata, queue_pubkey):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break

            try:
                # Prova a decodificare come stringa
                messaggio = data.decode()
                if messaggio.startswith("Errore:"):
                    # Errore ricevuto dal server (es. username già in uso)
                    print(messaggio)
                    sock.close()
                    sys.exit()
                elif "[Whisper da" in messaggio:
                    # Messaggio privato
                    # Trova l'indice di "]:"
                    indice_header_end = messaggio.find("]:")
                    if indice_header_end != -1:
                        # Header include timestamp e "[Whisper da username]"
                        header = messaggio[:indice_header_end+2]
                        # Il messaggio criptato è il resto
                        messaggio_crittografato_hex = messaggio[indice_header_end+2:].strip()
                        try:
                            messaggio_crittografato = bytes.fromhex(messaggio_crittografato_hex)
                            # Decripta con la chiave privata
                            cipher_rsa = PKCS1_OAEP.new(chiave_privata)
                            messaggio_decriptato = cipher_rsa.decrypt(messaggio_crittografato)
                            print(f"{header} {messaggio_decriptato.decode()}")
                        except ValueError:
                            # Se non è esadecimale, stampa come è
                            print(messaggio)
                    else:
                        print(messaggio)
                elif messaggio.startswith("/pubkey_response"):
                    # Ricezione della chiave pubblica richiesta
                    _, destinatario, chiave_pubblica_dest = messaggio.split(" ", 2)
                    # Metti la chiave pubblica nella coda
                    queue_pubkey.put((destinatario, chiave_pubblica_dest))
                else:
                    # Messaggio normale o messaggio di benvenuto
                    print(messaggio)
            except UnicodeDecodeError:
                # Se fallisce, stampa errore
                print("Errore nella decodifica del messaggio.")
        except Exception as e:
            print(f"Errore: {e}")
            break

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Uso: python client.py <ip_server> <porta_server> <username> <path_chiave_pubblica> <path_chiave_privata>")
        sys.exit()

    ip_server = sys.argv[1]
    porta_server = int(sys.argv[2])
    username = sys.argv[3]
    path_chiave_pubblica = sys.argv[4]
    path_chiave_privata = sys.argv[5]

    # Legge la chiave pubblica dal file
    with open(path_chiave_pubblica, 'r') as f:
        chiave_pubblica = f.read()

    # Legge la chiave privata dal file
    with open(path_chiave_privata, 'r') as f:
        chiave_privata_pem = f.read()
    chiave_privata = RSA.import_key(chiave_privata_pem)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip_server, porta_server))

    # Invia le informazioni iniziali al server
    info = {
        'username': username,
        'chiave_pubblica': chiave_pubblica
    }
    sock.sendall(json.dumps(info).encode())

    # Attende la risposta dal server (benvenuto o errore)
    response = sock.recv(4096).decode()
    if response.startswith("Errore:"):
        print(response)
        sock.close()
        sys.exit()
    else:
        print(response)

    # Coda per ricevere la chiave pubblica del destinatario
    queue_pubkey = queue.Queue()

    # Dizionario per le chiavi pubbliche cache
    public_keys_cache = {}  # username: chiave_pubblica

    # Avvia thread per ricevere messaggi
    threading.Thread(target=ricevi_messaggi, args=(sock, chiave_privata, queue_pubkey), daemon=True).start()

    # Stato iniziale
    encrypt = True  # La crittografia è attiva di default
    current_recipient = None  # Nessun destinatario di chat privata di default

    # Dichiara i comandi disponibili
    help_message = """
Comandi disponibili:
/help - Mostra questo messaggio di aiuto
/chat <username> - Entra in modalità chat privata con un utente
/broadcast - Passa alla modalità broadcast (messaggi a tutti)
/whisper <username> <messaggio> - Invia un messaggio privato a un utente
/refresh_key <username> - Aggiorna la chiave pubblica di un utente
/print_keys - Mostra le chiavi pubbliche in cache
/encrypt <on/off> - Abilita o disabilita la crittografia per i messaggi privati
"""

    while True:
        try:
            messaggio = input()
            if messaggio.startswith('/'):
                comandi = messaggio.strip().split()
                comando = comandi[0]

                if comando == '/chat':
                    if len(comandi) != 2:
                        print("Uso corretto: /chat <username>")
                        continue
                    current_recipient = comandi[1]
                    print(f"Modalità chat privata con {current_recipient} attivata.")
                elif comando == '/broadcast':
                    current_recipient = None
                    print("Modalità broadcast attivata.")
                elif comando == '/whisper':
                    if len(comandi) < 3:
                        print("Uso corretto: /whisper <destinatario> <messaggio>")
                        continue

                    destinatario = comandi[1]
                    messaggio_privato = messaggio.partition(destinatario)[2].strip()

                    if encrypt:
                        # Controlla se la chiave pubblica del destinatario è in cache
                        if destinatario in public_keys_cache:
                            chiave_pubblica_dest = public_keys_cache[destinatario]
                        else:
                            # Richiede la chiave pubblica del destinatario al server
                            sock.sendall(f"/get_pubkey {destinatario}".encode())

                            # Attende la chiave pubblica dal thread di ricezione
                            received_key = False
                            while True:
                                try:
                                    # Attende al massimo 5 secondi
                                    destinatario_ricevuto, chiave_pubblica_dest = queue_pubkey.get(timeout=5)
                                    if destinatario_ricevuto == destinatario:
                                        received_key = True
                                        break
                                except queue.Empty:
                                    print(f"Errore: tempo scaduto per la ricezione della chiave pubblica di {destinatario}.")
                                    break

                            if not received_key:
                                continue

                            if chiave_pubblica_dest.startswith("Errore"):
                                print(chiave_pubblica_dest)
                                continue

                            # Salva la chiave pubblica in cache
                            public_keys_cache[destinatario] = chiave_pubblica_dest

                        chiave_pubblica_rsa = RSA.import_key(chiave_pubblica_dest)
                        cipher_rsa = PKCS1_OAEP.new(chiave_pubblica_rsa)
                        messaggio_crittografato = cipher_rsa.encrypt(messaggio_privato.encode())
                        # Invia il messaggio crittografato in formato esadecimale per evitare problemi di codifica
                        messaggio_hex = messaggio_crittografato.hex()
                        sock.sendall(f"/whisper {destinatario} {messaggio_hex}".encode())
                    else:
                        # Invia il messaggio in chiaro
                        sock.sendall(messaggio.encode())

                elif comando == '/refresh_key':
                    if len(comandi) != 2:
                        print("Uso corretto: /refresh_key <username>")
                        continue
                    destinatario = comandi[1]
                    # Richiede la chiave pubblica aggiornata al server
                    sock.sendall(f"/get_pubkey {destinatario}".encode())

                    # Attende la chiave pubblica dal thread di ricezione
                    received_key = False
                    while True:
                        try:
                            # Attende al massimo 5 secondi
                            destinatario_ricevuto, chiave_pubblica_dest = queue_pubkey.get(timeout=5)
                            if destinatario_ricevuto == destinatario:
                                received_key = True
                                break
                        except queue.Empty:
                            print(f"Errore: tempo scaduto per la ricezione della chiave pubblica di {destinatario}.")
                            break

                    if not received_key:
                        continue

                    if chiave_pubblica_dest.startswith("Errore"):
                        print(chiave_pubblica_dest)
                        continue

                    # Aggiorna la chiave pubblica in cache
                    public_keys_cache[destinatario] = chiave_pubblica_dest
                    print(f"Chiave pubblica di {destinatario} aggiornata.")

                elif comando == '/print_keys':
                    if public_keys_cache:
                        print("Chiavi pubbliche in cache:")
                        for user, key in public_keys_cache.items():
                            print(f"Utente: {user}\n{key}\n")
                    else:
                        print("Nessuna chiave pubblica in cache.")

                elif comando == '/encrypt':
                    if len(comandi) < 2:
                        print("Uso corretto: /encrypt <on/off>")
                        continue
                    stato = comandi[1]
                    if stato == 'on':
                        encrypt = True
                    elif stato == 'off':
                        encrypt = False
                    else:
                        print("Comando non riconosciuto.")
                        continue
                    # Informa il server
                    sock.sendall(messaggio.encode())

                elif comando == '/help':
                    print(help_message)

                else:
                    print("Comando non riconosciuto. Digita /help per la lista dei comandi.")

            else:
                if current_recipient:
                    # Invia il messaggio come whisper al destinatario corrente
                    destinatario = current_recipient
                    messaggio_privato = messaggio

                    if encrypt:
                        # Controlla se la chiave pubblica del destinatario è in cache
                        if destinatario in public_keys_cache:
                            chiave_pubblica_dest = public_keys_cache[destinatario]
                        else:
                            # Richiede la chiave pubblica del destinatario al server
                            sock.sendall(f"/get_pubkey {destinatario}".encode())

                            # Attende la chiave pubblica dal thread di ricezione
                            received_key = False
                            while True:
                                try:
                                    # Attende al massimo 5 secondi
                                    destinatario_ricevuto, chiave_pubblica_dest = queue_pubkey.get(timeout=5)
                                    if destinatario_ricevuto == destinatario:
                                        received_key = True
                                        break
                                except queue.Empty:
                                    print(f"Errore: tempo scaduto per la ricezione della chiave pubblica di {destinatario}.")
                                    break

                            if not received_key:
                                continue

                            if chiave_pubblica_dest.startswith("Errore"):
                                print(chiave_pubblica_dest)
                                continue

                            # Salva la chiave pubblica in cache
                            public_keys_cache[destinatario] = chiave_pubblica_dest

                        chiave_pubblica_rsa = RSA.import_key(chiave_pubblica_dest)
                        cipher_rsa = PKCS1_OAEP.new(chiave_pubblica_rsa)
                        messaggio_crittografato = cipher_rsa.encrypt(messaggio_privato.encode())
                        # Invia il messaggio crittografato in formato esadecimale per evitare problemi di codifica
                        messaggio_hex = messaggio_crittografato.hex()
                        sock.sendall(f"/whisper {destinatario} {messaggio_hex}".encode())
                    else:
                        # Invia il messaggio in chiaro
                        sock.sendall(f"/whisper {destinatario} {messaggio_privato}".encode())
                else:
                    # Invia il messaggio al server come messaggio broadcast
                    sock.sendall(messaggio.encode())

        except KeyboardInterrupt:
            print("\nChiusura del client.")
            sock.close()
            break
        except Exception as e:
            print(f"Errore: {e}")
            sock.close()
            break
