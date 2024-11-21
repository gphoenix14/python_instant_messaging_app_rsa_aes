import socket
import threading
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import sys
import queue

def ricevi_messaggi(sock, gruppo, psk_gruppo, chiave_privata, queue_pubkey):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break

            try:
                # Prova a decodificare come stringa
                messaggio = data.decode()
                if messaggio.startswith("[Whisper da"):
                    # Messaggio privato
                    # Estrae la parte crittografata
                    parti = messaggio.split(":", 1)
                    if len(parti) == 2:
                        messaggio_crittografato = bytes.fromhex(parti[1].strip())
                        # Decripta con la chiave privata
                        cipher_rsa = PKCS1_OAEP.new(chiave_privata)
                        messaggio_decriptato = cipher_rsa.decrypt(messaggio_crittografato)
                        print(f"{parti[0]}: {messaggio_decriptato.decode()}")
                    else:
                        print(messaggio)
                elif messaggio.startswith("/pubkey_response"):
                    # Ricezione della chiave pubblica richiesta
                    _, destinatario, chiave_pubblica_dest = messaggio.split(" ", 2)
                    # Metti la chiave pubblica nella coda
                    queue_pubkey.put((destinatario, chiave_pubblica_dest))
                else:
                    print(messaggio)
            except UnicodeDecodeError:
                # Se fallisce, prova a decriptare con AES (per messaggi multicast)
                key = pad(psk_gruppo.encode(), 32)
                cipher = AES.new(key, AES.MODE_ECB)
                messaggio_decriptato = unpad(cipher.decrypt(data), AES.block_size)
                print(messaggio_decriptato.decode())
        except Exception as e:
            print(f"Errore: {e}")
            break

if __name__ == "__main__":
    if len(sys.argv) != 8:
        print("Uso: python client.py <ip_server> <porta_server> <username> <path_chiave_pubblica> <path_chiave_privata> <gruppo> <psk_gruppo>")
        sys.exit()

    ip_server = sys.argv[1]
    porta_server = int(sys.argv[2])
    username = sys.argv[3]
    path_chiave_pubblica = sys.argv[4]
    path_chiave_privata = sys.argv[5]
    gruppo = sys.argv[6]
    psk_gruppo = sys.argv[7]

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
        'chiave_pubblica': chiave_pubblica,
        'gruppo': gruppo,
        'psk_gruppo': psk_gruppo
    }
    sock.sendall(json.dumps(info).encode())

    # Stato iniziale
    encrypt = False
    mode = 'broadcast'

    # Coda per ricevere la chiave pubblica del destinatario
    queue_pubkey = queue.Queue()

    # Avvia thread per ricevere messaggi
    threading.Thread(target=ricevi_messaggi, args=(sock, gruppo, psk_gruppo, chiave_privata, queue_pubkey), daemon=True).start()

    while True:
        try:
            messaggio = input()
            if messaggio.startswith('/'):
                comandi = messaggio.strip().split()
                comando = comandi[0]

                if comando == '/whisper':
                    if len(comandi) < 3:
                        print("Uso corretto: /whisper <destinatario> <messaggio>")
                        continue

                    destinatario = comandi[1]
                    messaggio_privato = messaggio.partition(destinatario)[2].strip()

                    if encrypt:
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

                        chiave_pubblica_rsa = RSA.import_key(chiave_pubblica_dest)
                        cipher_rsa = PKCS1_OAEP.new(chiave_pubblica_rsa)
                        messaggio_crittografato = cipher_rsa.encrypt(messaggio_privato.encode())
                        # Invia il messaggio crittografato in formato esadecimale per evitare problemi di codifica
                        messaggio_hex = messaggio_crittografato.hex()
                        sock.sendall(f"/whisper {destinatario} {messaggio_hex}".encode())
                    else:
                        # Invia il messaggio in chiaro
                        sock.sendall(messaggio.encode())

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

                elif comando == '/broadcast':
                    mode = 'broadcast'
                    # Informa il server
                    sock.sendall(messaggio.encode())

                elif comando == '/multicast':
                    mode = 'multicast'
                    # Informa il server
                    sock.sendall(messaggio.encode())

                else:
                    sock.sendall(messaggio.encode())
            else:
                # Messaggio normale
                if mode == 'multicast':
                    # Crittografia AES
                    key = pad(psk_gruppo.encode(), 32)
                    cipher = AES.new(key, AES.MODE_ECB)
                    messaggio_crittografato = cipher.encrypt(pad(messaggio.encode(), AES.block_size))
                    sock.sendall(messaggio_crittografato)
                else:
                    # Invia il messaggio in chiaro
                    sock.sendall(messaggio.encode())
        except KeyboardInterrupt:
            print("\nChiusura del client.")
            sock.close()
            break
        except Exception as e:
            print(f"Errore: {e}")
            sock.close()
            break
