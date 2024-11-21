from Crypto.PublicKey import RSA

# Genera una chiave privata RSA a 2048 bit
chiave = RSA.generate(2048)

# Esporta la chiave privata
chiave_privata = chiave.export_key()
with open("chiave_privata.pem", "wb") as f:
    f.write(chiave_privata)

# Esporta la chiave pubblica
chiave_pubblica = chiave.publickey().export_key()
with open("chiave_pubblica.pem", "wb") as f:
    f.write(chiave_pubblica)

print("Chiavi generate e salvate su disco.")
