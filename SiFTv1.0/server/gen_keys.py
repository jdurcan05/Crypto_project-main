from Crypto.PublicKey import RSA

#Idk if we need anything more

pubkeyfile = "server_public_key.pem"
privkeyfile = "server_public_key.pem"


keypair = RSA.generate(2048)

with open(pubkeyfile, 'wb') as f:
        f.write(keypair.public_key().export_key(format='PEM'))
        
#excersize has a passkey. Would we want this? 
with open(privkeyfile, 'wb') as f:
        f.write(keypair.export_key(format='PEM'))

