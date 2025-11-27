from Crypto.PublicKey import RSA

#Name keys
pubkeyfile = "server_public_key.pem"
privkeyfile = "server_public_key.pem"

#Generate keys
keypair = RSA.generate(2048)

with open(pubkeyfile, 'wb') as f:
        f.write(keypair.public_key().export_key(format='PEM'))
        
#Make priv_key file without a passcode
with open(privkeyfile, 'wb') as f:
        f.write(keypair.export_key(format='PEM'))

