import secrets              

bits = secrets.randbits(256)
bits_hex = hex(bits)
priv_key = bits_hex[2:]

print ('bits:', bits)
print ('bits_hex:', bits_hex)
print ('priv_key:',priv_key)
print ('')

import eth_keys, eth_utils, binascii, os

bits_byt = (bits).to_bytes(32, byteorder='big')
bytes_hex = binascii.hexlify(bits_byt)

print ('bytes:', bits_byt)
print ('bytes_hex:', bytes_hex)
print ('')

##privKey = eth_keys.keys.PrivateKey(os.urandom(32))
privKey = eth_keys.keys.PrivateKey(binascii.unhexlify(bytes_hex))
pubKey = privKey.public_key
pubKeyCompressed = '0' + str(2 + int(pubKey) % 2) + str(pubKey[2:66])
address = pubKey.to_checksum_address()

print ('privKey (64 hex digits):', privKey)
print ('pubKey (plain, 128 hex digits):', pubKey)
print ('pubKey (compressed):', pubKeyCompressed)
print ('address:', address)



