import base64, json, struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64(v): return base64.urlsafe_b64encode(v).decode().rstrip('=')
def sized(v): return struct.pack('>I',len(v))+v
recipient=ec.derive_private_key(1,ec.SECP256R1())
ephemeral=ec.derive_private_key(2,ec.SECP256R1())
point=ephemeral.public_key().public_numbers()
vectors=[]
for u,v in [(b'',b''),(b'Alice',b'Bob')]:
 header={'alg':'ECDH-ES','enc':'A256GCM','epk':{'kty':'EC','crv':'P-256','x':b64(point.x.to_bytes(32,'big')),'y':b64(point.y.to_bytes(32,'big'))}}
 if u: header.update(apu=b64(u),apv=b64(v))
 protected=b64(json.dumps(header,separators=(',',':')).encode())
 other=sized(b'A256GCM')+sized(u)+sized(v)+struct.pack('>I',256)
 cek=ConcatKDFHash(algorithm=hashes.SHA256(),length=32,otherinfo=other).derive(ephemeral.exchange(ec.ECDH(),recipient.public_key()))
 iv=bytes(range(12));plain=b'Independent JWE fixture\x00\xff'
 sealed=AESGCM(cek).encrypt(iv,plain,protected.encode())
 vectors.append({'compact':'.'.join([protected,'',b64(iv),b64(sealed[:-16]),b64(sealed[-16:])]),'plaintext':b64(plain)})
print(json.dumps({'generator':'Python cryptography 41.0.7 ConcatKDFHash(SHA256) and AESGCM; fixed synthetic scalars 1 and 2','recipient_private':b64((1).to_bytes(32,'big')),'vectors':vectors},indent=2))
