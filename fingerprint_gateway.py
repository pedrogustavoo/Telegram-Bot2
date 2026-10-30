
import ssl
import socket
import json
import hashlib

from pathlib import Path

BASE = Path(__file__).resolve().parent

with open(BASE / "gateways.json", encoding="utf-8") as f:
    gateways = json.load(f)

gw_id = input("Gateway (ex: GW008): ").strip().upper()

if gw_id not in gateways:
    raise ValueError("Gateway nao encontrado no JSON!")

gw = gateways[gw_id]

if gw["protocolo"].lower() != "https":
    raise ValueError("Esse gateway nao usa HTTPS!")

ip = gw["ip"]
hostname = gw["tls_hostname"]
ca = BASE / gw["ca"]

print(f"\nGateway: {gw_id}")
print(f"IP: {ip}")
print(f"CA: {ca}")

# Cria contexto TLS usando a CA cadastrada
contexto = ssl.create_default_context(
    cafile=str(ca)
)

# Compatibilidade com certificados Browan antigos
contexto.verify_flags &= ~ssl.VERIFY_X509_STRICT

# Conecta e verifica o certificado
with socket.create_connection((ip, 443), timeout=10) as sock:
    with contexto.wrap_socket(
        sock,
        server_hostname=hostname
    ) as conexao:

        certificado = conexao.getpeercert(
            binary_form=True
        )

        fingerprint = hashlib.sha256(
            certificado
        ).hexdigest().upper()

        print("\nCERTIFICADO VALIDADO!")
        print("SHA-256:", fingerprint)
        print("\nCopie para tls_fingerprint_sha256")
