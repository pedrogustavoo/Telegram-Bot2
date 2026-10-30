"""Diagnostico seguro para o cadastro TLS do GatewayManager.

Uso:
  python diagnosticar_ssl.py GW008
  python diagnosticar_ssl.py --todos
  python diagnosticar_ssl.py --todos --somente-cadastro

Este programa NAO envia usuario/senha nem aplica configuracoes.
Uma segunda conexao SEM validacao so e feita se o handshake validado falhar,
para exibir a impressao digital apresentada pelo endereco cadastrado.
Nunca salva automaticamente o certificado observado como confiavel.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import socket
import ssl
from pathlib import Path

BASE = Path(__file__).resolve().parent
ARQUIVO_JSON = BASE / "gateways.json"
DIR_CERTS = (BASE / "certificados").resolve()


def print_item(label: str, value: str) -> None:
    print(f"  {label}: {value}")


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest().upper()


def validar_cadastro(gw_id: str, dados: dict) -> tuple[str, str, Path | None, str | None]:
    if not isinstance(dados, dict):
        raise ValueError("cadastro precisa ser um objeto JSON")

    ip = str(ipaddress.ip_address(dados["ip"]))
    if not ipaddress.ip_address(ip).is_private:
        raise ValueError("IP de gerenciamento nao e privado; confirme o cadastro")

    protocolo = str(dados["protocolo"]).lower().strip()
    if protocolo == "http":
        if dados.get("ca"):
            print("  AVISO: gateway HTTP tem ca cadastrada, mas essa CA nao sera usada")
        if dados.get("tls_fingerprint_sha256"):
            print("  AVISO: gateway HTTP tem fingerprint TLS, mas esse valor nao sera usado")
        return ip, protocolo, None, None
    if protocolo != "https":
        raise ValueError("protocolo deve ser 'http' ou 'https'")
   
    nome = str(dados.get("tls_hostname") or "").strip()
    c1 =dados.get("fabricante") != "milesight"
    c2 =not nome or "*" in nome or "://" in nome or "/" in nome
    if c1 and c2:
        raise ValueError("tls_hostname ausente ou invalido")
    if c1:
        ca_rel= dados.get("ca")     
    else:
        ca_rel= dados.get("certificado_servidor")
    if not isinstance(ca_rel, str) or not ca_rel.strip():
        raise ValueError(f"Arrume o certificado do Gateway: {gw_id}")
    
    ca_path = (BASE / ca_rel).resolve()
        
    if not isinstance(ca_rel, str) or not ca_rel.strip():
        raise ValueError("campo 'ca' ausente (caminho do CRT da autoridade)")
    ca_path = (BASE / ca_rel).resolve()
    if not ca_path.is_relative_to(DIR_CERTS):
        raise ValueError("a CA precisa ficar dentro da pasta certificados/")
    if not ca_path.is_file():
        raise FileNotFoundError(f"arquivo CA nao encontrado: {ca_path}")

    try:
        pem = ca_path.read_text(encoding="ascii")
        der_ca = ssl.PEM_cert_to_DER_cert(pem)
    except (OSError, ValueError, UnicodeError) as exc:
        raise ValueError("CA invalida; esperado certificado PEM com BEGIN CERTIFICATE") from exc

    print_item("Arquivo CA", str(ca_path))
    print_item("SHA-256 CA (nao e o SHA-256 do gateway)", fingerprint(der_ca))
    print_item("Hostname TLS", nome)

    fp_conf = dados.get("tls_fingerprint_sha256")
    if not fp_conf:
        print("  AVISO: tls_fingerprint_sha256 ausente; nao e possivel verificar identidade individual")
        fp_conf = None
    else:
        fp_conf = re.sub(r"[^0-9A-Fa-f]", "", str(fp_conf)).upper()
        if not re.fullmatch(r"[0-9A-F]{64}", fp_conf):
            raise ValueError("tls_fingerprint_sha256 invalido: precisa ter 64 caracteres hexadecimais")
        if fp_conf == fingerprint(der_ca):
            raise ValueError("fingerprint cadastrado e da CA, nao do certificado HTTPS do gateway")

    return ip, protocolo, ca_path, fp_conf


def obter_fingerprint_apresentado(ip: str, hostname: str) -> str:
    # Somente diagnostico sem credenciais. Certificado apresentado NAO e confiavel por esta coleta.
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexto.check_hostname = False
    contexto.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, 443), timeout=5) as sock:
        with contexto.wrap_socket(sock, server_hostname=hostname) as tls:
            cert_der = tls.getpeercert(binary_form=True)
            if not cert_der:
                raise ValueError("servidor nao apresentou certificado")
            return fingerprint(cert_der)


def verificar_tls(ip: str, hostname: str, ca_path: Path, fp_conf: str | None) -> None:
    contexto = ssl.create_default_context(cafile=str(ca_path))
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        contexto.verify_flags &= ~ssl.VERIFY_X509_STRICT
    # A verificacao de CA e hostname continua ativada.
    with socket.create_connection((ip, 443), timeout=5) as sock:
        with contexto.wrap_socket(sock, server_hostname=hostname) as tls:
            cert_der = tls.getpeercert(binary_form=True)
            if not cert_der:
                raise ValueError("servidor nao apresentou certificado")
            fp_atual = fingerprint(cert_der)
            print_item("Cadeia e hostname", "OK")
            print_item("SHA-256 do certificado HTTPS", fp_atual)
            if fp_conf:
                if fp_atual != fp_conf:
                    raise ValueError(
                        "fingerprint individual NAO confere! "
                        "Confira IP, certificado de servidor e cadastro antes de enviar senha."
                    )
                print_item("Fingerprint individual", "OK")
            else:
                print("  AVISO: cadeia valida, mas sem checagem do fingerprint individual")


def diagnosticar(gw_id: str, dados: dict, somente_cadastro: bool) -> bool:
    print(f"\n=== {gw_id} ===")
    try:
        ip, protocolo, ca_path, fp_conf = validar_cadastro(gw_id, dados)
        print_item("IP", ip)
        print_item("Protocolo", protocolo.upper())
        if protocolo == "http":
            print("  AVISO: HTTP nao utiliza TLS e nao protege sozinho credenciais administrativas")
            return True
        if somente_cadastro:
            print("  CADASTRO: estruturalmente valido (rede nao testada)")
            return True
        assert ca_path is not None
        hostname = str(dados["tls_hostname"]).strip()
        try:
            verificar_tls(ip, hostname, ca_path, fp_conf)
        except ssl.SSLCertVerificationError as exc:
            print_item("Erro SSL", str(exc))
            if "signature failure" in str(exc).lower() or "issuer" in str(exc).lower():
                print("  DIAGNOSTICO: provavel CA incorreta ou cadeia do servidor invalida")
            elif "hostname" in str(exc).lower() or "ip address mismatch" in str(exc).lower():
                print("  DIAGNOSTICO: tls_hostname nao corresponde ao certificado apresentado")
            elif "authority key identifier" in str(exc).lower():
                print("  DIAGNOSTICO: certificacao Browan legada; confira modo X509 nao rigoroso")
            print_item("Fingerprint apresentado (NAO autenticado)", obter_fingerprint_apresentado(ip, hostname))
            return False
        print("  RESULTADO: validacao HTTPS concluida, sem envio de credenciais")
        return True
    except (OSError, ssl.SSLError, ValueError, KeyError, TypeError, socket.timeout) as exc:
        print(f"  FALHA: {type(exc).__name__}: {exc}")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Diagnosticar JSON, CA e TLS do GatewayManager (somente leitura)")
    parser.add_argument("gateway", nargs="?", help="ID como GW008")
    parser.add_argument("--todos", action="store_true", help="Diagnosticar todos do JSON")
    parser.add_argument("--somente-cadastro", action="store_true", help="Nao conectar a rede")
    args = parser.parse_args()
    if not args.gateway and not args.todos:
        parser.error("informe um gateway ou --todos")
    try:
        cadastros = json.loads(ARQUIVO_JSON.read_text(encoding="utf-8"))
        if not isinstance(cadastros, dict):
            raise ValueError("o gateways.json deve conter objeto com ids de gateways")
    except (OSError, ValueError) as exc:
        print(f"ERRO ao abrir gateways.json: {exc}")
        return 1
    if args.todos:
        itens = list(cadastros.items())
    else:
        ids = {k.upper(): k for k in cadastros}
        chave = ids.get(args.gateway.upper())
        if chave is None:
            print(f"Gateway {args.gateway} nao encontrado no gateways.json")
            return 1
        itens = [(chave, cadastros[chave])]
    sucessos = sum(diagnosticar(k, v, args.somente_cadastro) for k, v in itens)
    print(f"\nResultado: {sucessos}/{len(itens)} cadastros sem falhas detectadas nesse teste.")
    return 0 if sucessos == len(itens) else 1


if __name__ == "__main__":
    raise SystemExit(main())
