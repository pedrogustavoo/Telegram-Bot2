"""Cliente Milesight UG65: HTTPS pinado, consulta e Apply com preflight.

Protecao: PREVIEW por padrao; POST somente com ENABLE_MILESIGHT_APPLY=1 e
apos confirmacao explicita. Nunca repete automaticamente um POST.
"""
from __future__ import annotations

import base64
import copy
import time
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import ssl
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

BASE = Path(__file__).resolve().parent


class MilesightClient:
    def __init__(self, gw_id: str, gateway: dict):
        self.gw_id = gw_id.upper()
        self.gateway = gateway
        self.ip = str(ipaddress.ip_address(gateway["ip"]))
        if not ipaddress.ip_address(self.ip).is_private:
            raise ValueError("Acesso administrativo permitido apenas por IP privado")

        self.porta = int(gateway.get("api_port", 8080))
        if not 1 <= self.porta <= 65535:
            raise ValueError("Porta da API invalida")

        # O SHA-256 deve identificar o certificado HTTPS do SERVIDOR,
        # nao a CA. Aceita fingerprint no JSON ou caminho do PEM ja conferido.
        fp_json = gateway.get("tls_fingerprint_sha256")
        pem_nome = gateway.get("certificado_servidor")

        fp_pem = None
        if pem_nome:
            caminho = (BASE / pem_nome).resolve()
            pasta_certificados = (BASE / "certificados").resolve()
            if not caminho.is_relative_to(pasta_certificados) or not caminho.is_file():
                raise ValueError("Certificado do servidor nao encontrado em certificados/")
            pem = caminho.read_text(encoding="ascii")
            der = ssl.PEM_cert_to_DER_cert(pem)
            fp_pem = hashlib.sha256(der).hexdigest()

        if fp_json:
            fp_json = re.sub(r"[:\s]", "", fp_json).lower()
            if not re.fullmatch(r"[0-9a-f]{64}", fp_json):
                raise ValueError("tls_fingerprint_sha256 invalido")

        if fp_json and fp_pem and not hmac.compare_digest(fp_json, fp_pem):
            raise ValueError("Fingerprint do JSON difere do certificado_servidor")

        fp = fp_json or fp_pem
        if not fp:
            raise ValueError("Cadastre tls_fingerprint_sha256 ou certificado_servidor (verificado fora de banda)")

        self.fingerprint_esperado = bytes.fromhex(fp)
        self.token = None

    @staticmethod
    def criptografar_senha(senha: str) -> str:
        """Transformacao do login da versao de firmware JA TESTADA no UG65.

        Nao equivale a protecao de transporte: a conexao TLS autenticada e obrigatoria.
        """
        cipher = AES.new(
            b"1111111111111111", AES.MODE_CBC, iv=b"2222222222222222"
        )
        dados = pad(senha.encode("utf-8"), AES.block_size)
        return base64.b64encode(cipher.encrypt(dados)).decode("ascii")

    def chamar_api(self, metodo: str, rota: str, dados: dict | None = None,
                   token: str | None = None) -> tuple[int, dict]:
        if metodo not in ("GET", "POST") or not rota.startswith("/api/"):
            raise ValueError("Metodo ou rota nao permitido")

        # TLS sem CA publica: o certificado deve ser FIXADO E CONFERIDO
        # ANTES de qualquer requisicao (inclusive usuario e senha).
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(
            self.ip, port=self.porta, context=contexto, timeout=10
        )
        try:
            conn.connect()
            recebido = conn.sock.getpeercert(binary_form=True)
            if not recebido or not hmac.compare_digest(
                hashlib.sha256(recebido).digest(), self.fingerprint_esperado
            ):
                raise ssl.SSLError("Certificado TLS diferente do fingerprint cadastrado")

            headers = {"Accept": "application/json"}
            body = None
            if dados is not None:
                headers["Content-Type"] = "application/json"
                body = json.dumps(dados)
            if token:
                headers["Authorization"] = f"Bearer {token}"

            conn.request(metodo, rota, body=body, headers=headers)
            resposta = conn.getresponse()
            conteudo = resposta.read()
            try:
                resultado = json.loads(conteudo)
            except (ValueError, UnicodeDecodeError) as erro:
                raise ValueError("API Milesight retornou resposta nao JSON") from erro
            if not isinstance(resultado, dict):
                raise ValueError("Formato inesperado de resposta da API Milesight")
            return resposta.status, resultado
        finally:
            conn.close()

    def login(self) -> None:
        usuario = os.getenv(f"{self.gw_id}_USERNAME", "admin")
        senha = os.getenv(f"{self.gw_id}_PASSWORD")
        if not senha:
            raise ValueError(f"Configure {self.gw_id}_PASSWORD no .env")

        status, resultado = self.chamar_api(
            "POST", "/api/internal/login",
            {"username": usuario, "password": self.criptografar_senha(senha)},
        )
        token = resultado.get("jwt") or resultado.get("token")
        if status != 200 or not isinstance(token, str) or not token:
            raise PermissionError(f"Login Milesight nao confirmado (HTTP {status})")
        self.token = token

    def consultar_packet(self) -> dict:
        """Consulta SOMENTE LEITURA; faz login automaticamente quando necessario."""
        if not self.token:
            self.login()
        status, config = self.chamar_api(
            "GET", "/api/packet-forwarder/network-servers", token=self.token
        )
        if status != 200:
            raise RuntimeError(f"Consulta Packet Forwarder falhou (HTTP {status})")
        return config


    # Campos documentados pelo fabricante para POST de Packet Forwarder.
    # 'connected' e estado dinamico (somente leitura), nao deve ser enviado.
    CAMPOS_POST = (
        "id", "servEnabled", "servAddr", "servType", "servPortUp",
        "servPortDown", "servMqttPort", "syncFreqPlan", "servGwKey",
        "Region", "Band", "username", "password",
    )
    TIPOS_DOCUMENTADOS = {"semtech", "ursalink", "loriot", "everynet"}
    CAMPOS_VOLATEIS = {"connected", "CupsUri", "TcUri"}

    def _validar_identidade(self, config: dict) -> None:
        esperado = str(self.gateway.get("eui") or "").upper()
        obtido = str(config.get("gatewayEui") or "").upper()
        if not esperado:
            raise ValueError("Cadastre o EUI no gateways.json antes do Apply Milesight")
        if esperado != obtido:
            raise ValueError(f"EUI diferente do cadastro para {self.gw_id}; Apply bloqueado")
        gateway_id = config.get("gatewayId")
        if not isinstance(gateway_id, str) or not gateway_id:
            raise ValueError("gatewayId nao retornado pela API; Apply bloqueado")
        if not isinstance(config.get("dataRetransmission"), bool):
            raise ValueError("dataRetransmission ausente ou invalido")
        servs = config.get("servs")
        if not isinstance(servs, list) or not servs:
            raise ValueError("Nenhum destino em servs; Apply bloqueado")
        ids = set()
        for servidor in servs:
            if not isinstance(servidor, dict):
                raise ValueError("Servidor malformado em servs")
            faltantes = [k for k in self.CAMPOS_POST if k not in servidor]
            if faltantes:
                raise ValueError(f"Faltam campos no destino: {', '.join(faltantes)}")
            destino_id = servidor["id"]
            if type(destino_id) is not int or destino_id in ids:
                raise ValueError("ID de destino invalido ou duplicado")
            ids.add(destino_id)
            if servidor["servType"] not in self.TIPOS_DOCUMENTADOS:
                raise ValueError(
                    f"Tipo de destino {servidor['servType']} nao documentado "
                    "para escrita nesta integracao; Apply bloqueado"
                )
            # Se houver configuracoes adicionais nao representadas no POST
            # documentado, nao arriscar descarta-las ou sobrescreve-las.
            for k, v in servidor.items():
                if k not in self.CAMPOS_POST and k not in self.CAMPOS_VOLATEIS:
                    if v not in (None, "", False, 0, [], {}):
                        raise ValueError(f"Campo adicional do destino '{k}' nao suportado para Apply")
            if servidor.get("CupsUri") or servidor.get("TcUri"):
                raise ValueError("Basic Station configurado: Apply nesta API bloqueado")
            if servidor["servType"] == "everynet" and "*" in str(servidor["password"]):
                raise ValueError("Senha Everynet mascarada; Apply nao seguro")
            for chave in ("servPortUp", "servPortDown", "servMqttPort"):
                if type(servidor[chave]) is not int:
                    raise ValueError(f"{chave} nao e inteiro no destino {destino_id}")
            for chave in ("servEnabled", "syncFreqPlan"):
                if not isinstance(servidor[chave], bool):
                    raise ValueError(f"{chave} invalido no destino {destino_id}")

    def _post_body(self, config: dict) -> dict:
        self._validar_identidade(config)
        return {
            "gatewayId": config["gatewayId"],
            "dataRetransmission": config["dataRetransmission"],
            "servs": [
                {campo: copy.deepcopy(destino[campo]) for campo in self.CAMPOS_POST}
                for destino in config["servs"]
            ],
        }

    @staticmethod
    def _destino(config: dict, destino_id: int) -> dict:
        for servidor in config["servs"]:
            if servidor["id"] == destino_id:
                return servidor
        raise ValueError(f"Destino ID {destino_id} nao existe no gateway")

    def preparar_apply(self, snapshot: dict, destino_id: int,
                       alteracoes: dict) -> dict:
        """Gera body validado SEM efetuar POST. Nao aceita troca de tipo/enable."""
        payload = self._post_body(snapshot)
        servidor = self._destino(payload, destino_id)
        if servidor["servType"] != "semtech" or servidor["servEnabled"] is not True:
            raise ValueError("O destino escolhido deve ser Semtech e estar habilitado")
        if not alteracoes or not set(alteracoes) <= {"servAddr", "servPortUp", "servPortDown"}:
            raise ValueError("Somente endereco, uplink e downlink podem ser alterados")
        if "servAddr" in alteracoes:
            endereco = alteracoes["servAddr"]
            if not isinstance(endereco, str) or not endereco or len(endereco) > 128 or any(c.isspace() for c in endereco):
                raise ValueError("Server Address invalido")
            servidor["servAddr"] = endereco
        for chave in ("servPortUp", "servPortDown"):
            if chave in alteracoes:
                valor = alteracoes[chave]
                if isinstance(valor, bool) or not str(valor).isascii() or not str(valor).isdecimal():
                    raise ValueError(f"{chave} deve ser inteiro")
                valor = int(valor)
                if not 1 <= valor <= 65535:
                    raise ValueError(f"{chave}: porta invalida")
                servidor[chave] = valor
        return payload

    def aplicar_com_preflight(self, snapshot: dict, destino_id: int,
                             alteracoes: dict) -> dict:
        """POST no maximo UMA vez. Em duvida faz apenas GET; nunca reenvia."""
        if os.getenv("ENABLE_MILESIGHT_APPLY", "1") != "1":
            raise PermissionError("Apply Milesight bloqueado: ENABLE_MILESIGHT_APPLY=1")
        proposta = self.preparar_apply(snapshot, destino_id, alteracoes)
        atual = self.consultar_packet()  # Preflight: novo GET, antes de qualquer escrita.
        if self._post_body(atual) != self._post_body(snapshot):
            raise ValueError("Config Milesight mudou desde a proposta. Reinicie /configurar")
        if proposta == self._post_body(snapshot):
            return {"sucesso": True, "detalhe": "Nenhum parametro mudou. POST nao enviado."}

        falha_post = None
        try:
            status, resposta = self.chamar_api(
                "POST", "/api/packet-forwarder/network-servers",
                dados=proposta, token=self.token
            )
            if status != 200 or resposta.get("error") or resposta.get("code") not in (None, 0, 200):
                falha_post = f"HTTP {status} ou erro retornado pela API"
        except Exception as erro:
            # Inclusive timeout: nunca tentar POST novamente automaticamente.
            falha_post = f"{type(erro).__name__} durante POST"

        # Releitura: confirmar no gateway, nao apenas confiar no HTTP 200.
        ultimo_erro = None
        for tentativa in range(3):
            if tentativa:
                time.sleep(2)
            try:
                lido = self.consultar_packet()
                if self._post_body(lido) == proposta:
                    return {
                        "sucesso": True,
                        "detalhe": "Valores de TODOS os destinos confirmados por nova leitura. "
                                   "Verifique o fluxo de pacotes no ChirpStack."
                    }
            except Exception as erro:
                ultimo_erro = type(erro).__name__

        explicacao = f" ({falha_post})" if falha_post else ""
        if ultimo_erro:
            explicacao += f" (GET de verificacao: {ultimo_erro})"
        return {
            "sucesso": False,
            "detalhe": "STATUS INDETERMINADO" + explicacao + ". "
                       "Nao repita o Apply; consulte /estado e os logs."
        }
