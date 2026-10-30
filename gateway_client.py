"""Cliente Browan / Pico Next. Login, leitura e Apply (apenas com autorizacao).

Nao executa nada ao importar. Credenciais sao lidas de variaveis de ambiente.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import ssl
import string
import time
import unicodedata
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode

import urllib3
from bs4 import BeautifulSoup

BASE = Path(__file__).resolve().parent
ALPHABET = string.ascii_letters + string.digits

# Chaves enviadas pela versao de firmware do HTML analisado.
NETWORK_FIELDS = {
    "xhr_network_ip": "id_network_ip",
    "xhr_up_port_val": "id_network_up_port",
    "xhr_down_port_val": "id_network_down_port",
    "xhr_keepAlive_val": "id_keep_time",
    "xhr_stat_val": "id_stat_time",
    "xhr_push_val": "id_push_timeout",
    "xhr_antenna_gain": "id_antenna_gain",
    "xhr_radio0_freq": "id_radio0_freq",
    "xhr_radio1_freq": "id_radio1_freq",
}
CHANNEL_FIELDS: dict[str, str] = {}
for number in range(8):
    prefix = "radio0" if number < 4 else "radio1"
    slot = number + 1
    CHANNEL_FIELDS[f"xhr_{prefix}_ch{slot}_status"] = f"id_{prefix}_ch{slot}_status"
    CHANNEL_FIELDS[f"xhr_{prefix}_ch{slot}_radio"] = f"id_ch_{number}_radioIF"
    CHANNEL_FIELDS[f"xhr_{prefix}_ch{slot}_if"] = f"id_{prefix}_ch{slot}_if"
CHANNEL_FIELDS.update({
    "xhr_ch_std_status": "id_ch_8_status",
    "xhr_ch_std_radioIF": "id_ch_8_radioIF",
    "xhr_ch_std_if": "id_radio1_ch9_if",
    "xhr_ch_std_bw": "id_ch_8_bw",
    "xhr_ch_std_sf": "id_ch_8_sf",
})
PARAM_TO_ELEMENT = {**NETWORK_FIELDS, **CHANNEL_FIELDS}
assert len(PARAM_TO_ELEMENT) == 38, f"Mapeamento incompleto: {len(PARAM_TO_ELEMENT)}"

EDITABLE = {
    "server": "xhr_network_ip",
    "uplink": "xhr_up_port_val",
    "downlink": "xhr_down_port_val",
    "ganho": "xhr_antenna_gain",
}


def normalizar(texto: str) -> str:
    texto = unicodedata.normalize("NFKD", texto.casefold().strip())
    return "".join(letra for letra in texto if not unicodedata.combining(letra))


def carregar_gateways() -> dict:
    with (BASE / "gateways.json").open(encoding="utf-8") as arquivo:
        return json.load(arquivo)


def buscar_gateway(termo: str, gateways: dict) -> tuple[str | None, dict | None]:
    chave = normalizar(termo)
    for gw_id, dados in gateways.items():
        if normalizar(gw_id) == chave:
            return gw_id, dados
    achados = [
        (gw_id, dados) for gw_id, dados in gateways.items()
        if normalizar(dados.get("local", "")) == chave
    ]
    if len(achados) > 1:
        raise ValueError("Esse local possui mais de um gateway. Informe o ID.")
    return achados[0] if achados else (None, None)


def _nonce() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(12))


def _field_value(element) -> str:
    if element.name == "select":
        selecionado = element.find("option", selected=True)
        if selecionado is None:
            selecionado = element.find("option")
        if selecionado is None:
            raise ValueError("Select sem opcoes na pagina")
        return str(selecionado.get("value", selecionado.text.strip()))
    return str(element.get("value", ""))


def interpretar_packet_html(html: str) -> dict:
    """Falha se algum dos 38 campos esperados estiver ausente."""
    soup = BeautifulSoup(html, "html.parser")
    eui_node = soup.find(id="id_gateway_id")
    if not eui_node:
        raise ValueError("Pagina nao contem Gateway ID; login/firmware devem ser verificados.")
    eui = re.sub(r"[^A-Fa-f0-9]", "", eui_node.get_text()).upper()
    if not re.fullmatch(r"[A-F0-9]{16}", eui):
        raise ValueError("EUI ausente ou invalido na pagina")
    valores = {}
    faltando = []
    for parametro, element_id in PARAM_TO_ELEMENT.items():
        element = soup.find(id=element_id)
        if element is None:
            faltando.append(element_id)
        else:
            valores[parametro] = _field_value(element)
    if faltando:
        raise ValueError("Firmware diferente: campos ausentes: " + ", ".join(faltando))
    return {"eui": eui, "params": valores}


def validar_valor(campo: str, texto: str, atual: str) -> str:
    valor = texto.strip()
    if valor == "-":
        return atual
    if campo == "server":
        if len(valor) > 128 or not valor or re.search(r"\s", valor):
            raise ValueError("Server Address invalido (1 a 128 caracteres, sem espacos)")
        # Apenas host ou IP, nunca URL com caminho, esquema ou query string.
        try:
            ipaddress.ip_address(valor)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9.-]+", valor):
                raise ValueError("Informe um dominio ou IP, sem http://, portas ou caminho")
            labels = valor.rstrip(".").split(".")
            if any(not p or len(p) > 63 or p.startswith("-") or p.endswith("-") for p in labels):
                raise ValueError("Hostname invalido")
    else:
        if not valor.isascii() or not valor.isdecimal():
            raise ValueError("Digite um numero inteiro, ou - para manter")
        numero = int(valor)
        maximo = 15 if campo == "ganho" else 65535
        minimo = 0 if campo == "ganho" else 1
        if not minimo <= numero <= maximo:
            raise ValueError(f"Permitido: {minimo} a {maximo}")
        valor = str(numero)
    return valor


class GatewayClient:
    def __init__(self, gateway: dict):
        self.gateway = gateway
        ip = ipaddress.ip_address(gateway["ip"])
        if not ip.is_private:
            raise ValueError("Acesso administrativo permitido apenas por IP privado")
        self.ip = str(ip)
        self.protocol = gateway["protocolo"].lower()
        self.headers = {}
        self.cookies: dict[str, str] = {}
        args = {
            "host": self.ip,
            "timeout": urllib3.Timeout(connect=5, read=12),
            "retries": False,
        }
        if self.protocol == "https":
            nome = gateway.get("tls_hostname")
            ca_nome = gateway.get("ca")
            c1 = gateway.get("fabricante") != "milesight"
            c2 = not nome or not ca_nome
            if c1 and c2:
                raise ValueError("O gateway esta invalido")
            ca = (BASE / ca_nome).resolve()
            directory = (BASE / "certificados").resolve()
            if not ca.is_relative_to(directory) or not ca.is_file():
                raise ValueError("CA nao cadastrada na pasta certificados")
            ctx = ssl.create_default_context(cafile=str(ca))
            if hasattr(ssl, "VERIFY_X509_STRICT"):
                ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
            args.update({
                "port": 443,
                "ssl_context": ctx,
                "server_hostname": nome,
                "assert_hostname": nome,
            })
            fingerprint = gateway.get("tls_fingerprint_sha256")
            if fingerprint:
                fp = re.sub(r"[^0-9A-Fa-f]", "", fingerprint)
                if len(fp) != 64:
                    raise ValueError("tls_fingerprint_sha256 invalido")
                args["assert_fingerprint"] = fp
            self.pool = urllib3.HTTPSConnectionPool(**args)
            self.headers["Host"] = nome
        elif self.protocol == "http":
            args["port"] = 80
            self.pool = urllib3.HTTPConnectionPool(**args)
        else:
            raise ValueError("Protocolo desconhecido")

    def close(self):
        self.pool.close()

    def _request(self, method: str, path: str, params: dict | None = None):
        headers = dict(self.headers)
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if method == "GET":
            if params is not None:
                query = dict(params)
                query["_"] = str(secrets.randbelow(10**12) / 10**12)
                path += "?" + urlencode(query)
            response = self.pool.request("GET", path, headers=headers, redirect=False)
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            response = self.pool.request(
                "POST", path, body=urlencode(params or {}).encode("ascii"),
                headers=headers, redirect=False,
            )
        for cookie in response.headers.getlist("Set-Cookie"):
            parsed = SimpleCookie()
            try:
                parsed.load(cookie)
                for name, morsel in parsed.items():
                    self.cookies[name] = morsel.value
            except Exception:
                pass
        return response

    def login(self, gateway_id: str):
        prefix = self.gateway.get("credentials_env_prefix", gateway_id).upper()
        if not re.fullmatch(r"[A-Z0-9_]+", prefix):
            raise ValueError("Prefixo de credenciais invalido")
        usuario = os.environ.get(f"{prefix}_USERNAME")
        senha = os.environ.get(f"{prefix}_PASSWORD")
        if not usuario or not senha:
            raise ValueError(f"Configure {prefix}_USERNAME e {prefix}_PASSWORD no servidor do bot")
        inicial = self._request("GET", "/cgi-bin/login.cgi")
        if inicial.status != 200:
            raise RuntimeError("Falha ao abrir a pagina de login")
        dados = {"username": usuario, "password": senha}
        if self.gateway.get("login") == "nonce":
            dados.update({"timestamp": str(int(time.time())), "nonce": _nonce()})
        elif self.gateway.get("login") != "simples":
            raise ValueError("Tipo de login desconhecido")
        response = self._request("POST", "/cgi-bin/login_check.cgi", dados)
        location = response.headers.get("Location", "")
        if response.status not in (302, 303) or not location.startswith("/cgi-bin/"):
            raise RuntimeError("Login nao confirmado: resposta/redirecionamento inesperado")
        pagina = self._request("GET", "/cgi-bin/lora_pktfwd.cgi")
        if pagina.status != 200:
            raise RuntimeError("Packet Forwarder indisponivel apos login")
        html = pagina.data.decode("utf-8", "replace")
        if "Authorization Required" in html:
            raise RuntimeError("Gateway solicitou login novamente")
        resultado = interpretar_packet_html(html)
        return resultado

    def consultar_packet(self) -> dict:
        response = self._request("GET", "/cgi-bin/lora_pktfwd.cgi")
        if response.status != 200:
            raise RuntimeError("Falha ao consultar Packet Forwarder")
        return interpretar_packet_html(response.data.decode("utf-8", "replace"))

    def aplicar_packet(self, params: dict) -> str:
        if set(params) != set(PARAM_TO_ELEMENT):
            raise ValueError("Payload incompleto; Apply cancelado")
        payload = dict(params)
        payload["xhr_timestamp"] = str(int(time.time()))
        payload["xhr_nonce"] = _nonce()
        response = self._request("GET", "/cgi-bin/lora_pktfwd_apply.cgi", payload)
        if response.status != 200:
            raise RuntimeError("Apply retornou HTTP diferente de 200")
        return response.data.decode("utf-8", "replace").strip()

    def aguardar_apply(self) -> str:
        for _ in range(8):
            time.sleep(1)
            response = self._request("GET", "/cgi-bin/lora_configuration_apply.cgi", {
                "xhr_json_check": "1",
                "xhr_timestamp": str(int(time.time())),
                "xhr_nonce": _nonce(),
            })
            if response.status != 200:
                raise RuntimeError("Falha ao consultar andamento do Apply")
            estado = response.data.decode("utf-8", "replace").strip()
            if estado != "checking":
                return estado
        raise TimeoutError("Aplicacao ainda em andamento; verificar manualmente")


def testar_conexao(gateway: dict) -> dict:
    client = GatewayClient(gateway)
    try:
        response = client._request("GET", "/cgi-bin/login.cgi")
        html = response.data.decode("utf-8", "replace")
        return {
            "ip": client.ip,
            "status": response.status,
            "pagina_login": "Authorization Required" in html,
            "tls": "HTTPS validado" if client.protocol == "https" else "HTTP (sem TLS)",
        }
    finally:
        client.close()


def consultar_autenticado(gw_id: str, gateway: dict) -> dict:
    client = GatewayClient(gateway)
    try:
        return client.login(gw_id)
    finally:
        client.close()


class ApplyStageTimeout(TimeoutError):
    """Timeout ao consultar/enviar, sem certeza de aplicacao."""

    def __init__(self, etapa: str):
        self.etapa = etapa
        super().__init__(f"Sem resposta durante: {etapa}. Nao repita o Apply sem reler o gateway.")


def _comparar_configuracao(leitura: dict, eui_esperado: str, esperado: dict) -> dict:
    """Verifica identidade e TODOS os 38 parametros, nao apenas os quatro editados."""
    if leitura["eui"] != eui_esperado:
        raise ValueError("EUI nao confere na releitura; resultado nao confiavel")
    if set(leitura["params"]) != set(esperado):
        raise ValueError("Releitura incompleta do Packet Forwarder")
    return {
        chave: (valor, leitura["params"].get(chave))
        for chave, valor in esperado.items()
        if str(leitura["params"].get(chave)) != str(valor)
    }


def confirmar_por_releitura(gw_id: str, gateway: dict, eui: str,
                            esperado: dict, causa: str) -> dict:
    """Somente GET/login em conexoes novas. NUNCA reenvia o Apply."""
    ultimo_erro = ""
    diferencas = None
    for tentativa, pausa in enumerate((1, 3, 5), start=1):
        time.sleep(pausa)
        print(f"[{gw_id}] Conferencia read-only {tentativa}/3 apos {causa}", flush=True)
        novo = None
        try:
            novo = GatewayClient(gateway)
            leitura = novo.login(gw_id)
            diferencas = _comparar_configuracao(leitura, eui, esperado)
            if not diferencas:
                return {
                    "sucesso": True,
                    "tipo": "confirmado_por_releitura",
                    "detalhe": "Valores confirmados por nova leitura do gateway, mesmo apos demora/timeout na resposta. O Apply nao foi repetido."
                }
            ultimo_erro = f"{len(diferencas)} campos ainda divergentes"
        except ValueError:
            # EUI errado ou erro estrutural: falha fechada, sem mensagem de sucesso.
            raise
        except (urllib3.exceptions.HTTPError, TimeoutError, OSError, RuntimeError) as exc:
            ultimo_erro = f"{type(exc).__name__} na leitura de confirmacao"
            print(f"[{gw_id}] {ultimo_erro}", flush=True)
        finally:
            if novo is not None:
                novo.close()
    return {
        "sucesso": False,
        "tipo": "indeterminado",
        "detalhe": (
            f"Resultado nao confirmado apos {causa}; {ultimo_erro or 'sem resposta conclusiva'}. "
            "Nao repita o Apply. Use /estado e confira os pacotes no ChirpStack."
        ),
        "campos": list(diferencas or {}),
    }


def aplicar_com_preflight(gw_id: str, gateway: dict, snapshot: dict, propostas: dict) -> dict:
    """Faz login NOVAMENTE, valida EUI e snapshot, aplica so 4 campos, rele e confere.

    Deve ser chamado APENAS apos permissao e confirmacao do usuario.
    """
    if os.environ.get("ENABLE_PACKET_APPLY") != "1":
        raise PermissionError("Apply desabilitado. Configure ENABLE_PACKET_APPLY=1 apos validar em bancada.")
    eui_esperado = re.sub(r"[^A-Fa-f0-9]", "", gateway.get("eui", "")).upper()
    if not re.fullmatch(r"[A-F0-9]{16}", eui_esperado):
        raise ValueError("Cadastre EUI conferido em gateways.json antes de habilitar Apply")
    if gateway["protocolo"].lower() == "http" and os.environ.get("ALLOW_HTTP_APPLY") != "1":
        raise PermissionError("Gateway HTTP: Apply bloqueado. Para LAN/VPN isolada, autorize explicitamente.")
    if gateway["protocolo"].lower() == "https" and not gateway.get("tls_fingerprint_sha256"):
        raise PermissionError("Cadastre fingerprint TLS individual confiavel antes do Apply HTTPS")
    client = GatewayClient(gateway)
    etapa = "login e verificacao anterior ao Apply"
    envio_iniciado = False
    try:
        print(f"[{gw_id}] 1/4: Login e verificacao de EUI/configuracao", flush=True)
        atual = client.login(gw_id)
        if atual["eui"] != eui_esperado or snapshot["eui"] != eui_esperado:
            raise ValueError("EUI nao confere; Apply bloqueado")
        if atual["params"] != snapshot["params"]:
            raise ValueError("Configuracao mudou desde a consulta; reinicie /configurar")
        para_enviar = atual["params"].copy()
        for key, value in propostas.items():
            if key not in EDITABLE.values():
                raise ValueError("Campo nao autorizado")
            para_enviar[key] = str(value)
        if para_enviar == atual["params"]:
            return {"sucesso": True, "detalhe": "Nenhuma mudanca necessaria"}

        etapa = "envio de lora_pktfwd_apply.cgi"
        print(f"[{gw_id}] 2/4: Enviando Apply (somente uma vez)", flush=True)
        envio_iniciado = True
        client.aplicar_packet(para_enviar)

        etapa = "consulta de andamento lora_configuration_apply.cgi"
        print(f"[{gw_id}] 3/4: Consultando andamento do Apply", flush=True)
        estado = client.aguardar_apply()

        etapa = "releitura de lora_pktfwd.cgi"
        print(f"[{gw_id}] 4/4: Relendo configuracao para confirmar", flush=True)
        time.sleep(1)
        depois = client.consultar_packet()
        diferencas = _comparar_configuracao(depois, eui_esperado, para_enviar)
        if diferencas:
            print(f"[{gw_id}] Configuracao ainda divergente; conferindo novamente", flush=True)
            return confirmar_por_releitura(gw_id, gateway, eui_esperado, para_enviar,
                                           "releitura com divergencias")
        return {"sucesso": True, "tipo": "confirmado_por_releitura",
                "detalhe": f"38 parametros confirmados por leitura do gateway. Estado: {estado or 'sem texto'}"}
    except (urllib3.exceptions.ReadTimeoutError, TimeoutError) as erro:
        print(f"[{gw_id}] {type(erro).__name__} na etapa: {etapa}", flush=True)
        if not envio_iniciado:
            raise ApplyStageTimeout(etapa) from erro
        # Timeout DEPOIS de iniciar envio: nunca mandar Apply novamente.
        return confirmar_por_releitura(gw_id, gateway, eui_esperado, para_enviar,
                                       f"timeout na etapa {etapa}")
    finally:
        client.close()
