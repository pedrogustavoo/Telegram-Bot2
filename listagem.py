"""Listagem de gateways: independente do Telegram e das conexoes HTTP."""
from gateway_client import normalizar

def montar_paginas_lista(gateways: dict, filtro: str = "") -> list[str]:
    """Formatacao offline; mensagens abaixo do limite de 4096 do Telegram."""
    termo = normalizar(filtro)
    encontrados = sorted(
        (
            (gw_id, dados)
            for gw_id, dados in gateways.items()
            if not termo
            or termo in normalizar(gw_id)
            or termo in normalizar(str(dados.get("local", "")))
        ),
        key=lambda item: item[0].casefold(),
    )
    if not encontrados:
        return ["Nenhum gateway encontrado para esse filtro." if termo
                else "Nenhum gateway cadastrado no JSON."]

    titulo = f"GATEWAYS CADASTRADOS — {len(encontrados)}"
    if filtro.strip():
        titulo += " (filtro aplicado)"
    paginas, pagina = [], titulo + "\n"
    for gw_id, dados in encontrados:
        # Limpa quebras de linha para impedir listagens confusas.
        local = " ".join(str(dados.get("local") or "Local nao informado").split())[:120]
        endereco = str(dados.get("ip") or "IP nao informado")[:64]
        protocolo = str(dados.get("protocolo") or "?").upper()[:12]
        linha = f"\n{gw_id} — {local}\nIP: {endereco} | {protocolo}\n"
        if len(pagina) + len(linha) > 3500:
            paginas.append(pagina)
            pagina = titulo + " (continuacao)\n"
        pagina += linha
    paginas.append(pagina)
    return paginas


