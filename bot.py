"""Bot Telegram: configuracao guiada do Packet Forwarder Browan.

Uma unica conversa por usuario; credenciais NUNCA passam pelo Telegram.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import time
from pathlib import Path
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env", override=True)

from milesight_client import MilesightClient


def fabricante_de(gateway: dict) -> str:
    fabricante = str(gateway.get("fabricante", "browan")).strip().lower()
    if fabricante not in ("browan", "milesight"):
        raise ValueError(f"Fabricante nao suportado: {fabricante}")
    return fabricante



from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application, CallbackQueryHandler, CommandHandler, ContextTypes,
    ConversationHandler, MessageHandler, filters,
)

from listagem import montar_paginas_lista

from gateway_client import (
    EDITABLE, ApplyStageTimeout, aplicar_com_preflight, buscar_gateway, carregar_gateways,
    consultar_autenticado, testar_conexao, validar_valor,
)

TOKEN = os.environ.get("BOT_TOKEN", "")
ID_AUTORIZADO = int(os.environ.get("TELEGRAM_USER_ID", "0"))
SERVER, UPLINK, DOWNLINK, GANHO, CONFIRMAR = range(5)
CAMPOS = ["server", "uplink", "downlink", "ganho"]
DESCRICOES = {
    "server": "Server Address (IP publico ou dominio)",
    "uplink": "Server Uplink Port (1–65535)",
    "downlink": "Server Downlink Port (1–65535)",
    "ganho": "Antenna Gain (0–15)",
}
VALIDADE = 300  # 5 minutos, evita aplicar uma proposta antiga


async def permitido(update: Update) -> bool:
    u, chat = update.effective_user, update.effective_chat
    if not u or not chat or chat.type != "private" or u.id != ID_AUTORIZADO:
        if update.effective_message:
            await update.effective_message.reply_text("Comando restrito ao administrador.")
        elif update.callback_query:
            await update.callback_query.answer("Nao autorizado", show_alert=True)
        return False
    return True


async def meu_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_message and update.effective_user:
        await update.effective_message.reply_text(f"Seu ID Telegram: {update.effective_user.id}")


def selecionar(args):
    termo = " ".join(args).strip()
    if not termo:
        raise ValueError("Informe ID ou local. Ex.: /configurar GW008")
    gw_id, dados = buscar_gateway(termo, carregar_gateways())
    if dados is None:
        raise ValueError("Gateway nao encontrado")
    return gw_id, dados


async def buscar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await permitido(update):
        return
    try:
        gw_id, d = selecionar(context.args)
        await update.effective_message.reply_text(
            f"ID: {gw_id}\nLocal: {d.get('local', 'Nao informado')}\n"
            f"IP VPN: {d['ip']}\nProtocolo: {d.get('protocolo', 'https' if fabricante_de(d) == 'milesight' else 'nao informado')}\n"
            "Somente consulta ao cadastro."
        )
    except (ValueError, KeyError) as e:
        await update.effective_message.reply_text(str(e))


async def listar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await permitido(update):
        return
    try:
        cadastro = carregar_gateways()
        filtro = " ".join(context.args).strip()
        for pagina in montar_paginas_lista(cadastro, filtro):
            await update.effective_message.reply_text(pagina)
    except (OSError, ValueError, TypeError) as e:
        print("Falha /listar:", type(e).__name__)
        await update.effective_message.reply_text(
            "Nao consegui ler gateways.json. Confira se ele existe e se o JSON esta valido."
        )


async def testar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await permitido(update):
        return
    try:
        gw_id, d = selecionar(context.args)
        if fabricante_de(d) == "milesight":
            # Verifica TLS fixado, autentica e consulta sem alterar o equipamento.
            config = await asyncio.to_thread(MilesightClient(gw_id, d).consultar_packet)
            await update.effective_message.reply_text(
                f"{gw_id}: API Milesight acessivel (HTTPS + login + consulta OK).\n"
                "Somente leitura. Nenhum Apply enviado."
            )
            return
        r = await asyncio.to_thread(testar_conexao, d)
        await update.effective_message.reply_text(
            f"{gw_id}: HTTP {r['status']}\n{r['tls']}\n"
            f"Pagina de login: {'sim' if r['pagina_login'] else 'nao confirmada'}"
        )
    except Exception as e:
        print("Falha /testar:", type(e).__name__)
        await update.effective_message.reply_text(f"Falha ao testar: {type(e).__name__}.")


async def estado(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Leitura autenticada do Packet Forwarder; nao chama Apply."""
    if not await permitido(update):
        return
    try:
        gw_id, dados = selecionar(context.args)
        if fabricante_de(dados) == "milesight":
            config = await asyncio.to_thread(MilesightClient(gw_id, dados).consultar_packet)
            eui = str(config.get("gatewayEui") or "").upper()
            esperado = str(dados.get("eui") or "").upper()
            if esperado and (not eui or eui != esperado):
                await update.effective_message.reply_text(
                    f"ALERTA: EUI do {gw_id} nao confirmado!\n"
                    f"Esperado: {esperado}\nObtido: {eui or '(ausente)'}\n"
                    "Nao aplique nenhuma configuracao."
                )
                return
            linhas = [f"ESTADO ATUAL — {gw_id} (Milesight UG65)",
                      f"EUI: {eui or '(nao retornado)'}"]
            servidores = config.get("servs", [])
            if not isinstance(servidores, list):
                raise ValueError("Resposta Milesight: servs nao e uma lista")
            for i, servidor in enumerate(servidores, start=1):
                if not isinstance(servidor, dict):
                    raise ValueError("Resposta Milesight: servidor invalido")
                linhas.extend([
                    f"Servidor {i}: {servidor.get('servAddr', '(nao informado)')}",
                    f"Uplink: {servidor.get('servPortUp', '(nao informado)')}",
                    f"Downlink: {servidor.get('servPortDown', '(nao informado)')}",
                ])
            if not servidores:
                linhas.append("Nenhum destino encontrado em servs; confira a estrutura da resposta.")
            linhas.append("Somente consulta. Nenhum Apply enviado.")
            await update.effective_message.reply_text("\n".join(linhas))
            return
        leitura = await asyncio.to_thread(consultar_autenticado, gw_id, dados)
        cadastrado = str(dados.get("eui", "")).upper()
        eui = leitura["eui"]
        if cadastrado and cadastrado != eui:
            await update.effective_message.reply_text(
                f"ALERTA: EUI nao confere no {gw_id}!\nEsperado: {cadastrado}\nObtido: {eui}\n"
                "Nao aplique nenhuma configuracao."
            )
            return
        atual = leitura["params"]
        linhas = [
            f"ESTADO ATUAL — {gw_id}",
            f"EUI: {eui}",
            f"Server Address: {atual['xhr_network_ip']}",
            f"Uplink: {atual['xhr_up_port_val']}",
            f"Downlink: {atual['xhr_down_port_val']}",
            f"Ganho antena: {atual['xhr_antenna_gain']}",
        ]
        ultimo = context.user_data.get("ultimo_apply")
        if ultimo and ultimo["gw_id"] == gw_id:
            linhas.extend(["", "COMPARACAO COM ULTIMA PROPOSTA:"])
            iguais = True
            for etiqueta, key in EDITABLE.items():
                esperado = ultimo["campos"].get(key)
                if esperado is None:
                    continue
                encontrado = atual.get(key)
                bate = str(esperado) == str(encontrado)
                iguais &= bate
                linhas.append(f"{etiqueta}: {encontrado} | esperado {esperado} | {'OK' if bate else 'DIFERENTE'}")
            linhas.append("CONFIRMADO: os quatro valores da ultima proposta aparecem no gateway. Verifique trafego UDP no ChirpStack." if iguais
                          else "Divergencias encontradas. Nao repita Apply antes de investigar.")
        linhas.append("Consulta de leitura apenas. Nenhum Apply enviado.")
        await update.effective_message.reply_text("\n".join(linhas))
    except Exception as e:
        print("Falha /estado:", type(e).__name__, flush=True)
        await update.effective_message.reply_text(
            f"Nao foi possivel ler o estado atual ({type(e).__name__}). "
            "Verifique pelo navegador e pelos logs do servidor. Nenhum Apply enviado."
        )




M_EDITABLE = {"server": "servAddr", "uplink": "servPortUp", "downlink": "servPortDown"}
M_CAMPOS = ["server", "uplink", "downlink"]


async def iniciar_milesight(update, context, gw_id, dados, destino_solicitado=None):
    cliente = MilesightClient(gw_id, dados)
    config = await asyncio.to_thread(cliente.consultar_packet)
    # Impede Apply no gateway errado; teste a identidade antes mesmo do formulario.
    esperado = str(dados.get("eui", "")).upper()
    obtido = str(config.get("gatewayEui", "")).upper()
    if not esperado or obtido != esperado:
        raise ValueError("EUI Milesight ausente ou diferente do cadastrado")
    destinos = [
        s for s in config.get("servs", [])
        if s.get("servType") == "semtech" and s.get("servEnabled") is True
    ]
    if destino_solicitado is None:
        if len(destinos) != 1:
            ids = ", ".join(str(s.get("id")) for s in destinos) or "nenhum"
            await update.effective_message.reply_text(
                f"{gw_id}: encontrei {len(destinos)} destinos Semtech ativos (IDs: {ids}).\n"
                f"Escolha explicitamente: /configurar {gw_id} ID_DO_DESTINO"
            )
            return ConversationHandler.END
        destino = destinos[0]
    else:
        destino = next((s for s in destinos if s.get("id") == destino_solicitado), None)
        if destino is None:
            raise ValueError("Destino ID informado nao esta ativo ou nao e Semtech")

    # Valida estrutura do body para avisar problemas ANTES do fluxo interativo.
    await asyncio.to_thread(cliente.preparar_apply, config, destino["id"], {"servAddr": destino["servAddr"]})
    context.user_data["proposta"] = {
        "tipo": "milesight", "gw_id": gw_id, "gateway": dados, "snapshot": config,
        "destino_id": destino["id"], "campos": {}, "criado_em": time.monotonic()
    }
    await update.effective_message.reply_text(
        f"Milesight {gw_id} | EUI: {obtido} | Destino ID: {destino['id']}\n"
        f"Server: {destino['servAddr']}\n"
        f"Uplink: {destino['servPortUp']}\nDownlink: {destino['servPortDown']}\n\n"
        "A API consultada NAO altera ganho de antena.\n"
        "Novo Server Address? Digite o dominio/IP ou '-' para manter.\n"
        "Use /cancelar para sair. Nenhum Apply foi enviado."
    )
    return SERVER


async def receber_milesight(update, context, p):
    posicao = len(p["campos"])
    if posicao >= len(M_CAMPOS):
        return CONFIRMAR
    destino = MilesightClient._destino(p["snapshot"], p["destino_id"])
    campo = M_CAMPOS[posicao]
    chave = M_EDITABLE[campo]
    atual = destino[chave]
    try:
        valor = validar_valor(campo, update.effective_message.text, str(atual))
        if campo != "server":
            valor = int(valor)
    except ValueError as erro:
        await update.effective_message.reply_text(f"{erro}\nTente novamente ou '-' para manter.")
        return posicao
    p["campos"][chave] = valor
    if len(p["campos"]) < len(M_CAMPOS):
        prox = M_CAMPOS[len(p["campos"])]
        await update.effective_message.reply_text(
            f"{DESCRICOES[prox]}? Atual: {destino[M_EDITABLE[prox]]}\n"
            "Digite o novo valor ou '-' para manter."
        )
        return len(p["campos"])
    # Preview so inclui campos alterados, preserva o restante do payload.
    texto = [
        f"CONFIRMACAO MILESIGHT — {p['gw_id']}",
        f"EUI: {p['snapshot']['gatewayEui']}",
        f"Destino ID: {p['destino_id']}",
        ""
    ]
    alterou = False
    for etiqueta, chave in M_EDITABLE.items():
        antigo, novo = destino[chave], p["campos"][chave]
        alterou |= antigo != novo
        texto.append(f"{etiqueta}: {antigo} -> {novo}")
    texto.extend([
        "", "Outros destinos serao preservados.",
        "ATENCAO: a troca pode interromper trafego LoRa; precisa de janela autorizada.",
        "Nenhuma mudanca foi enviada ate a confirmacao."
    ])
    token = secrets.token_hex(8)
    p["token"] = token
    p["confirmar_em"] = time.monotonic()
    await update.effective_message.reply_text(
        "\n".join(texto),
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("Confirmar Apply", callback_data=f"apply:{token}"),
            InlineKeyboardButton("Cancelar", callback_data=f"cancel:{token}"),
        ]])
    )
    return CONFIRMAR


async def iniciar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await permitido(update):
        return ConversationHandler.END
    try:
        destino_solicitado = None
        args = context.args
        if len(args) == 2 and args[0].upper().startswith("GW") and args[1].isdecimal():
            destino_solicitado = int(args[1])
            args = args[:1]
        gw_id, dados = selecionar(args)
        if fabricante_de(dados) == "milesight":
            return await iniciar_milesight(update, context, gw_id, dados, destino_solicitado)
        if destino_solicitado is not None:
            raise ValueError("ID de destino so e aceito no Milesight")
        # Este login vem de variaveis de ambiente do processo, nunca da conversa.
        snapshot = await asyncio.to_thread(consultar_autenticado, gw_id, dados)
        eui_cadastrado = dados.get("eui")
        context.user_data["proposta"] = {
            "gw_id": gw_id, "gateway": dados, "snapshot": snapshot,
            "campos": {}, "criado_em": time.monotonic(),
        }
        atual = snapshot["params"]
        await update.effective_message.reply_text(
            f"Login OK, Packet Forwarder lido!\n"
            f"Gateway: {gw_id} | EUI: {snapshot['eui']}\n"
            f"EUI no cadastro: {eui_cadastrado or '(nao cadastrado)'}\n\n"
            f"Atual:\n"
            f"Server: {atual['xhr_network_ip']}\n"
            f"Uplink: {atual['xhr_up_port_val']}\n"
            f"Downlink: {atual['xhr_down_port_val']}\n"
            f"Ganho: {atual['xhr_antenna_gain']}\n\n"
            f"Novo {DESCRICOES['server']}? Digite o valor ou '-' para manter.\n"
            "Use /cancelar para sair."
        )
        return SERVER
    except Exception as e:
        print("Falha /configurar:", type(e).__name__, str(e), flush=True)
        await update.effective_message.reply_text(
            f"Nao foi possivel iniciar a configuracao ({type(e).__name__}). "
            "Veja o motivo detalhado no terminal do bot. Nenhum Apply enviado."
        )
        return ConversationHandler.END


async def receber(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await permitido(update):
        return ConversationHandler.END
    proposta = context.user_data.get("proposta")
    if not proposta:
        await update.effective_message.reply_text("Sessao perdida. Inicie /configurar novamente.")
        return ConversationHandler.END
    if proposta.get("tipo") == "milesight":
        return await receber_milesight(update, context, proposta)
    campos = proposta["campos"]
    posicao = len(campos)
    if posicao >= len(CAMPOS):
        return CONFIRMAR
    key = CAMPOS[posicao]
    parametro = EDITABLE[key]
    atual = proposta["snapshot"]["params"][parametro]
    try:
        valor = validar_valor(key, update.effective_message.text, atual)
    except ValueError as e:
        await update.effective_message.reply_text(
            f"{e}\nTente novamente ou use '-' para manter {atual}."
        )
        return posicao
    campos[parametro] = valor
    if len(campos) < len(CAMPOS):
        proximo = CAMPOS[len(campos)]
        existente = proposta["snapshot"]["params"][EDITABLE[proximo]]
        await update.effective_message.reply_text(
            f"OK. {DESCRICOES[proximo]}?\nAtual: {existente}\n"
            "Digite novo valor ou '-' para manter."
        )
        return len(campos)
    changes = [
        f"{label}: {proposta['snapshot']['params'][p]} -> {campos[p]}"
        for label, p in EDITABLE.items()
        if proposta["snapshot"]["params"][p] != campos[p]
    ]
    token = secrets.token_hex(8)
    proposta["token"] = token
    proposta["confirmar_em"] = time.monotonic()
    await update.effective_message.reply_text(
        f"CONFIRMACAO — {proposta['gw_id']}\n"
        f"EUI: {proposta['snapshot']['eui']}\n\n"
        + ("\n".join(changes) if changes else "Nenhuma alteracao solicitada")
        + "\n\nRadios e canais serao preservados. "
        "O Apply pode interromper a recepcao LoRa. "
        "Confirme somente com janela autorizada e plano de recuperacao.",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("Confirmar Apply", callback_data=f"apply:{token}"),
            InlineKeyboardButton("Cancelar", callback_data=f"cancel:{token}"),
        ]])
    )
    return CONFIRMAR


async def confirmar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await permitido(update):
        return ConversationHandler.END
    query = update.callback_query
    p = context.user_data.get("proposta")
    if not p or query.data.split(":", 1)[-1] != p.get("token"):
        await query.answer("Solicitacao expirada", show_alert=True)
        return ConversationHandler.END
    if time.monotonic() - p.get("confirmar_em", 0) > VALIDADE:
        await query.answer("Prazo expirou. Inicie novamente.", show_alert=True)
        context.user_data.pop("proposta", None)
        return ConversationHandler.END
    await query.answer()
    await query.edit_message_reply_markup(reply_markup=None)
    if query.data.startswith("cancel:"):
        context.user_data.pop("proposta", None)
        await query.message.reply_text("Configuracao cancelada, sem alteracoes.")
        return ConversationHandler.END
    if p.get("tipo") == "milesight":
        try:
            await query.message.reply_text(
                "Milesight: preflight, POST unico e verificacao por GET em andamento. "
                "Se houver timeout, NAO repita Apply."
            )
            cliente = MilesightClient(p["gw_id"], p["gateway"])
            resultado = await asyncio.to_thread(
                cliente.aplicar_com_preflight,
                p["snapshot"], p["destino_id"], p["campos"]
            )
            titulo = "APPLY MILESIGHT CONFIRMADO" if resultado["sucesso"] else "MILESIGHT: STATUS INDETERMINADO"
            await query.message.reply_text(f"{titulo} — {p['gw_id']}\n{resultado['detalhe']}")
        except (ValueError, PermissionError) as erro:
            await query.message.reply_text(f"Milesight: Apply bloqueado ANTES do POST: {erro}")
        except Exception as erro:
            print("Milesight Apply falhou:", type(erro).__name__, flush=True)
            await query.message.reply_text(
                "Milesight: falha ou status indeterminado. Nao repita Apply; use /estado."
            )
        finally:
            context.user_data.pop("proposta", None)
        return ConversationHandler.END
    if fabricante_de(p["gateway"]) != "browan":
        await query.message.reply_text("Apply bloqueado: fabricante nao suportado neste fluxo.")
        context.user_data.pop("proposta", None)
        return ConversationHandler.END
    # Guarda apenas a proposta (na memoria) para comparar em /estado,
    # mesmo se o Apply terminar em estado indeterminado.
    context.user_data["ultimo_apply"] = {
        "gw_id": p["gw_id"], "campos": dict(p["campos"]),
    }
    try:
        await query.message.reply_text(
            f"Processando {p['gw_id']}: conferindo, aplicando uma unica vez e verificando a leitura. "
            "Se o gateway demorar, aguarde; nao envie o comando novamente."
        )
        resultado = await asyncio.to_thread(
            aplicar_com_preflight, p["gw_id"], p["gateway"], p["snapshot"], p["campos"]
        )
        if resultado["sucesso"]:
            titulo = "CONFIGURACAO CONFIRMADA COM SUCESSO"
        else:
            titulo = "STATUS INDETERMINADO — NAO REPITA O APPLY"
        await query.message.reply_text(
            f"{titulo} — {p['gw_id']}\n{resultado['detalhe']}\n"
            "A confirmacao indica que os parametros estao gravados; confira tambem "
            "a chegada de pacotes UDP no ChirpStack."
        )
    except ApplyStageTimeout as e:
        print("Apply nao confirmado no gateway", p["gw_id"], "etapa:", e.etapa, flush=True)
        await query.message.reply_text(
            f"STATUS INDETERMINADO — {p['gw_id']}\n"
            f"Timeout na etapa: {e.etapa}\n"
            "O gateway pode ter aplicado a mudanca. NAO repita o Apply.\n"
            f"Use /estado {p['gw_id']} para reler os valores e confira a chegada de pacotes no ChirpStack."
        )
    except PermissionError as e:
        print("Apply bloqueado por regra de seguranca:", str(e))
        await query.message.reply_text(
            "Apply NAO executado: " + str(e) + "\n"
            "Revise as condicoes de seguranca antes de tentar novamente. "
            "Nao habilite Apply em producao sem autorizacao e recuperacao local."
        )
    except ValueError as e:
        print("Apply rejeitado por validacao:", str(e))
        await query.message.reply_text(
            "Apply NAO confirmado (validacao): " + str(e)
        )
    except Exception as e:
        print("Falha durante Apply:", type(e).__name__)
        await query.message.reply_text(
            f"Apply nao confirmado ({type(e).__name__}). "
            "Confira os logs e o estado atual antes de tentar novamente."
        )
    finally:
        context.user_data.pop("proposta", None)
    return ConversationHandler.END


async def cancelar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop("proposta", None)
    if update.effective_message:
        await update.effective_message.reply_text("Cancelado. Nenhum Apply enviado por este comando.")
    return ConversationHandler.END


def main():
    if not TOKEN:
        raise SystemExit("Defina BOT_TOKEN")
    if not ID_AUTORIZADO:
        print("Atencao: apenas /meuid funcionara ate cadastrar TELEGRAM_USER_ID")
    app = Application.builder().token(TOKEN).build()
    conversa = ConversationHandler(
        entry_points=[CommandHandler("configurar", iniciar)],
        states={
            SERVER: [MessageHandler(filters.TEXT & ~filters.COMMAND, receber)],
            UPLINK: [MessageHandler(filters.TEXT & ~filters.COMMAND, receber)],
            DOWNLINK: [MessageHandler(filters.TEXT & ~filters.COMMAND, receber)],
            GANHO: [MessageHandler(filters.TEXT & ~filters.COMMAND, receber)],
            CONFIRMAR: [CallbackQueryHandler(confirmar, pattern=r"^(apply|cancel):[0-9a-f]{16}$")],
        },
        fallbacks=[CommandHandler("cancelar", cancelar)],
        allow_reentry=True,
        name="configuracao_forwarder",
        persistent=False,
    )
    app.add_handler(conversa)
    app.add_handler(CommandHandler("meuid", meu_id))
    app.add_handler(CommandHandler("buscar", buscar))
    app.add_handler(CommandHandler("listar", listar))
    app.add_handler(CommandHandler("testar", testar))
    app.add_handler(CommandHandler("estado", estado))
    print("Bot iniciado: /listar, /buscar, /testar, /estado, /configurar, /cancelar")
    app.run_polling()


if __name__ == "__main__":
    main()
