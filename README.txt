GatewayManager - Configuracao guiada do Packet Forwarder (Browan)

ATENCAO: o Apply envia todos os 38 parametros, embora altere somente 4.
No padrao, o script funciona em modo pre-visualizacao e NAO aplica mudancas.

1. Instale o Python e as dependencias:
   python -m pip install -r requirements.txt

2. Copie seu gateways.json para esta pasta, sem sobrescrever por exemplo.
   Os exemplos GW006/GW008 sao ficticios, revise nomes/IPs/EUI.
   No gateway HTTPS, use ca e tls_hostname, e opcionalmente o pin:
   "tls_fingerprint_sha256": "64_HEXADECIMAIS_DO_CERTIFICADO_HTTPS"
   Coloque webCrt.crt dentro da pasta certificados/GW008/.
   O pin deve ser coletado de maneira autenticada, idealmente no provisionamento LAN.
   O hostname wildcard e a CA sozinhos nao confirmam a identidade individual.
   Para testes read-only /configurar, nao e preciso o pin, mas para Apply SIM.

3. No PowerShell, na pasta do projeto:
   $env:BOT_TOKEN="SEU_TOKEN"
   $env:TELEGRAM_USER_ID="SEU_ID_NUMERICO"
   $env:GW008_USERNAME="admin"
   $env:GW008_PASSWORD="SENHA_DO_GATEWAY"
   (Para GW006: GW006_USERNAME / GW006_PASSWORD)

   Atenção: variaveis de ambiente sao uma solucao didatica. Em producao,
   use armazenamento de segredos e uma conta de servico com privilegios minimos.
   Nunca coloque senhas nas mensagens do Telegram nem no gateways.json.

4. Rode:
   python bot.py

5. Em conversa PRIVADA com o bot:
   /listar                  (mostra todos os gateways, ID, local, IP e protocolo)
   /listar boulevard        (filtra por ID ou local, sem diferenciar acentos)
   /buscar GW008
   /testar GW008
   /configurar GW008

   O bot faz login, le o Packet Forwarder e pergunta sequencialmente:
   - Server Address (IP publico do destino ChirpStack ou dominio)
   - Server Uplink Port
   - Server Downlink Port
   - Antenna Gain
   Digite '-' para manter o valor atual em qualquer campo.
   Em seguida veja o resumo e confirme/cancele pelos botoes.

6. PARA HABILITAR O APPLY (APENAS COM AUTORIZACAO E ACESSO DE RECUPERACAO):
   - Cadastre o EUI exato do gateway em gateways.json:
       "eui": "16_HEXADECIMAIS"
   - Para HTTPS, cadastre o fingerprint TLS individual confiavel:
       "tls_fingerprint_sha256": "64_HEXADECIMAIS"
   - Confira o alvo, servidor UDP e alcance do port forwarding.
   - Libere em terminal PowerShell apenas para a janela de teste:
       $env:ENABLE_PACKET_APPLY="1"
   - Para HTTP em LAN isolada/VPN confiavel, se realmente autorizado:
       $env:ALLOW_HTTP_APPLY="1"
   - Reinicie o bot. Use /configurar ... e confirme o resumo.
   - O sistema refaz login e consulta se o EUI e os 38 campos nao mudaram;
     em seguida envia um GET /cgi-bin/lora_pktfwd_apply.cgi com 38 parametros,
     timestamp, nonce e _; consulta lora_configuration_apply.cgi, rele campos.

7. O firmware HTML estudado apresenta radio/canais 'disabled', mas ainda os envia
   no Apply. A ferramenta os preserva tal qual o HTML; nenhuma mudanca em radio
   ou canais e preparada. Um firmware diferente pode exigir novo mapeamento.

8. HTTP na LAN pode expor credenciais. Prefira HTTPS validado e acesso via VPN.
   Certificado da CA deve vir de uma fonte autenticada. O codigo relaxa apenas
   VERIFY_X509_STRICT por compatibilidade com certificados antigos da Browan.
   O teste HTTPS so exige CA e hostname, mas Apply exige fingerprint individual.

9. O servidor precisa estar na VPN e o IP publico do ChirpStack deve estar
   recebendo UDP 1700 (ou outra porta escolhida) no Gateway Bridge.
   O painel WEB do ChirpStack NAO deve ser exposto publicamente.

10. SOBRE "SEM PERMISSAO":
    - "Comando restrito ao administrador": TELEGRAM_USER_ID nao coincide com /meuid
      ou o chat nao e privado. Ajuste a variavel e reinicie.
    - "Apply NAO executado": o bot agora informa qual trava impediu o envio.
      ENABLE_PACKET_APPLY so deve ser habilitado para testes autorizados com
      plano de recuperacao, depois de cadastrar EUI; HTTPS tambem exige
      tls_fingerprint_sha256 confiavel; HTTP exige ALLOW_HTTP_APPLY.
    - No modo somente leitura, /listar, /buscar e /testar funcionam sem Apply.
