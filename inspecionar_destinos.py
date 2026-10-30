"""Leitura de dados nao secretos para identificar se o Apply e suportado."""
import json
import sys
from pathlib import Path
from dotenv import load_dotenv
from milesight_client import MilesightClient

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / '.env', override=True)

def main():
    gw_id = (sys.argv[1] if len(sys.argv) > 1 else 'GW004').upper()
    gateways = json.loads((BASE / 'gateways.json').read_text(encoding='utf-8'))
    config = MilesightClient(gw_id, gateways[gw_id]).consultar_packet()
    print('gatewayEui:', config.get('gatewayEui'))
    print('gatewayId:', config.get('gatewayId'))
    print('dataRetransmission:', config.get('dataRetransmission'))
    for s in config.get('servs', []):
        print('id:', s.get('id'), '| tipo:', s.get('servType'), '| ativo:', s.get('servEnabled'))
        print('  address:', s.get('servAddr'), '| up:', s.get('servPortUp'), '| down:', s.get('servPortDown'))
        print('  nomes dos campos:', ', '.join(sorted(s.keys())))
    print('Nenhum JWT, senha ou corpo integral foram exibidos.')

if __name__ == '__main__':
    main()
