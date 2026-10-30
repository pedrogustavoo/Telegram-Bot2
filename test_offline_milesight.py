"""Testes offline: nao abre VPN nem envia requests a nenhum equipamento."""
import copy
import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

# Stub somente para permitir importar cliente num ambiente sem pycryptodome.
# Estes testes nao executam login/AES ou acesso TLS.
if 'Crypto' not in sys.modules:
    crypto = types.ModuleType('Crypto')
    cipher = types.ModuleType('Crypto.Cipher')
    aes = types.ModuleType('Crypto.Cipher.AES')
    aes.MODE_CBC = 2
    util = types.ModuleType('Crypto.Util')
    padding = types.ModuleType('Crypto.Util.Padding')
    padding.pad = lambda x, y: x
    sys.modules.update({'Crypto': crypto, 'Crypto.Cipher': cipher,
                        'Crypto.Cipher.AES': aes, 'Crypto.Util': util,
                        'Crypto.Util.Padding': padding})

path = Path(__file__).with_name('milesight_client.py')
spec = importlib.util.spec_from_file_location('milesight_client', path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def servidor(ident, addr, tipo='semtech', enabled=True):
    return {
        'id':ident, 'servEnabled':enabled, 'servAddr':addr, 'servType':tipo,
        'servPortUp':1700, 'servPortDown':1700, 'servMqttPort':0,
        'syncFreqPlan':False, 'connected':0, 'servGwKey':'', 'Region':'',
        'Band':'', 'username':'', 'password':'', 'CupsUri':'', 'TcUri':''
    }


def fixture():
    return {
        'gatewayEui':'24E124FFFEFD4242', 'gatewayId':'24E124FFFEFD4242',
        'dataRetransmission':False, 'status':1, 'pendingData':0,
        'servs':[servidor(2, 'old.example.com'),
                 servidor(0, 'localhost', 'ursalink', False)]
    }


def novo_cliente(snapshot):
    cliente = mod.MilesightClient.__new__(mod.MilesightClient)
    cliente.gw_id = 'GW004'
    cliente.gateway = {'eui': snapshot['gatewayEui']}
    cliente.token = 'token-falso-nao-usado'
    return cliente

class TestMilesightOffline(unittest.TestCase):
    def test_dry_run_preserva_destinos(self):
        snap=fixture(); cliente=novo_cliente(snap)
        body=cliente.preparar_apply(snap, 2, {'servAddr':'new.example.com','servPortUp':1710})
        self.assertEqual(len(body['servs']), 2)
        self.assertEqual(body['servs'][0]['servAddr'],'new.example.com')
        self.assertEqual(body['servs'][0]['servPortUp'],1710)
        self.assertEqual(body['servs'][0]['servPortDown'],1700)
        self.assertEqual(body['servs'][1]['servAddr'],'localhost')
        self.assertEqual(snap['servs'][0]['servAddr'],'old.example.com')
        self.assertNotIn('connected', body['servs'][0])
        self.assertNotIn('pendingData', body)

    def test_apply_desabilitado_nao_executa_post(self):
        snap=fixture(); cliente=novo_cliente(snap)
        cliente.chamar_api = lambda *a,**k: self.fail('Nao pode fazer request!')
        with patch.dict(os.environ, {'ENABLE_MILESIGHT_APPLY':'1'}):
            with self.assertRaises(PermissionError):
                cliente.aplicar_com_preflight(snap, 2, {'servAddr':'new.example.com'})

    def test_preflight_mudou_abort(self):
        snap=fixture(); cliente=novo_cliente(snap)
        novo=copy.deepcopy(snap); novo['servs'][1]['servAddr']='different.example.com'
        cliente.consultar_packet = lambda: copy.deepcopy(novo)
        cliente.chamar_api = lambda *a,**k: self.fail('Nao pode enviar POST!')
        with patch.dict(os.environ, {'ENABLE_MILESIGHT_APPLY':'1'}):
            with self.assertRaisesRegex(ValueError,'mudou'):
                cliente.aplicar_com_preflight(snap, 2, {'servAddr':'new.example.com'})

    def test_enviar_apenas_uma_vez_e_confirmar(self):
        snap=fixture(); cliente=novo_cliente(snap)
        body=cliente.preparar_apply(snap,2,{'servAddr':'new.example.com'})
        chamadas=[]
        leituras=[snap, {**copy.deepcopy(snap),'servs': copy.deepcopy(snap['servs'])}]
        leituras[1]['servs'][0]['servAddr']='new.example.com'
        cliente.consultar_packet=lambda: copy.deepcopy(leituras.pop(0))
        def fake_request(metodo,rota,dados=None,token=None):
            chamadas.append((metodo,rota,copy.deepcopy(dados)))
            self.assertEqual(dados,body)
            return (200,{})
        cliente.chamar_api=fake_request
        with patch.dict(os.environ, {'ENABLE_MILESIGHT_APPLY':'1'}):
            ret=cliente.aplicar_com_preflight(snap,2,{'servAddr':'new.example.com'})
        self.assertTrue(ret['sucesso'])
        self.assertEqual(len(chamadas),1)
        self.assertEqual(chamadas[0][0],'POST')

    def test_timeout_nao_repete_post(self):
        snap=fixture(); cliente=novo_cliente(snap)
        chamada=[]
        cliente.consultar_packet=lambda: copy.deepcopy(snap)
        def timeout(metodo, rota, dados=None, token=None):
            chamada.append(metodo)
            raise TimeoutError('simulado')
        cliente.chamar_api=timeout
        with patch.dict(os.environ, {'ENABLE_MILESIGHT_APPLY':'1'}), patch.object(mod.time, 'sleep', lambda _: None):
            ret=cliente.aplicar_com_preflight(snap,2,{'servAddr':'new.example.com'})
        self.assertEqual(chamada, ['POST'])
        self.assertFalse(ret['sucesso'])
        self.assertIn('Nao repita',ret['detalhe'])

    def test_sem_mudancas_nao_envia_post(self):
        snap=fixture(); cliente=novo_cliente(snap)
        cliente.consultar_packet=lambda: copy.deepcopy(snap)
        cliente.chamar_api=lambda *a,**k: self.fail('Nao pode fazer POST')
        with patch.dict(os.environ, {'ENABLE_MILESIGHT_APPLY':'1'}):
            ret=cliente.aplicar_com_preflight(snap,2,{'servAddr':'old.example.com'})
        self.assertTrue(ret['sucesso'])
        self.assertIn('POST nao enviado',ret['detalhe'])

    def test_tipo_nao_documentado_bloqueado(self):
        snap=fixture(); snap['servs'].append(servidor(4,'','basicstation',False))
        cliente=novo_cliente(snap)
        with self.assertRaisesRegex(ValueError,'nao documentado'):
            cliente.preparar_apply(snap,2,{'servAddr':'new.example.com'})

    def test_eui_divergente_bloqueado(self):
        snap=fixture(); cliente=novo_cliente(snap)
        snap['gatewayEui']='0000000000000000'
        with self.assertRaisesRegex(ValueError,'EUI'):
            cliente.preparar_apply(snap,2,{'servAddr':'new.example.com'})

if __name__=='__main__': unittest.main(verbosity=2)
