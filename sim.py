import json


def buscar_leitura():
    with open ("planilha.json", "r") as file:
        salve = json.load(file)
    buscar =input("Digite o rádio para buscar leitura:")
    for transmissor in salve:
        if transmissor == buscar:
            return "Aqui está seus dados"
        else:
            return "Esse transmissor não existe"






