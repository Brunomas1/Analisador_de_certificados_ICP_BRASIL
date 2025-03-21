# Analisador de Certificados ICP-Brasil - Modern GUI

Este projeto é uma aplicação Python para análise de certificados digitais ICP-Brasil. A aplicação lê certificados nos formatos DER e PEM, extrai informações importantes (como dados do proprietário, validade, número de série, entre outros) e as apresenta em uma interface moderna e organizada desenvolvida com [customtkinter](https://github.com/TomSchimansky/CustomTkinter).

## O que foi feito

- **Interface Moderna:**  
  Utilização do customtkinter para uma interface com abas, fontes maiores e layout limpo.
- **Leitura de Certificados:**  
  Suporte para arquivos DER e PEM, com extração dos campos ICP-Brasil (por exemplo, dados de pessoa física e jurídica) conforme os padrões exigidos.
- **Exibição de Dados:**  
  As informações extraídas são exibidas em duas abas:
  - **Resumo:** Mostra informações gerais (nome, emissor, número de série, validade, datas) e os dados do proprietário (apenas os campos com conteúdo real).
  - **Detalhes dos OIDs:** Exibe os valores brutos (em hexadecimal) e a decodificação de cada OID presente no certificado.
- **Exportação:**  
  Possibilidade de exportar as informações exibidas para um arquivo TXT.

## Requisitos

- Python 3.9 ou superior (testado com Python 3.12)
- [customtkinter](https://github.com/TomSchimansky/CustomTkinter)
- [cryptography](https://cryptography.io/)
- [asn1](https://pypi.org/project/asn1/)

*Os demais módulos utilizados (binascii, re, datetime, os, tkinter) fazem parte da biblioteca padrão do Python.*

## Instalação

1. **Clone o Repositório**
   
   No terminal, execute:
   ```bash
   git clone https://github.com/Brunomas1/Certanaliser.git
   cd Certanaliser
   ```

2. **Instale as Dependências**

   Utilize o pip para instalar as bibliotecas necessárias:
   ```bash
   pip install customtkinter cryptography asn1
   ```

## Execução

Para iniciar o Analisador de Certificados, execute:
```bash
python certanaliserv2.py
```

Ao abrir a aplicação:
1. Clique em "Selecionar Certificado (.cer, .pem)" para carregar um certificado.
2. Visualize as informações extraídas nas abas Resumo e Detalhes dos OIDs.
3. Utilize o botão "Exportar para TXT" para salvar os dados exibidos em um arquivo de texto.

## Contribuição

Este projeto é aberto a sugestões e melhorias. Se você encontrar algum problema ou tiver ideias para novas funcionalidades, sinta-se à vontade para abrir uma issue ou enviar um pull request.
