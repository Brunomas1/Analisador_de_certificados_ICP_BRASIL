# Analisador de Certificados ICP-Brasil

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

## CNPJ
![Descrição da Imagem](pj.png)
![Descrição da Imagem](pj_2.png)

## CPF

![Descrição da Imagem](pf.png)
![Descrição da Imagem](pf_2.png)



## Contribuição e Licença

Este é um projeto aberto e de livre uso, desenvolvido para fins educacionais. Está disponível para toda a comunidade e pode ser utilizado, modificado e aprimorado por qualquer pessoa.

Sugestões e melhorias são sempre bem-vindas. Se você encontrar algum problema ou tiver ideias para novas funcionalidades, sinta-se à vontade para abrir uma issue ou enviar um pull request.

Este projeto está licenciado sob a [Licença MIT](./LICENSE), o que significa que é fornecido **"no estado em que se encontra", sem garantias de qualquer tipo**.  
Criado por **Bruno Monteiro de Andrade Silva** ([brunomas1](https://github.com/brunomas1)).

