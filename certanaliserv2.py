import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
import asn1
import binascii
import re

class CertificateAnalyzer:
    def __init__(self, master):
        self.master = master
        self.master.title("Analisador de Certificados ICP-Brasil")
        self.master.geometry("900x700")
        ctk.set_appearance_mode("System")  # Pode ser "Dark" ou "Light" também
        ctk.set_default_color_theme("blue")
        
        self.oid_info = {}
        self.setup_ui()
        
        # Mapeamento dos OIDs para os detalhes
        self.oid_mapping = {
            "2.16.76.1.3.1": "PF - Dados (Data Nasc/CPF/NIS/RG/Emissor)",
            "2.16.76.1.3.6": "PF - CEI",
            "2.16.76.1.3.5": "PF - Título de Eleitor",
            "2.16.76.1.3.9": "PF - RIC",
            "2.16.76.1.3.11": "PF - Cadastro Servidor/Militar",
            "2.16.76.1.3.4": "PJ - Dados do Responsável (Data Nasc/CPF/NIS/RG/Emissor)",
            "2.16.76.1.3.2": "PJ - Nome do Responsável",
            "2.16.76.1.3.3": "PJ - CNPJ",
            "2.16.76.1.3.7": "PJ - CEI",
            "2.16.76.1.4.2": "Identificação Profissional"
        }
    
    def setup_ui(self):
        self.main_frame = ctk.CTkFrame(self.master)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Frame superior com botões (sem ícones)
        self.top_frame = ctk.CTkFrame(self.main_frame)
        self.top_frame.pack(fill="x", pady=(0, 10))
        
        self.select_button = ctk.CTkButton(
            self.top_frame,
            text="Selecionar Certificado (.cer, .pem)",
            font=ctk.CTkFont(size=16),
            command=self.select_certificate
        )
        self.select_button.pack(side="left", padx=5)
        
        self.export_button = ctk.CTkButton(
            self.top_frame,
            text="Exportar para TXT",
            font=ctk.CTkFont(size=16),
            command=self.export_to_txt
        )
        self.export_button.pack(side="left", padx=5)
        
        # Tabview para separar Resumo e Detalhes
        self.tabview = ctk.CTkTabview(self.main_frame)
        self.tabview.pack(fill="both", expand=True)
        self.tabview.add("Resumo")
        self.tabview.add("Detalhes")
        
        # Caixa de texto para exibição dos dados com fonte moderna
        self.summary_text = ctk.CTkTextbox(self.tabview.tab("Resumo"), font=ctk.CTkFont(size=16))
        self.summary_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.details_text = ctk.CTkTextbox(self.tabview.tab("Detalhes"), font=ctk.CTkFont(size=16))
        self.details_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.status_label = ctk.CTkLabel(self.master, text="Aguardando seleção do certificado...", font=ctk.CTkFont(size=16))
        self.status_label.pack(fill="x", side="bottom", pady=10)
    
    def select_certificate(self):
        try:
            file_path = filedialog.askopenfilename(
                title="Selecione o arquivo de certificado",
                filetypes=[("Certificados", "*.cer *.pem"), ("Todos os arquivos", "*.*")]
            )
            if file_path:
                self.status_label.configure(text=f"Processando: {os.path.basename(file_path)}")
                self.master.update_idletasks()
                self.analyze_certificate(file_path)
                self.status_label.configure(text=f"Certificado analisado: {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao processar o certificado: {str(e)}")
            self.status_label.configure(text="Erro ao processar o certificado")
    
    def analyze_certificate(self, file_path):
        self.oid_info = {}
        with open(file_path, 'rb') as cert_file:
            cert_data = cert_file.read()
            if b"-----BEGIN CERTIFICATE-----" in cert_data:
                certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
            else:
                certificate = x509.load_der_x509_certificate(cert_data, default_backend())
            self.certificate = certificate
        
        # Informações gerais do certificado
        subject = certificate.subject
        subject_name = ""
        for attr in subject:
            if attr.oid == NameOID.COMMON_NAME:
                subject_name = attr.value
        
        issuer_name = certificate.issuer.rfc4514_string()
        serial_number = hex(certificate.serial_number)
        not_valid_before = certificate.not_valid_before
        not_valid_after = certificate.not_valid_after
        now = datetime.datetime.now()
        if now < not_valid_before:
            validity_status = "Ainda não é válido"
        elif now > not_valid_after:
            validity_status = "Expirado"
        else:
            validity_status = "Válido"
        
        # Processa a extensão "Subject Alternative Name" para extrair os OIDs ICP-Brasil
        for extension in certificate.extensions:
            if extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                san = extension.value
                for name in san:
                    if isinstance(name, x509.OtherName):
                        oid_str = name.type_id.dotted_string
                        raw_value = name.value
                        self.process_icp_oid(oid_str, raw_value)
        
        self.display_formatted_info(subject_name, issuer_name, serial_number,
                                    not_valid_before, not_valid_after, validity_status)
    
    def process_icp_oid(self, oid_str, raw_value):
        try:
            decoder = asn1.Decoder()
            decoder.start(raw_value)
            tag, value = decoder.read()
            hex_value = binascii.hexlify(value).decode('ascii')
            self.oid_info[oid_str] = {
                'raw': value,
                'hex': hex_value,
                'text': self.decode_oid_value(oid_str, value, hex_value)
            }
        except Exception as e:
            print(f"Erro ao processar OID {oid_str}: {str(e)}")
    
    def pad_hex_value(self, hex_value, expected_length):
        if len(hex_value) < expected_length:
            missing = expected_length - len(hex_value)
            pad = "30" * (missing // 2)
            return hex_value + pad
        return hex_value
    
    def decode_oid_value(self, oid_str, raw_value, hex_value):
        try:
            if oid_str in ["2.16.76.1.3.1", "2.16.76.1.3.4"]:
                hex_value = self.pad_hex_value(hex_value, 110)
            if oid_str == "2.16.76.1.3.1":
                data_nasc = bytes.fromhex(hex_value[0:16]).decode('ascii')
                cpf = bytes.fromhex(hex_value[16:38]).decode('ascii')
                nis = bytes.fromhex(hex_value[38:60]).decode('ascii')
                rg = bytes.fromhex(hex_value[60:90]).decode('ascii')
                orgao = bytes.fromhex(hex_value[90:110]).decode('ascii').strip()
                return {
                    'data_nasc': f"{data_nasc[0:2]}/{data_nasc[2:4]}/{data_nasc[4:8]}",
                    'cpf': cpf.strip(),
                    'nis': nis.strip(),
                    'rg': rg.strip(),
                    'emissor': orgao
                }
            elif oid_str == "2.16.76.1.3.6":
                cei = bytes.fromhex(hex_value[0:24]).decode('ascii').strip()
                return {'cei': cei}
            elif oid_str == "2.16.76.1.3.5":
                titulo = bytes.fromhex(hex_value[0:24]).decode('ascii').strip()
                zona = bytes.fromhex(hex_value[24:30]).decode('ascii').strip()
                secao = bytes.fromhex(hex_value[30:38]).decode('ascii').strip()
                municipio_uf = bytes.fromhex(hex_value[38:82]).decode('ascii').strip()
                return {
                    'titulo': titulo,
                    'zona': zona,
                    'secao': secao,
                    'municipio_uf': municipio_uf
                }
            elif oid_str == "2.16.76.1.3.9":
                ric = bytes.fromhex(hex_value[0:22]).decode('ascii').strip()
                return {'ric': ric}
            elif oid_str == "2.16.76.1.3.11":
                cadastro = bytes.fromhex(hex_value[0:20]).decode('ascii').strip()
                return {'cadastro_servidor': cadastro}
            elif oid_str.startswith("2.16.76.1.4.2"):
                prof = bytes.fromhex(hex_value).decode('ascii').strip()
                return {'profissional': prof}
            elif oid_str == "2.16.76.1.3.4":
                data_nasc = bytes.fromhex(hex_value[0:16]).decode('ascii')
                cpf = bytes.fromhex(hex_value[16:38]).decode('ascii')
                nis = bytes.fromhex(hex_value[38:60]).decode('ascii')
                rg = bytes.fromhex(hex_value[60:90]).decode('ascii')
                orgao = bytes.fromhex(hex_value[90:110]).decode('ascii').strip()
                return {
                    'data_nasc': f"{data_nasc[0:2]}/{data_nasc[2:4]}/{data_nasc[4:8]}",
                    'cpf': cpf.strip(),
                    'nis': nis.strip(),
                    'rg': rg.strip(),
                    'emissor': orgao
                }
            elif oid_str == "2.16.76.1.3.2":
                nome = bytes.fromhex(hex_value).decode('ascii').strip()
                return {'nome': nome}
            elif oid_str == "2.16.76.1.3.3":
                cnpj = bytes.fromhex(hex_value[0:28]).decode('ascii').strip()
                return {'cnpj': cnpj}
            elif oid_str == "2.16.76.1.3.7":
                cei = bytes.fromhex(hex_value[0:24]).decode('ascii').strip()
                return {'cei': cei}
            return {'value': hex_value}
        except Exception as e:
            print(f"Erro ao decodificar OID {oid_str}: {str(e)}")
            return {'value': hex_value, 'error': str(e)}
    
    def is_empty_value(self, value):
        if not value:
            return True
        if value == "0" or re.match(r'^0+$', value) or value == "00/00/0000":
            return True
        return False
    
    def display_formatted_info(self, subject_name, issuer_name, serial_number,
                               not_valid_before, not_valid_after, validity_status):
        lines = []
        lines.append(f"Nome: {subject_name}")
        lines.append(f"Emissor: {issuer_name}")
        lines.append(f"Número de Série: {serial_number}")
        lines.append(f"Validade: {validity_status}")
        lines.append(f"Válido de: {not_valid_before.strftime('%d/%m/%Y %H:%M:%S')}")
        lines.append(f"Válido até: {not_valid_after.strftime('%d/%m/%Y %H:%M:%S')}")
        lines.append("")
        # Se for PF
        if "2.16.76.1.3.1" in self.oid_info:
            pf = self.oid_info.get("2.16.76.1.3.1", {}).get("text", {})
            lines.append("Dados do Proprietário (PF):")
            if not self.is_empty_value(pf.get('data_nasc', '')):
                lines.append(f"  Data de nascimento: {pf.get('data_nasc', '')}")
            if not self.is_empty_value(pf.get('cpf', '')):
                lines.append(f"  CPF: {pf.get('cpf', '')}")
            if not self.is_empty_value(pf.get('nis', '')):
                lines.append(f"  NIS: {pf.get('nis', '')}")
            if not self.is_empty_value(pf.get('rg', '')):
                lines.append(f"  RG: {pf.get('rg', '')}")
            if not self.is_empty_value(pf.get('emissor', '')):
                lines.append(f"  Emissor: {pf.get('emissor', '')}")
        # Se for PJ – exibe apenas os campos que possuem conteúdo real, com CNPJ logo após o CPF
        elif "2.16.76.1.3.4" in self.oid_info:
            pj_dados = self.oid_info.get("2.16.76.1.3.4", {}).get("text", {})
            responsavel = self.oid_info.get("2.16.76.1.3.2", {}).get("text", {})
            cnpj_info = self.oid_info.get("2.16.76.1.3.3", {}).get("text", {})
            cei_info = self.oid_info.get("2.16.76.1.3.7", {}).get("text", {})
            lines.append("Dados do Proprietário (PJ):")
            nome_resp = responsavel.get('nome', '')
            if not self.is_empty_value(nome_resp):
                lines.append(f"  Nome do Responsável: {nome_resp}")
            data_nasc = pj_dados.get('data_nasc', '')
            if not self.is_empty_value(data_nasc):
                lines.append(f"  Data de nascimento: {data_nasc}")
            cpf = pj_dados.get('cpf', '')
            if not self.is_empty_value(cpf):
                lines.append(f"  CPF: {cpf}")
            cnpj = cnpj_info.get('cnpj', '')
            if not self.is_empty_value(cnpj):
                lines.append(f"  CNPJ: {cnpj}")
            if not self.is_empty_value(pj_dados.get('nis', '')):
                lines.append(f"  NIS: {pj_dados.get('nis', '')}")
            if not self.is_empty_value(pj_dados.get('rg', '')):
                lines.append(f"  RG: {pj_dados.get('rg', '')}")
            if not self.is_empty_value(pj_dados.get('emissor', '')):
                lines.append(f"  Emissor: {pj_dados.get('emissor', '')}")
            if not self.is_empty_value(cei_info.get('cei', '')):
                lines.append(f"  CEI da PJ: {cei_info.get('cei', '')}")
        else:
            lines.append("Tipo de certificado não identificado (PF/PJ)")
        
        summary = "\n".join(lines)
        self.summary_text.delete("1.0", "end")
        self.summary_text.insert("1.0", summary)
        
        details_lines = ["Detalhes dos OIDs encontrados:\n"]
        for oid, data in self.oid_info.items():
            oid_name = self.oid_mapping.get(oid, "OID Desconhecido")
            details_lines.append(f"OID: {oid} - {oid_name}")
            details_lines.append(f"Valor Hex: {data.get('hex', '')}")
            details_lines.append(f"Valor Decodificado: {data.get('text', '')}")
            details_lines.append("-" * 50)
        details = "\n".join(details_lines)
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", details)
    
    def export_to_txt(self):
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Arquivos de Texto", "*.txt"), ("Todos os arquivos", "*.*")],
                title="Salvar informações como"
            )
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("Resumo:\n")
                    f.write(self.summary_text.get("1.0", "end"))
                    f.write("\n" + "=" * 50 + "\n")
                    f.write("Detalhes dos OIDs:\n")
                    f.write(self.details_text.get("1.0", "end"))
                self.status_label.configure(text=f"Exportado: {os.path.basename(file_path)}")
                messagebox.showinfo("Exportação concluída", f"As informações foram exportadas para:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Erro na exportação", f"Falha ao exportar: {str(e)}")
            self.status_label.configure(text="Erro na exportação")

def main():
    root = ctk.CTk()
    app = CertificateAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()
