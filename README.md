# 🔴 RedTux 1.2

**Atualização RedTux 1.2** é uma ferramenta ofensiva de linha de comando para pentesters e entusiastas de segurança ofensiva. Ela integra diversas funções úteis para reconhecimento, exploração e pós-exploração em ambientes de rede e sistemas.

---

## ⚙️ Requisitos

- Python 3.7+
- Dependências opcionais:
  - `paramiko` (para SSH): `pip install paramiko`
  - `impacket` (para SMB): `pip install impacket`
  - `pwntools` (para exploits binários): `pip install pwntools`
  - `sublist3r`, `curl`, `msfconsole` (devem estar no PATH do sistema)

---

## 🧪 Instalação

```bash
git clone https://github.com/seuusuario/redtux.git
cd redtux
pip install -r requirements.txt  # se desejar automatizar dependências
```

---

## 🚀 Uso

```bash
python redtux.py [OPÇÃO] [ARGUMENTOS]
```

### 🔍 Reconhecimento

| Comando | Descrição |
|--------|-----------|
| `--scan <IP>` | Scan de portas padrão (21, 22, 80, 443) usando multithreading |
| `--recon <DOMÍNIO>` | Reconhecimento de subdomínios com Sublist3r |

### 🎯 Exploração

| Comando | Descrição |
|--------|-----------|
| `--payload <STRING>` | Ofusca string (ex: payload) em Base64 |
| `--deobf <STRING>` | Desofusca string em Base64 |
| `--msf <PAYLOAD> <RHOST> <LHOST> <LPORT>` | Executa exploit via Metasploit RPC |
| `--exploit <BIN>` | (Incompleto) Executa binário com suporte ao pwntools (requer instalação manual) |

### 🛠 Pós-Exploração

| Comando | Descrição |
|--------|-----------|
| `--ssh <IP> <USER> <PASS> <CMD>` | Executa comando remoto via SSH |
| `--smb <IP> <USER> <PASS>` | Enumeração SMB (requer Impacket) |
| `--exfil <ARQUIVO> <URL>` | Exfiltra arquivo via `curl` para servidor remoto |
| `--clear-logs` | Apaga arquivos `.log` do diretório `/var/log/` |

---

## ⚠️ Aviso Legal

Este software é fornecido apenas para fins educacionais e deve ser usado **exclusivamente em ambientes autorizados**. O uso indevido pode violar leis locais e internacionais. O autor não se responsabiliza por qualquer dano causado pelo uso inadequado desta ferramenta.

---

## 📄 Licença

MIT License
