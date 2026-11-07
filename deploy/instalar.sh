#!/bin/bash
# Instala (ou atualiza) o Backdraft em /opt/backdraft, num Ubuntu/Debian com systemd. Rode como root, de dentro da pasta
# do projeto copiada para o servidor:
#
#   sudo ./deploy/instalar.sh usuario1,usuario2
#
# O argumento (logins autorizados, ALLOWED_USERS) so e obrigatorio na primeira instalacao.
# Pode rodar de novo para atualizar: preserva o .env, o certificado TLS e os dados em /var/lib/backdraft.
#
# Variaveis opcionais:  SEM_LDAP=1  nao instala a biblioteca ldap3 (use so usuarios locais)
set -euo pipefail

DEST=/opt/backdraft
USUARIOS="${1:-}"
ORIGEM="$(cd "$(dirname "$0")/.." && pwd)"
ARQUIVOS=(backdraft.py dados.py enriquecimento.py historico.py avisos.py static)

[ "$(id -u)" = 0 ] || { echo "Rode com sudo."; exit 1; }
command -v python3 >/dev/null || { echo "python3 nao encontrado (precisa do 3.10 ou mais novo)."; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || { echo "Python 3.10 ou mais novo e necessario."; exit 1; }
command -v openssl >/dev/null || apt-get install -y openssl >/dev/null

id backdraft >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin backdraft

# --- programa (somente leitura para o usuario do servico)
install -d -m 755 "$DEST"
for a in "${ARQUIVOS[@]}"; do cp -r "$ORIGEM/$a" "$DEST/"; done
CAMINHOS=(); for a in "${ARQUIVOS[@]}"; do CAMINHOS+=("$DEST/$a"); done
chown -R root:root "${CAMINHOS[@]}"
chmod -R go-w "${CAMINHOS[@]}"

# --- biblioteca ldap3 (so para login por LDAP). Preferimos o pacote da distribuicao; sem ele, pip numa pasta propria
if [ "${SEM_LDAP:-0}" != "1" ] && ! python3 -c 'import ldap3' 2>/dev/null; then
  if command -v apt-get >/dev/null && apt-get install -y python3-ldap3 >/dev/null 2>&1; then
    echo "python3-ldap3 instalado pelo apt"
  elif python3 -m pip --version >/dev/null 2>&1        && { python3 -m pip install --quiet --disable-pip-version-check --target "$DEST/lib" -r "$ORIGEM/requirements.txt" 2>/dev/null             || python3 -m pip install --quiet --disable-pip-version-check --break-system-packages --target "$DEST/lib" -r "$ORIGEM/requirements.txt"; }; then
    chown -R root:root "$DEST/lib"; chmod -R go-w "$DEST/lib"
    find "$DEST/lib" -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
    echo "ldap3 instalado em $DEST/lib (pip)"
  else
    echo "AVISO: nao consegui instalar o ldap3 (apt/pip/internet). O login por LDAP nao vai funcionar; usuarios locais funcionam."
  fi
fi

# --- certificado TLS (autoassinado; troque pelo da sua organizacao quando houver: TLS_CERT/TLS_KEY no .env)
if [ ! -f "$DEST/tls/cert.pem" ]; then
  install -d -m 750 -o root -g backdraft "$DEST/tls"
  IPS="$(hostname -I | tr ' ' '\n' | grep -E '^[0-9]+\.' | sed 's/^/IP:/' | paste -sd, -)"
  openssl req -x509 -newkey rsa:4096 -nodes -days 825 -subj "/CN=backdraft" \
    -addext "subjectAltName=DNS:backdraft,${IPS}" \
    -out "$DEST/tls/cert.pem" -keyout "$DEST/tls/key.pem" >/dev/null 2>&1
  chown root:backdraft "$DEST/tls/cert.pem" "$DEST/tls/key.pem"
  chmod 644 "$DEST/tls/cert.pem"; chmod 640 "$DEST/tls/key.pem"
  echo "certificado TLS autoassinado criado (825 dias) em $DEST/tls"
fi

# --- .env
if [ ! -f "$DEST/.env" ]; then
  [ -n "$USUARIOS" ] || { echo "Primeira instalacao: informe os logins autorizados. Ex.: sudo ./deploy/instalar.sh ana.silva,bruno.souza"; exit 1; }
  umask 077
  sed -e "s|^BACKDRAFT_SECRET=.*|BACKDRAFT_SECRET=$(openssl rand -hex 32)|" -e "s|^ALLOWED_USERS=.*|ALLOWED_USERS=$USUARIOS|" \
      "$ORIGEM/.env.example" > "$DEST/.env"
  echo ".env criado em $DEST/.env"
else
  # acrescenta as chaves novas do .env.example que o .env ainda nao tem (sem tocar nas existentes)
  grep -E '^[A-Z_]+=' "$ORIGEM/.env.example" | while IFS= read -r linha; do
    chave="${linha%%=*}"
    grep -q "^${chave}=" "$DEST/.env" || { echo "$linha" >> "$DEST/.env"; echo ".env: chave nova adicionada: $chave"; }
  done
  # segredo: se o .env antigo tem o placeholder, gera um de verdade
  if grep -q '^BACKDRAFT_SECRET=gerado-pelo-instalador' "$DEST/.env"; then
    sed -i "s|^BACKDRAFT_SECRET=.*|BACKDRAFT_SECRET=$(openssl rand -hex 32)|" "$DEST/.env"
  fi
  # a lista de usuarios vem DEPOIS de acrescentar as chaves (senao a linha ainda nao existe e o sed nao faz nada)
  if [ -n "$USUARIOS" ]; then
    sed -i "s|^ALLOWED_USERS=.*|ALLOWED_USERS=$USUARIOS|" "$DEST/.env"
    echo "ALLOWED_USERS atualizado: $USUARIOS"
  fi
fi
chown root:backdraft "$DEST/.env"; chmod 640 "$DEST/.env"

# --- avisos do que ainda falta configurar
grep -q '^INDEXER_PASS=.\+' "$DEST/.env" || echo "FALTA: preencha INDEXER_PASS em $DEST/.env (senha do usuario somente leitura do indexador do Wazuh)"
[ -f "$DEST/root-ca.pem" ] || echo "FALTA: copie a CA do Wazuh para $DEST/root-ca.pem (a de /etc/wazuh-indexer/certs/root-ca.pem)"
if ! grep -q '^LOCAL_USERS=.\+' "$DEST/.env" && ! grep -q '^LDAP_HOST=.\+' "$DEST/.env" && ! grep -q '^BROKER_A_HOST=.\+' "$DEST/.env"; then
  echo "FALTA: configure o login em $DEST/.env (LOCAL_USERS com 'python3 $DEST/backdraft.py --gerar-hash usuario', ou LDAP_*)"
fi

install -m 644 "$ORIGEM/deploy/backdraft.service" /etc/systemd/system/backdraft.service
systemctl daemon-reload
systemctl enable backdraft >/dev/null 2>&1
systemctl restart backdraft
sleep 2

echo "--- verificacao"
systemctl is-active backdraft || { echo "O servico nao subiu: veja 'journalctl -u backdraft -n 30'"; exit 1; }
python3 - <<'PY'
import ssl, urllib.request
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
print("GET /saude ->", urllib.request.urlopen("https://127.0.0.1:8443/saude", context=c, timeout=5).read().decode())
PY
echo "Painel: https://$(hostname -I | awk '{print $1}'):8443"
