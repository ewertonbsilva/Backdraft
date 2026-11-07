# Autenticação do Backdraft

O Backdraft **não guarda senhas em texto**. Quem entra digita usuário e senha, e o painel confere de um de dois jeitos:

1. **Usuário local**: a senha é conferida contra um hash PBKDF2-SHA256 guardado no `.env`.
2. **LDAP/LDAPS**: o painel tenta um *bind* no servidor LDAP com o usuário e a senha digitados.

Os dois podem **coexistir**. Em todos os casos, **só entra quem também estiver em `ALLOWED_USERS`**: autenticar não basta, é preciso estar autorizado.

## Fluxo de um login

1. O navegador envia usuário e senha por HTTPS para `/login` (com checagem de origem contra CSRF).
2. O painel confere se o IP ou o usuário está bloqueado (5 falhas em 5 minutos).
3. Se o usuário está em `LOCAL_USERS`, confere o hash. **Uma senha errada aqui não "cai" para o LDAP.**
4. Senão, e se houver servidor LDAP configurado, **escolhe o servidor pela rede de quem entra** (abaixo) e faz o *bind*.
5. Aceito, e presente em `ALLOWED_USERS`: cria o **cookie de sessão** assinado (HMAC), `HttpOnly`, `SameSite=Strict` e `Secure`.
6. O log (`journalctl -u backdraft`) registra o resultado, e, quando há LDAP, qual servidor atendeu. Nunca a senha.

## Usuários locais

```bash
python3 /opt/backdraft/backdraft.py --gerar-hash ana.silva
```

Pede a senha duas vezes (sem eco, mínimo de 10 caracteres) e imprime `usuario|hash`. Coloque no `.env`:

```ini
LOCAL_USERS=ana.silva|pbkdf2_sha256:600000:SAL:HASH,bruno.souza|pbkdf2_sha256:600000:SAL:HASH
ALLOWED_USERS=ana.silva,bruno.souza
```

Para trocar uma senha, gere outro hash e substitua a entrada. Para remover alguém, apague a entrada **e** o login de `ALLOWED_USERS`. O formato do hash é `pbkdf2_sha256:iterações:sal:hash` (base64 *url-safe*, sem vírgula nem `|`, então não quebra o `.env`).

## LDAP / LDAPS

Servidor único:

```ini
LDAP_HOST=ldap.exemplo.com
LDAP_PORT=636
LDAP_BASE=ou=people,dc=exemplo,dc=com
LDAP_USER_DN=uid={usuario},{base}
LDAP_CA=/opt/backdraft/ldap-ca.pem
LDAP_NAME=ldap.exemplo.com
```

| Variável | O que é |
|---|---|
| `LDAP_BASE` | ramo onde ficam os usuários |
| `LDAP_USER_DN` | molde do DN do usuário. `{usuario}` já vem **escapado**; `{base}` é o `LDAP_BASE` |
| `LDAP_CA` | certificado do servidor (PEM), **fixado**: a conexão só vale se bater |
| `LDAP_NAME` | nome **DNS** que consta no certificado (SAN). Vazio = não confere o nome |

Só LDAPS (TLS direto, normalmente porta 636). **Não há StartTLS** e não há modo sem criptografia: a senha não pode trafegar em claro.

### Pegar o certificado do servidor

```bash
openssl s_client -connect ldap.exemplo.com:636 -showcerts </dev/null 2>/dev/null \
  | openssl x509 > /opt/backdraft/ldap-ca.pem
openssl x509 -in /opt/backdraft/ldap-ca.pem -noout -subject -ext subjectAltName
```

A segunda linha mostra o nome DNS para colocar em `LDAP_NAME`. Se o seu servidor usa uma CA própria, use o certificado **da CA** (ou da cadeia) no lugar do certificado do servidor.

### Por que `LDAP_NAME`

O `ldap3` no Python 3.12 **não compara IP no SAN do certificado, só nomes DNS**. Se o certificado só tem o IP, a validação falha mesmo com tudo certo. Informe um nome DNS que esteja no certificado.

### Active Directory

O painel faz *bind* com o **DN** montado por `LDAP_USER_DN`. No AD o DN do usuário costuma ter a forma `CN=Nome Completo,OU=...`, que **não dá para derivar do login**. Opções:

- se o seu AD aceita *bind* por **UPN**, use `LDAP_USER_DN={usuario}@exemplo.local` (o `{base}` não é usado);
- ou use o *bind* por `sAMAccountName` com o prefixo do domínio: `LDAP_USER_DN=EXEMPLO\{usuario}`.

Os dois formatos são aceitos pelo AD no campo de usuário do *bind*, mas **teste no seu ambiente** antes de contar com isso: o painel só valida o resultado do *bind*.

### Dois servidores, escolhidos pela rede

Para duas localidades com dois servidores LDAP que se replicam:

```ini
BROKER_A_NOME=site-a
BROKER_A_HOST=ldap-a.exemplo.com
BROKER_A_PORT=636
BROKER_A_CA=/opt/backdraft/ldap-ca-a.pem
BROKER_A_NAME=ldap-a.exemplo.com
BROKER_A_REDES=192.0.2.0/24,198.51.100.0/24

BROKER_B_NOME=site-b
BROKER_B_HOST=ldap-b.exemplo.com
BROKER_B_PORT=636
BROKER_B_CA=/opt/backdraft/ldap-ca-b.pem
BROKER_B_NAME=ldap-b.exemplo.com
BROKER_B_REDES=203.0.113.0/24
```

Quando `BROKER_*_HOST` está preenchido, o `LDAP_HOST` é ignorado (`LDAP_BASE` e `LDAP_USER_DN` valem para os dois).

A regra, para o IP de quem está entrando:

| Situação | O que o painel faz |
|---|---|
| O IP está em `BROKER_x_REDES` de um servidor | tenta **esse primeiro** |
| O IP não está em nenhuma lista | ordem configurada (A, depois B) |
| O primeiro servidor **não responde** (rede, firewall, certificado) | tenta o outro |
| O servidor responde **"senha inválida"** | **definitivo**: não tenta o outro |

Atrás de proxy, o IP do cliente vem de `X-Real-IP`, e só se o proxy estiver em `TRUSTED_PROXIES`.

> **Libere o IP do Backdraft nos dois servidores.** Se só um estiver liberado, o login funciona, mas quem deveria ir ao outro espera o tempo limite de 5 s antes de cair no reserva.

## "Lembrar de mim"

| | Sem marcar | Marcado |
|---|---|---|
| Cookie | de sessão (some ao fechar o navegador) | persistente (`Max-Age`) |
| Inatividade tolerada | `IDLE_SECONDS` (15 min) | `REMEMBER_IDLE_SECONDS` (24 h) |
| Duração máxima | `MAX_LIFE_SECONDS` (8 h) | `REMEMBER_DAYS` (7 dias) |

A inatividade se renova a cada ação do usuário; o limite de dias **não** (o instante do login não muda). A sessão "lembrada" leva um campo `m=1` dentro do cookie assinado: o usuário não consegue ligá-lo por conta própria, porque a assinatura deixaria de bater. **Sair** apaga o cookie. Para derrubar **todas** as sessões, troque `BACKDRAFT_SECRET`. `REMEMBER_DAYS=0` remove a caixa da tela.

## Proteções no login

- Login validado antes de qualquer consulta: só `[A-Za-z0-9._-]`, até 64 caracteres. Isso, mais o escape do DN, impede injeção de DN/filtro.
- Senha vazia nunca vai ao servidor LDAP (o *bind* com senha vazia é anônimo e "funciona").
- Certificado fixado e nome conferido; nada de `CERT_NONE`.
- **5 falhas em 5 minutos** bloqueiam por IP **e** por usuário (HTTP 429). Cada falha também espera ~0,7 s.
- A mensagem não diz se foi o usuário ou a senha que errou.
- "Servidor indisponível" (HTTP 503) é diferente de "senha inválida" (401): quem está sem acesso por causa de rede não deve achar que digitou errado.

## Problemas comuns

| Mensagem ou sintoma | Causa | O que fazer |
|---|---|---|
| "Usuário ou senha inválidos" | senha errada, usuário inexistente ou DN montado errado | confira `LDAP_USER_DN` e `LDAP_BASE`; teste um *bind* com `ldapwhoami` |
| "Seu usuário não tem permissão" | autenticou, mas não está em `ALLOWED_USERS` | adicione o login |
| "Servidor de autenticação indisponível" | nenhum servidor respondeu | veja o log: `ldap … indisponivel: <motivo>` |
| `CERTIFICATE_VERIFY_FAILED` | `LDAP_CA` não é o certificado desse servidor | refaça o `openssl s_client` |
| `hostname doesn't match` | `LDAP_NAME` não consta no certificado | use um nome da lista `subjectAltName` |
| Conexão recusada / expira | firewall do servidor LDAP ou porta errada | libere o IP do Backdraft; confira a porta |
| Login lento (~5 s) | servidor preferido da rede barrado, painel usa o reserva | libere o IP nos **dois** servidores |
| Entra com qualquer senha | **senha vazia** chegando ao LDAP (bind anônimo) | não acontece no Backdraft; se for código seu, recuse senha vazia antes |

Testando o *bind* à mão:

```bash
LDAPTLS_CACERT=/opt/backdraft/ldap-ca.pem ldapwhoami -H ldaps://ldap.exemplo.com:636 \
  -D "uid=ana.silva,ou=people,dc=exemplo,dc=com" -W
```
