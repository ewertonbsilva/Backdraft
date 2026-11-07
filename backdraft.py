#!/usr/bin/env python3
"""Backdraft: painel de vulnerabilidades do Wazuh, SOMENTE LEITURA, com o "como corrigir".

Servidor HTTP minimo (stdlib) + ldap3 (vendorizado em ./lib). Le o indice wazuh-states-vulnerabilities-* do indexador do
Wazuh com um usuario so de leitura e escuta em HTTPS na rede interna. Login por LDAP(S) e/ou usuarios locais,
restrito a ALLOWED_USERS. Nao executa nada nos servidores: so mostra e gera texto para copiar.
Configuracao 100% por variaveis de ambiente (ver .env.example). Python 3.10+.
"""
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import ssl
import sys
import threading
import time
from datetime import datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "lib"))
import dados as D  # noqa: E402
from avisos import Avisos, texto_novas, texto_semanal  # noqa: E402
from enriquecimento import Enriquecimento  # noqa: E402
from historico import Historico  # noqa: E402

STATIC = os.path.join(BASE, "static")
USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
NOME_SERV_RE = re.compile(r"^[\w .()-]{1,100}$")
COOKIE = "backdraft_sessao"


def env(nome, padrao=""):
    return os.environ.get(nome, padrao).rstrip("\r")  # .env com fim de linha do Windows nao pode quebrar valores


class Config:
    def __init__(self):
        self.bind = env("BACKDRAFT_BIND", "0.0.0.0")
        self.port = int(env("BACKDRAFT_PORT", "8443"))
        self.secret = env("BACKDRAFT_SECRET").encode()
        self.indexer_url = env("INDEXER_URL", "https://127.0.0.1:9200")
        self.indexer_user = env("INDEXER_USER", "backdraft-read")
        self.indexer_pass = env("INDEXER_PASS")
        self.indexer_ca = env("INDEXER_CA", os.path.join(BASE, "root-ca.pem"))
        self.cache = int(env("CACHE_SECONDS", "300"))
        # Servidor LDAP unico (LDAP_*) ou ate dois (BROKER_A_* / BROKER_B_*, abaixo). Tudo vazio = so usuarios locais.
        self.ldap_host = env("LDAP_HOST")
        self.ldap_port = int(env("LDAP_PORT", "636"))
        self.ldap_base = env("LDAP_BASE")  # ex.: ou=people,dc=exemplo,dc=com
        self.ldap_dn = env("LDAP_USER_DN", "uid={usuario},{base}")  # como montar o DN do usuario (AD: {usuario}@dominio nao serve: use o DN)
        self.ldap_ca = env("LDAP_CA", os.path.join(BASE, "ldap-ca.pem"))
        # Nome DNS no certificado (SAN). O ldap3 no Python 3.12 nao compara IP no SAN, so nomes DNS. Vazio = nao confere o nome.
        self.ldap_name = env("LDAP_NAME")
        # Identificacao da organizacao (aparece no titulo e no relatorio) e fuso
        self.org = env("ORG_NOME")
        self.titulo = (self.org + " · Backdraft") if self.org else "Backdraft"
        self.tz_nome = D.TZ_NOME
        # Usuarios locais (sem LDAP): LOCAL_USERS=usuario|hash,outro|hash  (gere o hash com: python3 backdraft.py --gerar-hash usuario)
        self.usuarios_locais = {}
        for par in env("LOCAL_USERS").split(","):
            if "|" in par:
                u, h = par.strip().split("|", 1)
                if u.strip():
                    self.usuarios_locais[u.strip().lower()] = h.strip()
        # Servidores LDAP. BROKER_A_* / BROKER_B_*: o painel tenta primeiro o que atende a rede (BROKER_x_REDES) de quem esta
        # entrando e, se ele nao responder, o outro. Sem BROKER_*, usa o LDAP_* acima (um so).
        self.brokers = []
        for k in ("A", "B"):
            h = env("BROKER_%s_HOST" % k)
            if h:
                self.brokers.append({
                    "nome": env("BROKER_%s_NOME" % k, "LDAP " + k), "host": h,
                    "port": int(env("BROKER_%s_PORT" % k, "636")),
                    "ca": env("BROKER_%s_CA" % k, os.path.join(BASE, "ldap-ca-%s.pem" % k.lower())),
                    "name": env("BROKER_%s_NAME" % k),
                    "redes": [ipaddress.ip_network(x.strip(), strict=False) for x in env("BROKER_%s_REDES" % k).split(",") if x.strip()]})
        if not self.brokers and self.ldap_host:
            self.brokers.append({"nome": "ldap", "host": self.ldap_host, "port": self.ldap_port, "ca": self.ldap_ca,
                                 "name": self.ldap_name, "redes": []})
        self.allowed = {u.strip().lower() for u in env("ALLOWED_USERS", "").split(",") if u.strip()}
        self.idle = int(env("IDLE_SECONDS", "900"))
        self.max_life = int(env("MAX_LIFE_SECONDS", "28800"))
        # "Lembrar de mim": sessao mais longa, em cookie persistente (0 dias = sem a opcao na tela de login)
        # Quantas maquinas deveriam ter agente (ex.: computadores do AD). So para o relatorio mostrar a cobertura; 0 = nao sabe
        self.esperadas = int(env("MAQUINAS_ESPERADAS", "0") or 0)
        self.lembrar_dias = int(env("REMEMBER_DAYS", "7"))
        self.lembrar_max = self.lembrar_dias * 86400
        self.lembrar_idle = int(env("REMEMBER_IDLE_SECONDS", "86400"))
        self.cookie_secure = env("COOKIE_SECURE", "1") == "1"
        self.tls_cert, self.tls_key = env("TLS_CERT"), env("TLS_KEY")
        self.proxies = [ipaddress.ip_network(x.strip()) for x in env("TRUSTED_PROXIES", "").split(",") if x.strip()]
        self.allowed_nets = [ipaddress.ip_network(x.strip(), strict=False) for x in env("ALLOWED_IPS").split(",") if x.strip()]
        self.estado = env("BACKDRAFT_ESTADO")  # pasta gravavel (historico, listas KEV/EPSS, avisos); vazio = so em memoria
        self.url_publica = env("AVISO_URL")
        b = env("BACKDRAFT_BASE").strip("/")
        self.base = "/" + b if b else ""


# ---------------------------------------------------------------- sessao (cookie assinado, sem estado)
def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def criar_token(secret, uid, nome, emitido, ultimo, lembrar=False):
    d = {"u": uid, "n": nome, "i": emitido, "l": ultimo}
    if lembrar:
        d["m"] = 1
    corpo = _b64(json.dumps(d, separators=(",", ":")).encode())
    return corpo + "." + _b64(hmac.new(secret, corpo.encode(), hashlib.sha256).digest())


def ler_token(secret, token, idle, max_life, agora=None, idle_m=None, max_m=None):
    """Dict da sessao ou None (assinatura invalida, inativa demais ou velha demais).
    Sessao com "lembrar de mim" (m=1) usa os limites idle_m/max_m, quando informados."""
    agora = time.time() if agora is None else agora
    try:
        corpo, assinatura = token.split(".", 1)
        if not hmac.compare_digest(_b64(hmac.new(secret, corpo.encode(), hashlib.sha256).digest()), assinatura):
            return None
        d = json.loads(_unb64(corpo))
        if d.get("m") and idle_m and max_m:
            idle, max_life = idle_m, max_m
        if agora - d["l"] > idle or agora - d["i"] > max_life:
            return None
        return d
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def ip_permitido(redes, ip):
    if not redes:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in r for r in redes)


class Limitador:
    """Anti forca bruta: N falhas na janela bloqueiam, por IP e por usuario."""

    def __init__(self, tentativas=5, janela=300):
        self.n, self.janela, self._f, self._l = tentativas, janela, {}, threading.Lock()

    def _podar(self, chave, agora):
        self._f[chave] = [t for t in self._f.get(chave, []) if agora - t < self.janela]
        return self._f[chave]

    def bloqueado(self, *chaves, agora=None):
        agora = time.time() if agora is None else agora
        with self._l:
            return any(len(self._podar(c, agora)) >= self.n for c in chaves)

    def falha(self, *chaves, agora=None):
        agora = time.time() if agora is None else agora
        with self._l:
            for c in chaves:
                self._podar(c, agora).append(agora)

    def ok(self, *chaves):
        with self._l:
            for c in chaves:
                self._f.pop(c, None)


# ---------------------------------------------------------------- usuarios locais (PBKDF2-SHA256, sem LDAP)
def gerar_hash_senha(senha, iteracoes=600000):
    """'pbkdf2_sha256:iteracoes:sal:hash' (base64 url-safe). A senha em si nunca e guardada."""
    sal = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), sal, iteracoes)
    return "pbkdf2_sha256:%d:%s:%s" % (iteracoes, _b64(sal), _b64(h))


def verificar_senha(senha, guardado):
    try:
        alg, it, sal, h = guardado.split(":")
        if alg != "pbkdf2_sha256":
            return False
        calc = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), _unb64(sal), int(it))
        return hmac.compare_digest(calc, _unb64(h))
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------- autenticacao no LDAP (LDAPS, bind direto)
def escapar_rdn(valor):
    return re.sub(r'([,+"\\<>;=#])', r"\\\1", valor)


class LdapIndisponivel(Exception):
    pass


def ordenar_brokers(brokers, ip):
    """Brokers cuja rede contem o IP do cliente vem primeiro; os demais ficam como reserva, na ordem configurada."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return list(brokers)
    perto = [b for b in brokers if any(a in r for r in b["redes"])]
    return perto + [b for b in brokers if b not in perto]


def _autenticar_em(cfg, b, usuario, senha):
    from ldap3 import Connection, Server, Tls
    from ldap3.core.exceptions import LDAPBindError, LDAPException
    dn = cfg.ldap_dn.format(usuario=escapar_rdn(usuario), base=cfg.ldap_base)
    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=b["ca"], valid_names=[b["name"]] if b["name"] else None)
    servidor = Server(b["host"], port=b["port"], use_ssl=True, tls=tls, connect_timeout=5)
    try:
        con = Connection(servidor, user=dn, password=senha, receive_timeout=8, raise_exceptions=True)
        if not con.bind():
            return False, None
    except LDAPBindError:
        return False, None
    except LDAPException as e:
        if "invalidcredentials" in str(e).lower().replace(" ", ""):
            return False, None
        raise LdapIndisponivel(str(e))
    except OSError as e:
        raise LdapIndisponivel(str(e))
    nome = usuario
    try:
        if con.search(cfg.ldap_base, "(uid=%s)" % usuario.replace("\\", ""), attributes=["cn"]) and con.entries:
            nome = str(con.entries[0].cn.value or usuario)
    except Exception:
        pass
    con.unbind()
    return True, nome


def autenticar(cfg, usuario, senha, ip="", log=None):
    """(True, nome) se aceitou; (False, None) se recusou. LdapIndisponivel se nenhum servidor LDAP respondeu.
    Usuario local (LOCAL_USERS): confere o hash PBKDF2. Demais: bind LDAP, escolhendo o servidor pela rede do cliente
    (ip) e so passando ao outro se o primeiro estiver fora do ar: uma recusa de senha e definitiva (os servidores
    replicam entre si). Senha vazia nunca vai ao servidor (bind LDAP com senha vazia e anonimo e 'funciona')."""
    if not USER_RE.match(usuario or "") or not senha:
        return False, None
    local = cfg.usuarios_locais.get(usuario.lower())
    if local:  # usuario local: nao consulta o LDAP (e uma senha errada aqui nao "cai" para o LDAP)
        return (True, usuario) if verificar_senha(senha, local) else (False, None)
    if not cfg.brokers:  # so ha usuarios locais: quem nao esta na lista e simplesmente recusado
        return False, None
    ultimo = None
    for b in ordenar_brokers(cfg.brokers, ip):
        try:
            r = _autenticar_em(cfg, b, usuario, senha)
        except LdapIndisponivel as e:
            ultimo = e
            if log:
                log("ldap %s (%s) indisponivel: %s" % (b["nome"], b["host"], e))
            continue
        if log:
            log("autenticacao pelo ldap %s (%s) para o IP %s" % (b["nome"], b["host"], ip or "?"))
        return r
    raise LdapIndisponivel(str(ultimo) if ultimo else "nenhum servidor LDAP configurado")


# ---------------------------------------------------------------- HTTP
HEAD_SEG = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
                               "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000",
}
TIPOS = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".png": "image/png",
         ".svg": "image/svg+xml"}

PAG_LOGIN = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>%(titulo)s</title>
<link rel="icon" type="image/svg+xml" href="%(base)s/static/icone.svg"><link rel="stylesheet" href="%(base)s/static/app.css"></head>
<body class="login-ui" data-base="%(base)s"><main class="login-dialog">
<img class="logo" src="%(base)s/static/logo.svg" alt="">
<h1 class="app-name">%(titulo)s</h1>
<p class="aviso">Entre com seu usuário e senha.</p>
%(erro)s
<form method="post" action="%(base)s/login" autocomplete="on">
<label for="u">Usuário</label><input id="u" name="usuario" type="text" autocomplete="username" autocapitalize="none" autofocus required maxlength="64">
<label for="s">Senha</label><input id="s" name="senha" type="password" autocomplete="current-password" required maxlength="256">
%(lembrar)s<button type="submit">Entrar</button></form></main>
<p class="rodape">Painel somente leitura · Acesso restrito à equipe autorizada</p></body></html>"""

PAG_PAINEL = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>%(titulo)s</title>
<link rel="icon" type="image/svg+xml" href="%(base)s/static/icone.svg"><link rel="stylesheet" href="%(base)s/static/app.css"></head><body class="painel" data-base="%(base)s">
<header class="topo"><img src="%(base)s/static/logo.svg" alt="" class="topo-logo"><div class="topo-tit"><strong>%(titulo)s</strong>
<span>Vulnerabilidades do Wazuh e como corrigir</span></div><div class="topo-dir">
<a class="sair" href="%(base)s/relatorio" target="_blank" rel="noopener">Relatório</a>
<span class="usuario" title="Sessão">%(nome)s</span>
<form method="post" action="%(base)s/logout"><button class="sair" type="submit">Sair</button></form></div></header>
<nav class="abas" id="abas" aria-label="Seções">
<button type="button" data-aba="geral" class="ativa">Visão geral</button><button type="button" data-aba="servidores">Servidores</button>
<button type="button" data-aba="pacotes">Por pacote</button><button type="button" data-aba="vulns">Vulnerabilidades</button>
<button type="button" data-aba="corrigir">Como corrigir</button><button type="button" data-aba="ajuda">Como ler</button></nav>
<div id="aviso" class="erro aviso-topo" hidden></div>

<main class="aba dash" id="aba-geral"><section class="hero" id="hero"></section>
<div class="dash-grade">
<section class="cartao g4"><h2>Por gravidade</h2><div id="g-grav"></div></section>
<section class="cartao g5"><h2>Tendência <small>(uma foto por dia)</small></h2><div id="g-trend"></div></section>
<section class="cartao g3"><h2>Tem correção?</h2><div id="g-corr"></div></section>
<section class="cartao g5"><h2>Servidores com mais críticas <small>(clique para o plano de correção)</small></h2><div id="g-top"></div></section>
<section class="cartao g4"><h2>Por sistema</h2><div id="g-so"></div></section>
<section class="cartao g3"><h2>Estações × servidores</h2><div id="g-tipo"></div></section>
<section class="cartao g12 kev-cartao"><h2>🔥 Exploradas ativamente <small>(lista da CISA: corrija primeiro)</small></h2><div id="g-kev"></div></section>
<section class="cartao g5"><h2>Onde um patch resolve mais <small>(por críticas)</small></h2><div id="g-pkg"></div></section>
<section class="cartao g7"><h2>CVEs por ano de publicação</h2><div id="g-ano"></div></section>
<section class="cartao g6"><h2>Kernels</h2><div id="g-kern"></div></section>
<section class="cartao g6"><h2>Agentes do Wazuh</h2><div id="g-agentes"></div></section>
</div></main>

<main class="aba pagina" id="aba-servidores" hidden><section class="cartao larg"><h2>Servidores</h2>
<div class="filtros"><input id="s-q" type="search" placeholder="Filtrar por nome ou sistema…" aria-label="Filtrar servidores">
<select id="s-tipo" aria-label="Tipo"><option value="">Servidores e estações</option><option value="Servidor">Só servidores</option><option value="Estação">Só estações</option></select>
<select id="s-so" aria-label="Sistema"><option value="">Todos os sistemas</option></select>
<label class="chk"><input type="checkbox" id="s-crit"> só com críticas</label>
<label class="chk"><input type="checkbox" id="s-desc"> só agente desconectado</label></div>
<div class="filtros sel-barra"><span class="nota" id="n-sel">Nenhuma máquina selecionada.</span>
<button type="button" class="botao claro" id="s-todos">Selecionar as filtradas</button><button type="button" class="botao claro" id="s-limpar">Limpar</button>
<button type="button" class="botao" id="s-rel" disabled>Relatório da seleção</button>
<select id="s-grupo" aria-label="Relatório de um grupo"><option value="">Relatório de um grupo…</option><option value="todos">Todas as máquinas</option>
<option value="tipo:Servidor">Só servidores</option><option value="tipo:Estação">Só estações</option><option value="criticos">Só as com críticas</option></select></div>
<p class="nota" id="n-serv"></p><div class="rolagem alta"><table id="t-serv"></table></div></section></main>

<main class="aba pagina" id="aba-pacotes" hidden><section class="cartao larg"><h2>Pacotes e programas <small>(somando todos os servidores)</small></h2>
<p class="nota">Cada linha é um pacote. Veja quantos servidores ele afeta: atualizar um só pacote resolve muitas falhas de uma vez.</p>
<div class="filtros"><input id="p-q" type="search" placeholder="Filtrar pelo nome do pacote…" aria-label="Filtrar pacotes">
<select id="p-ger" aria-label="Tipo"><option value="">Todos os tipos</option><option value="apt">Linux (apt)</option><option value="dnf">Linux (dnf)</option>
<option value="windows-prog">Programas do Windows</option><option value="windows-so">Windows (sistema)</option><option value="snap">Snap</option></select>
<label class="chk"><input type="checkbox" id="p-kev"> só com CVEs exploradas</label></div>
<p class="nota" id="n-pkgs"></p><div class="rolagem alta"><table id="t-pkgs"></table></div></section></main>

<main class="aba pagina" id="aba-vulns" hidden><section class="cartao larg"><h2>Vulnerabilidades</h2>
<div class="filtros" id="f-sev" role="group" aria-label="Gravidade"></div>
<div class="filtros"><input id="v-q" type="search" placeholder="CVE (ex.: CVE-2024-1234) ou nome do pacote…" aria-label="Buscar">
<select id="v-serv" aria-label="Servidor"><option value="">Todos os servidores</option></select>
<label class="chk"><input type="checkbox" id="v-corr"> só com correção disponível</label>
<label class="chk"><input type="checkbox" id="v-kev"> só exploradas ativamente 🔥</label>
<a id="csv-vulns" class="botao" href="#" download>Exportar CSV</a></div>
<p class="nota" id="n-vulns"></p><div class="rolagem alta"><table id="t-vulns"></table></div>
<div class="filtros pag"><button type="button" class="botao" id="v-ant">‹ Anterior</button><span id="v-pag"></span>
<button type="button" class="botao" id="v-prox">Próxima ›</button></div></section></main>

<main class="aba pagina" id="aba-corrigir" hidden><section class="cartao larg"><h2>Plano de correção</h2>
<div class="filtros"><select id="c-serv" aria-label="Servidor"><option value="">Escolha um servidor…</option></select>
<button type="button" class="botao claro" id="c-rel" disabled>Relatório deste servidor</button></div>
<div id="c-res"><p class="nota">Escolha um servidor para ver o que atualizar, em que ordem, e o que fazer <b>antes</b> de corrigir.</p></div></section></main>

<main class="aba pagina" id="aba-ajuda" hidden><section class="cartao larg" id="ajuda"></section></main>

<div id="modal" class="modal" hidden></div><footer class="rodape-p">Dados do Wazuh, atualizados a cada ~1 h · <span id="atualizado">—</span> · fuso %(tz)s</footer>
<script src="%(base)s/static/charts.js"></script><script src="%(base)s/static/app.js"></script></body></html>"""

PAG_RELATORIO = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Relatório de vulnerabilidades · %(titulo)s</title>
<link rel="icon" type="image/svg+xml" href="%(base)s/static/icone.svg"><link rel="stylesheet" href="%(base)s/static/app.css">
<link rel="stylesheet" href="%(base)s/static/relatorio.css"></head><body class="rel" data-base="%(base)s" data-usuario="%(nome)s (%(uid)s)" data-org="%(org)s">
<div class="rel-acoes sem-impressao"><button type="button" class="botao" id="imprimir">Imprimir / Salvar em PDF</button>
<a class="botao claro" href="%(base)s/">Voltar ao painel</a><span class="nota">No diálogo de impressão, escolha “Salvar como PDF” e ative “Gráficos de segundo plano”.</span></div>
<article class="rel-pagina" id="rel"><p class="nota">Carregando…</p></article>
<div class="rel-rodape-fixo" aria-hidden="true">%(titulo)s · Relatório de vulnerabilidades · CONFIDENCIAL, USO INTERNO</div>
<script src="%(base)s/static/charts.js"></script><script src="%(base)s/static/relatorio.js"></script></body></html>"""


class Servico:
    def __init__(self, cfg, ix=None, enr=None):
        self.cfg = cfg
        self.ix = ix or D.Indexador(cfg.indexer_url, cfg.indexer_user, cfg.indexer_pass, cfg.indexer_ca)
        self.cache, self.lim = D.Cache(cfg.cache), Limitador()
        self.enr = enr or Enriquecimento(cfg.estado)
        self.hist = Historico(cfg.estado)
        self.avisos = Avisos(os.environ, cfg.estado)
        self.lim_aviso = Limitador(1, 60)

    # ---- dados com cache (o Wazuh so reavalia a cada ~1 h)
    def status(self):
        return self.cache.obter("status", lambda: D.status_agentes(self.ix))

    def servidores(self):
        return self.cache.obter("servidores", lambda: D.servidores(self.ix, self.status()))

    def kernels(self):
        return self.cache.obter("kernels", lambda: D.kernels_resumo(self.ix, self.servidores()))

    def resumo(self):
        def montar():
            r = D.resumo(self.ix, self.servidores(), self.enr)
            r["kernels"] = self.kernels()
            r["enriquecimento"] = self.enr.resumo()
            ult = self.hist.ultima() or {}
            r["mudanca"] = {"novas": ult.get("novas"), "corrigidas": ult.get("corrigidas"), "dia": ult.get("dia")} if ult else None
            r["avisos"] = {"canais": self.avisos.canais}
            r["periodo"] = D.mudanca_periodo(self.hist.serie(60), 7)
            r["cobertura"] = {"monitoradas": r["servidores"], "esperadas": self.cfg.esperadas or None,
                              "ativos": r["agentes"]["ativos"], "desconectados": r["agentes"]["desconectados"],
                              "conhecido": r["agentes"]["conhecido"]}
            return r
        return self.cache.obter("resumo", montar)

    # ---- rotina horaria: foto do dia, o que e novo/corrigido, avisos
    def tirar_foto(self):
        lista = D.servidores(self.ix, D.status_agentes(self.ix))
        r = D.resumo(self.ix, lista, self.enr)
        k = D.kernels_resumo(self.ix, lista)
        novas, corrigidas, primeira = self.hist.comparar_criticas(D.criticas_chaves(self.ix))
        foto = D.foto_diaria(r, lista, k)
        ult = self.hist.ultima()
        mesmo_dia = ult and ult.get("dia") == datetime.now(D.TZ).strftime("%Y-%m-%d")
        foto["novas"] = len(novas) + (ult.get("novas", 0) if mesmo_dia else 0)
        foto["corrigidas"] = len(corrigidas) + (ult.get("corrigidas", 0) if mesmo_dia else 0)
        self.hist.registrar(foto)
        if primeira:
            print("historico: primeira foto gravada (base para novas/corrigidas)", flush=True)
            return foto
        if novas and self.avisos.pode_avisar_novas(len(novas)):
            ok, erros = self.avisos.enviar("Backdraft: críticas novas", texto_novas(novas, corrigidas, r, self.cfg.url_publica))
            print("aviso novas criticas: ok=%s erros=%s" % (ok, erros), flush=True)
            if ok:
                self.avisos.marcou_novas()
        pend, sem = self.avisos.semana_pendente()
        if pend:
            ok, erros = self.avisos.enviar("Backdraft: resumo semanal", texto_semanal(r, self.hist.serie(14), self.cfg.url_publica))
            print("aviso semanal: ok=%s erros=%s" % (ok, erros), flush=True)
            if ok:
                self.avisos.marcou_semana(sem)
        return foto


def laco_enriquecimento(sv):
    time.sleep(3)
    while True:
        try:
            if not sv.enr.kev or time.time() - sv.enr.atualizado_em > 20 * 3600:
                erros = sv.enr.atualizar()
                print("listas KEV/EPSS: %s" % (("erros: " + "; ".join(erros)) if erros else "atualizadas"), flush=True)
        except Exception as e:
            print("listas KEV/EPSS: falha inesperada: %s" % e, flush=True)
        time.sleep(3600)


def laco_historico(sv):
    time.sleep(25)  # deixa as listas KEV/EPSS baixarem primeiro
    while True:
        try:
            sv.tirar_foto()
        except Exception as e:
            print("historico: erro: %s" % e, flush=True)
        time.sleep(3600)


def criar_handler(sv):
    cfg = sv.cfg

    class H(BaseHTTPRequestHandler):
        server_version = "backdraft"
        sys_version = ""
        timeout = 30  # conexao parada por mais de 30 s e derrubada

        def log_message(self, fmt, *a):
            pass

        def _ip(self):
            ip = self.client_address[0]
            try:
                if any(ipaddress.ip_address(ip) in n for n in cfg.proxies):
                    return self.headers.get("X-Real-IP") or (self.headers.get("X-Forwarded-For", "").split(",")[-1].strip() or ip)
            except ValueError:
                pass
            return ip

        def _log(self, msg):
            print("%s ip=%s %s" % (datetime.now(D.TZ).strftime("%Y-%m-%d %H:%M:%S"), self._ip(), msg), flush=True)

        def _enviar(self, codigo, corpo, tipo="text/html; charset=utf-8", extra=None, cache=True):
            if isinstance(corpo, str):
                corpo = corpo.encode()
            self.send_response(codigo)
            self.send_header("Content-Type", tipo)
            self.send_header("Content-Length", str(len(corpo)))
            self.send_header("Cache-Control", "public, max-age=300" if cache else "no-store")
            for k, v in HEAD_SEG.items():
                self.send_header(k, v)
            for k, v in (extra or []):
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(corpo)

        def _redir(self, destino, extra=None):
            self.send_response(303)
            self.send_header("Location", cfg.base + destino)
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or []):
                self.send_header(k, v)
            self.end_headers()

        def _cookie(self, valor, apagar=False, max_age=None):
            c = "%s=%s; Path=%s; HttpOnly; SameSite=Strict" % (COOKIE, "" if apagar else valor, cfg.base or "/")
            if apagar:
                c += "; Max-Age=0"
            elif max_age:
                c += "; Max-Age=%d" % max_age  # persistente ("lembrar de mim"); sem isso o cookie some ao fechar o navegador
            if cfg.cookie_secure:
                c += "; Secure"
            return ("Set-Cookie", c)

        def _sessao(self):
            c = SimpleCookie(self.headers.get("Cookie", ""))
            if COOKIE not in c:
                return None
            return ler_token(cfg.secret, c[COOKIE].value, cfg.idle, cfg.max_life,
                             idle_m=cfg.lembrar_idle if cfg.lembrar_dias else None, max_m=cfg.lembrar_max if cfg.lembrar_dias else None)

        def _renovar(self, s):
            agora = int(time.time())
            lembrar = bool(s.get("m"))
            resta = max(1, s["i"] + cfg.lembrar_max - agora) if lembrar else None
            return self._cookie(criar_token(cfg.secret, s["u"], s["n"], s["i"], agora, lembrar), max_age=resta)

        def _origem_ok(self):
            o = self.headers.get("Origin")
            if not o or o == "null":
                o = self.headers.get("Referer")
            if o:
                return urlparse(o).netloc == self.headers.get("Host", "")
            return self.headers.get("Sec-Fetch-Site", "same-origin") in ("same-origin", "none")

        def _login_pag(self, erro="", codigo=200):
            msg = '<p class="erro" role="alert">%s</p>' % html.escape(erro) if erro else ""
            lembrar = ('<label class="lembrar"><input type="checkbox" name="lembrar" value="1"> Lembrar de mim neste computador '
                       '(%d dias)</label>' % cfg.lembrar_dias) if cfg.lembrar_dias else ""
            self._enviar(codigo, PAG_LOGIN % {"erro": msg, "base": cfg.base, "lembrar": lembrar, "titulo": html.escape(cfg.titulo)}, cache=False)

        def _ip_ok(self):
            return ip_permitido(cfg.allowed_nets, self._ip())

        def _negar_ip(self):
            self._log("acesso negado (IP fora da lista)")
            self._enviar(403, "Acesso não permitido a partir deste endereço.", "text/plain; charset=utf-8", cache=False)

        def _rota(self):
            p = urlparse(self.path)
            caminho = p.path
            if cfg.base and (caminho == cfg.base or caminho.startswith(cfg.base + "/")):
                caminho = caminho[len(cfg.base):] or "/"
            return p, caminho

        def do_GET(self):
            p, caminho = self._rota()
            if caminho != "/saude" and not self._ip_ok():
                return self._negar_ip()
            if caminho == "/saude":
                return self._enviar(200, '{"ok":true}', "application/json", cache=False)
            if caminho.startswith("/static/"):
                nome = os.path.basename(caminho)
                arq = os.path.join(STATIC, nome)
                if os.path.splitext(nome)[1] in TIPOS and os.path.isfile(arq):
                    with open(arq, "rb") as f:
                        return self._enviar(200, f.read(), TIPOS[os.path.splitext(nome)[1]], cache=False)
                return self._enviar(404, "não encontrado", "text/plain; charset=utf-8", cache=False)
            s = self._sessao()
            if caminho == "/login":
                return self._redir("/") if s else self._login_pag()
            if not s:
                if caminho.startswith("/api/"):
                    return self._enviar(401, '{"erro":"sessao"}', "application/json", cache=False)
                return self._redir("/login")
            if caminho.startswith("/api/"):
                return self._api(s, caminho, parse_qs(p.query))
            if caminho == "/":
                return self._enviar(200, PAG_PAINEL % {"nome": html.escape(s["n"]), "base": cfg.base, "titulo": html.escape(cfg.titulo), "tz": html.escape(cfg.tz_nome)}, cache=False,
                                    extra=[self._renovar(s)])
            if caminho == "/relatorio":
                return self._enviar(200, PAG_RELATORIO % {"nome": html.escape(s["n"]), "uid": html.escape(s["u"]), "base": cfg.base, "titulo": html.escape(cfg.titulo), "org": html.escape(cfg.org)}, cache=False,
                                    extra=[self._renovar(s)])
            self._enviar(404, "não encontrado", "text/plain; charset=utf-8", cache=False)

        # ---- API (todas so leitura). Cada _r_* devolve (codigo, corpo, tipo, cabecalhos extras).
        def _json(self, obj, codigo=200):
            return codigo, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8", []

        def _agora(self):
            return datetime.now(D.TZ).strftime("%d/%m/%Y %H:%M:%S")

        def _r_resumo(self, q):
            return self._json(dict(sv.resumo(), gerado_em=self._agora()))

        def _r_servidores(self, q):
            return self._json({"servidores": sv.servidores(), "agentes_conhecido": sv.status() is not None, "gerado_em": self._agora()})

        def _r_servidor(self, q):
            nome = (q.get("nome") or [""])[0]
            if not NOME_SERV_RE.match(nome):
                return self._json({"erro": "Servidor inválido."}, 400)
            r = sv.cache.obter("srv:" + nome, lambda: D.servidor(sv.ix, nome, sv.enr))
            return self._json(r) if r else self._json({"erro": "Servidor não encontrado."}, 404)

        def _r_relatorio(self, q):
            """Relatorio de UM servidor, de uma selecao (servidores=a,b,c) ou de um grupo (grupo=todos|tipo:Servidor|...)."""
            lista = sv.servidores()
            grupo = (q.get("grupo") or [""])[0]
            titulo = ""
            if grupo:
                g = D.resolver_grupo(grupo, lista)
                if not g:
                    return self._json({"erro": "Grupo inválido."}, 400)
                titulo, nomes = g
                nomes = nomes[:200]
            else:
                nomes = [n.strip() for n in (q.get("servidores") or [""])[0].split(",") if n.strip()]
                if not nomes or len(nomes) > 60 or any(not NOME_SERV_RE.match(n) for n in nomes):
                    return self._json({"erro": "Informe de 1 a 60 servidores válidos."}, 400)

            def detalhe(n):
                return sv.cache.obter("srv:" + n, lambda: D.servidor(sv.ix, n, sv.enr))
            r = sv.cache.obter("rel:%s|%s" % (titulo, ",".join(sorted(nomes))), lambda: D.relatorio(sv.ix, lista, nomes, titulo, sv.enr, detalhe))
            return self._json(dict(r, gerado_em=self._agora()))

        def _r_pacotes(self, q):
            return self._json({"pacotes": sv.cache.obter("pacotes", lambda: D.pacotes(sv.ix, sv.enr)), "gerado_em": self._agora()})

        def _r_pacote(self, q):
            nome = (q.get("nome") or [""])[0]
            if not 0 < len(nome) <= 300:
                return self._json({"erro": "Pacote inválido."}, 400)
            return self._json({"servidores": sv.cache.obter("pkg:" + nome, lambda: D.pacote_detalhe(sv.ix, nome))})

        def _r_historico(self, q):
            return self._json({"serie": sv.hist.serie(120)})

        def _r_avisos(self, q):
            a = sv.avisos
            return self._json({"canais": a.canais, "ativo": a.ativo, "ultimo_erro": a.estado.get("ultimo_erro", ""),
                               "min_novas": a.min_novas, "intervalo_h": a.intervalo_h})

        def _filtros(self, q):
            sevs = [x for x in (q.get("sev") or [""])[0].split(",") if x in D.SEVS]
            serv = (q.get("servidor") or [""])[0]
            if serv and not NOME_SERV_RE.match(serv):
                serv = "\x00"  # nome invalido: nenhum resultado, nunca "todos"
            return (sevs, serv, (q.get("q") or [""])[0].strip()[:80], (q.get("corrigivel") or [""])[0] == "1",
                    (q.get("exploradas") or [""])[0] == "1")

        def _r_vulns(self, q):
            sevs, serv, texto, corr, expl = self._filtros(q)
            try:
                pag = int((q.get("pagina") or ["0"])[0])
            except ValueError:
                pag = 0
            return self._json(D.vulnerabilidades(sv.ix, sevs, serv, texto, corr, pag, 100, expl, sv.enr))

        def _r_vulns_csv(self, q):
            sevs, serv, texto, corr, expl = self._filtros(q)
            linhas = D.vulnerabilidades_csv(sv.ix, sevs, serv, texto, corr, expl, sv.enr)
            sit = {"corrigido": "tem correção", "ate": "versão corrigida desconhecida", "sem": "sem correção publicada"}
            csv = D.csv_texto(["CVE", "Gravidade", "Nota", "Explorada ativamente (CISA)", "EPSS", "Servidor", "Pacote", "Versão instalada",
                               "Atualizar para", "Situação", "Publicada", "Referência"],
                              [[x["cve"], D.SEV_PT[x["sev"]], x["nota"], "sim" if x["kev"] else "", x["epss"] if x["epss"] is not None else "",
                                x["servidor"], x["pacote"], x["instalada"], x["corrigir_para"] or "", sit.get(x["situacao"], ""),
                                x["publicada"], x["ref"]] for x in linhas])
            return 200, csv, "text/csv; charset=utf-8", [("Content-Disposition", 'attachment; filename="backdraft-vulnerabilidades.csv"')]

        def _r_cves(self, q):
            serv, pacote = (q.get("servidor") or [""])[0], (q.get("pacote") or [""])[0]
            if not NOME_SERV_RE.match(serv) or not 0 < len(pacote) <= 300:
                return self._json({"erro": "Parâmetros inválidos."}, 400)
            return self._json({"itens": D.cves_do_pacote(sv.ix, serv, pacote, sv.enr)})

        def _api(self, s, caminho, q):
            rotas = {"/api/resumo": self._r_resumo, "/api/servidores": self._r_servidores, "/api/servidor": self._r_servidor,
                     "/api/pacotes": self._r_pacotes, "/api/pacote": self._r_pacote, "/api/historico": self._r_historico,
                     "/api/avisos": self._r_avisos, "/api/relatorio": self._r_relatorio, "/api/vulns": self._r_vulns, "/api/vulns.csv": self._r_vulns_csv,
                     "/api/cves": self._r_cves}
            fn = rotas.get(caminho)
            if not fn:
                return self._enviar(404, '{"erro":"rota inexistente"}', "application/json", cache=False)
            extra = [self._renovar(s)] if self.headers.get("X-Atividade") else []  # so acao do usuario estende a sessao
            try:
                codigo, corpo, tipo, cab = fn(q)
                return self._enviar(codigo, corpo, tipo, extra=extra + cab, cache=False)
            except Exception as e:  # indexador fora, credencial errada, resposta inesperada...
                self._log("erro em %s: %s" % (caminho, e))
                return self._enviar(502, json.dumps({"erro": "Não foi possível consultar o Wazuh para esta seção."}),
                                    "application/json; charset=utf-8", extra=extra, cache=False)

        def _testar_aviso(self, s):
            """POST /api/avisos/testar: manda uma mensagem de teste pelos canais configurados (1 por minuto)."""
            def resp(codigo, obj):
                return self._enviar(codigo, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8", cache=False)
            if not sv.avisos.ativo:
                return resp(400, {"erro": "Nenhum canal de aviso configurado (Telegram ou e-mail no .env)."})
            if sv.lim_aviso.bloqueado("t"):
                return resp(429, {"erro": "Aguarde um minuto para testar de novo."})
            sv.lim_aviso.falha("t")
            ok, erros = sv.avisos.enviar("Backdraft: teste de aviso", "Teste enviado por %s. Se você recebeu esta mensagem, os avisos estão funcionando." % s["u"])
            self._log("teste de aviso uid=%s ok=%s erros=%s" % (s["u"], ok, erros))
            return resp(200 if ok else 502, {"ok": ok, "erros": erros})

        def do_POST(self):
            p, caminho = self._rota()
            # Le o corpo ANTES de responder: fechar com corpo pendente pode gerar RST e o navegador veria "falha de conexao".
            corpo = self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 4096))
            if not self._ip_ok():
                return self._negar_ip()
            if not self._origem_ok():
                return self._enviar(403, "origem inválida", "text/plain; charset=utf-8", cache=False)
            if caminho == "/api/avisos/testar":
                sess = self._sessao()
                if not sess:
                    return self._enviar(401, '{"erro":"sessao"}', "application/json", cache=False)
                return self._testar_aviso(sess)
            form = parse_qs(corpo.decode("utf-8", "replace"))
            if caminho == "/logout":
                self._log("logout")
                return self._redir("/login", [self._cookie("", apagar=True)])
            if caminho != "/login":
                return self._enviar(404, "não encontrado", "text/plain; charset=utf-8", cache=False)
            usuario = (form.get("usuario") or [""])[0].strip()
            senha = (form.get("senha") or [""])[0]
            lembrar = bool(cfg.lembrar_dias) and (form.get("lembrar") or [""])[0] == "1"
            ip, chave_u = self._ip(), "u:" + usuario.lower()
            if sv.lim.bloqueado("i:" + ip, chave_u):
                self._log("login bloqueado (muitas tentativas) uid=%s" % usuario[:64])
                return self._login_pag("Muitas tentativas. Aguarde alguns minutos.", 429)
            try:
                ok, nome = autenticar(cfg, usuario, senha, ip, self._log)
            except LdapIndisponivel as e:
                self._log("ldap indisponivel: %s" % e)
                return self._login_pag("Servidor de autenticação indisponível. Tente novamente.", 503)
            if ok and usuario.lower() not in cfg.allowed:
                self._log("login negado (sem permissao) uid=%s" % usuario)
                sv.lim.falha("i:" + ip, chave_u)
                return self._login_pag("Seu usuário não tem permissão para este painel.", 403)
            if not ok:
                self._log("login falhou uid=%s" % usuario[:64])
                sv.lim.falha("i:" + ip, chave_u)
                time.sleep(0.7)
                return self._login_pag("Usuário ou senha inválidos.", 401)
            sv.lim.ok("i:" + ip, chave_u)
            agora = int(time.time())
            self._log("login ok uid=%s%s" % (usuario, " (lembrar de mim)" if lembrar else ""))
            self._redir("/", [self._cookie(criar_token(cfg.secret, usuario, nome, agora, agora, lembrar),
                                           max_age=cfg.lembrar_max if lembrar else None)])

    return H


def gerar_hash_interativo(usuario):
    """python3 backdraft.py --gerar-hash USUARIO : pede a senha 2x (sem eco) e imprime a entrada para LOCAL_USERS no .env."""
    import getpass
    if not USER_RE.match(usuario or ""):
        sys.exit("Usuario invalido (so letras, numeros, ponto, hifen e sublinhado).")
    a = getpass.getpass("Senha de %s (minimo 10 caracteres): " % usuario)
    if len(a) < 10:
        sys.exit("Senha curta demais (minimo 10 caracteres).")
    if getpass.getpass("Repita a senha: ") != a:
        sys.exit("As senhas nao conferem.")
    print("%s|%s" % (usuario, gerar_hash_senha(a)))
    print("Acrescente isso a LOCAL_USERS no .env (varios usuarios separados por virgula) e a ALLOWED_USERS.")


def main():
    if "--gerar-hash" in sys.argv:
        i = sys.argv.index("--gerar-hash")
        return gerar_hash_interativo(sys.argv[i + 1] if len(sys.argv) > i + 1 else "")
    cfg = Config()
    if len(cfg.secret) < 32:
        sys.exit("BACKDRAFT_SECRET ausente ou curto (minimo 32 caracteres)")
    if not cfg.allowed or not cfg.indexer_pass:
        sys.exit("Defina ALLOWED_USERS e INDEXER_PASS no .env")
    if not os.path.isfile(cfg.indexer_ca):
        sys.exit("CA do Wazuh nao encontrada em %s (copie /etc/wazuh-indexer/certs/root-ca.pem e ajuste INDEXER_CA)" % cfg.indexer_ca)
    if not (cfg.usuarios_locais or cfg.brokers):
        print("AVISO: nenhum login configurado (LOCAL_USERS ou LDAP_*/BROKER_*): ninguem conseguira entrar.", flush=True)
    if cfg.cookie_secure and not (cfg.tls_cert and cfg.tls_key) and not cfg.proxies:
        sys.exit("COOKIE_SECURE=1 exige HTTPS: defina TLS_CERT/TLS_KEY (ou TRUSTED_PROXIES atras de um proxy HTTPS)")
    if cfg.estado:
        os.makedirs(cfg.estado, exist_ok=True)
    sv = Servico(cfg)
    threading.Thread(target=laco_enriquecimento, args=(sv,), daemon=True).start()
    threading.Thread(target=laco_historico, args=(sv,), daemon=True).start()
    ctx = None
    if cfg.tls_cert and cfg.tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cfg.tls_cert, cfg.tls_key)

    class Servidor(ThreadingHTTPServer):
        daemon_threads = True

        def get_request(self):  # o handshake TLS acontece na thread da conexao: um cliente lento nao trava o servidor
            sock, addr = super().get_request()
            if ctx:
                sock = ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
            return sock, addr

    srv = Servidor((cfg.bind, cfg.port), criar_handler(sv))
    print("backdraft em %s://%s:%d (usuarios=%d, avisos=%s, estado=%s)" % (
        "https" if cfg.tls_cert else "http", cfg.bind, cfg.port, len(cfg.allowed), "+".join(sv.avisos.canais) or "desligados",
        cfg.estado or "memoria"), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
