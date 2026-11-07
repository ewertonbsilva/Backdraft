"""Avisos do Backdraft por Telegram e/ou e-mail. Desligado por padrao: so liga se houver configuracao no .env.

* "Novas criticas": quando aparecem CVEs criticas que nao existiam na ultima verificacao (no maximo 1 aviso a cada N horas).
* "Resumo semanal": toda segunda-feira, a partir das 08h (fuso BACKDRAFT_TZ).
O Wazuh 4.14 nao gera alerta de CVE; este e o aviso que faltava.
"""
import json
import os
import smtplib
import ssl
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime
from email.message import EmailMessage

from dados import SEV_PT, TZ


def _env(e, k, p=""):
    return (e.get(k, p) or "").strip()


class Avisos:
    def __init__(self, env, pasta=""):
        self.tg_token, self.tg_chat = _env(env, "TELEGRAM_BOT_TOKEN"), _env(env, "TELEGRAM_CHAT_ID")
        self.smtp_host, self.smtp_port = _env(env, "SMTP_HOST"), int(_env(env, "SMTP_PORT", "587") or 587)
        self.smtp_user, self.smtp_pass = _env(env, "SMTP_USER"), env.get("SMTP_PASS", "")
        self.smtp_de, self.smtp_para = _env(env, "SMTP_FROM"), [x.strip() for x in _env(env, "SMTP_TO").split(",") if x.strip()]
        self.smtp_modo = _env(env, "SMTP_MODE", "starttls").lower()  # starttls | ssl | plain
        self.min_novas = int(_env(env, "AVISO_MIN_NOVAS", "1") or 1)
        self.intervalo_h = float(_env(env, "AVISO_INTERVALO_HORAS", "6") or 6)
        self.url = _env(env, "AVISO_URL")  # endereco do painel para o link no aviso
        self.pasta, self._l = pasta, threading.Lock()
        self.estado = {"ultimo_novas": 0, "ultima_semana": "", "ultimo_erro": ""}
        arq = self._arq()
        if arq and os.path.isfile(arq):
            try:
                with open(arq, encoding="utf-8") as f:
                    self.estado.update(json.load(f))
            except (OSError, ValueError):
                pass

    def _arq(self):
        return os.path.join(self.pasta, "avisos.json") if self.pasta else ""

    def _salvar(self):
        arq = self._arq()
        if arq:
            try:
                with open(arq + ".tmp", "w", encoding="utf-8") as f:
                    json.dump(self.estado, f)
                os.replace(arq + ".tmp", arq)
            except OSError:
                pass

    @property
    def canais(self):
        c = []
        if self.tg_token and self.tg_chat:
            c.append("Telegram")
        if self.smtp_host and self.smtp_de and self.smtp_para:
            c.append("E-mail")
        return c

    @property
    def ativo(self):
        return bool(self.canais)

    # ---- envio
    def _telegram(self, texto):
        for i in range(0, len(texto), 3800):  # limite do Telegram: 4096
            dado = urllib.parse.urlencode({"chat_id": self.tg_chat, "text": texto[i:i + 3800], "disable_web_page_preview": "true"}).encode()
            req = urllib.request.Request("https://api.telegram.org/bot%s/sendMessage" % self.tg_token, data=dado)
            with urllib.request.urlopen(req, timeout=20) as r:
                if r.status != 200:
                    raise RuntimeError("Telegram HTTP %d" % r.status)

    def _email(self, assunto, texto):
        m = EmailMessage()
        m["Subject"], m["From"], m["To"] = assunto, self.smtp_de, ", ".join(self.smtp_para)
        m.set_content(texto)
        ctx = ssl.create_default_context()
        if self.smtp_modo == "ssl":
            s = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=25, context=ctx)
        else:
            s = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=25)
            if self.smtp_modo == "starttls":
                s.starttls(context=ctx)
        try:
            if self.smtp_user:
                s.login(self.smtp_user, self.smtp_pass)
            s.send_message(m)
        finally:
            try:
                s.quit()
            except Exception:
                pass

    def enviar(self, assunto, texto):
        """Tenta todos os canais configurados. -> (canais_ok, erros)."""
        ok, erros = [], []
        for nome, fn in (("Telegram", lambda: self._telegram(assunto + "\n\n" + texto)), ("E-mail", lambda: self._email(assunto, texto))):
            if nome not in self.canais:
                continue
            try:
                fn()
                ok.append(nome)
            except Exception as e:
                erros.append("%s: %s" % (nome, str(e)[:120]))
        with self._l:
            self.estado["ultimo_erro"] = "; ".join(erros)
            self._salvar()
        return ok, erros

    # ---- politica
    def pode_avisar_novas(self, n_novas, agora=None):
        agora = time.time() if agora is None else agora
        return self.ativo and n_novas >= self.min_novas and agora - self.estado.get("ultimo_novas", 0) >= self.intervalo_h * 3600

    def marcou_novas(self, agora=None):
        with self._l:
            self.estado["ultimo_novas"] = time.time() if agora is None else agora
            self._salvar()

    def semana_pendente(self, agora=None):
        """Segunda-feira, 08h ou mais (fuso BACKDRAFT_TZ), ainda nao enviado nesta semana ISO."""
        d = datetime.fromtimestamp(time.time() if agora is None else agora, TZ)
        sem = "%d-W%02d" % d.isocalendar()[:2]
        return self.ativo and d.weekday() == 0 and d.hour >= 8 and self.estado.get("ultima_semana") != sem, sem

    def marcou_semana(self, sem):
        with self._l:
            self.estado["ultima_semana"] = sem
            self._salvar()


# ---------------------------------------------------------------- textos (puro texto: serve para Telegram e e-mail)
def texto_novas(novas, corrigidas, resumo, url=""):
    g = resumo["gravidade"]
    linhas = ["🔥 Backdraft: %d CVE(s) CRÍTICA(S) nova(s) desde a última verificação." % len(novas)]
    por_serv = {}
    for k in novas:
        cve, _, srv = k.partition("|")
        por_serv.setdefault(srv, []).append(cve)
    for srv, cves in sorted(por_serv.items(), key=lambda x: -len(x[1]))[:8]:
        linhas.append("• %s: %d (%s%s)" % (srv, len(cves), ", ".join(sorted(cves)[:3]), "…" if len(cves) > 3 else ""))
    if len(por_serv) > 8:
        linhas.append("… e mais %d servidores." % (len(por_serv) - 8))
    if corrigidas:
        linhas.append("✅ %d crítica(s) corrigida(s) no mesmo período." % len(corrigidas))
    linhas.append("")
    linhas.append("Hoje: %d críticas, %d altas, %d médias em %d servidores." % (g["Critical"], g["High"], g["Medium"], resumo["servidores"]))
    if resumo.get("kev", {}).get("cves"):
        linhas.append("⚠️ %d CVE(s) já exploradas ativamente (CISA) em %d servidores." % (resumo["kev"]["cves"], resumo["kev"]["servidores"]))
    if url:
        linhas.append(url)
    return "\n".join(linhas)


def texto_semanal(resumo, serie, url=""):
    g = resumo["gravidade"]
    linhas = ["📊 Backdraft: resumo semanal de vulnerabilidades", "",
              "%d críticas · %d altas · %d médias · %d baixas" % (g["Critical"], g["High"], g["Medium"], g["Low"]),
              "%d de %d servidores com crítica." % (resumo["com_critica"], resumo["servidores"])]
    if len(serie) >= 2:
        ant = serie[max(0, len(serie) - 8)]
        d = g["Critical"] - ant.get("grav", {}).get("Critical", g["Critical"])
        linhas.append("Críticas nos últimos %d dias: %s%d." % (len(serie) - serie.index(ant) - 1, "+" if d > 0 else "", d))
    kev = resumo.get("kev", {})
    if kev.get("cves"):
        linhas.append("⚠️ Exploradas ativamente (CISA): %d CVEs em %d servidores." % (kev["cves"], kev["servidores"]))
    linhas.append("")
    linhas.append("Piores servidores:")
    for s in resumo["top_servidores"][:5]:
        linhas.append("• %s: %d críticas, %d altas" % (s["nome"], s["Critical"], s["High"]))
    if url:
        linhas += ["", url]
    return "\n".join(linhas)
