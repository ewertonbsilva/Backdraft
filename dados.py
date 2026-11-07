"""Backdraft: leitura do indice de vulnerabilidades do Wazuh e montagem do plano de correcao.

So biblioteca padrao. O indice (wazuh-states-vulnerabilities-*) guarda UM documento por CVE x pacote x servidor.
A "versao corrigida" vem do campo vulnerability.scanner.condition:
  "Package less than X"              -> corrigido na versao X (atualizar para X ou mais nova)
  "Package less than or equal to X"  -> afetado ate X; a versao corrigida e desconhecida
  "Package default status"           -> afetado e sem correcao publicada pelo fabricante
Nada aqui executa comandos: so gera texto para uma pessoa copiar.
"""
import base64
import json
import os
import re
import ssl
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone

try:  # fuso das datas do painel, dos avisos semanais e do historico diario (BACKDRAFT_TZ, ex.: America/Sao_Paulo)
    from zoneinfo import ZoneInfo
    TZ_NOME = os.environ.get("BACKDRAFT_TZ", "America/Sao_Paulo").strip() or "UTC"
    TZ = ZoneInfo(TZ_NOME)
except Exception:  # sem o banco de fusos (ex.: Windows sem tzdata): UTC-3 fixo
    TZ_NOME, TZ = "UTC-3", timezone(timedelta(hours=-3))
INDICE = "wazuh-states-vulnerabilities-*"
INDICE_MON = "wazuh-monitoring-*"  # status dos agentes (precisa de permissao de leitura extra)
F_SEV, F_AGENTE, F_CVE = "vulnerability.severity", "agent.name", "vulnerability.id"
F_PLAT, F_PKG, F_TIPO = "host.os.platform", "package.name", "package.type"
F_VER, F_COND, F_NOTA = "package.version", "vulnerability.scanner.condition", "vulnerability.score.base"

SEVS = ["Critical", "High", "Medium", "Low", "Outra"]  # 'Outra' = sem classificacao ('-', 'None')
SEV_PT = {"Critical": "Crítica", "High": "Alta", "Medium": "Média", "Low": "Baixa", "Outra": "Sem classificação"}
RANK = {s: i for i, s in enumerate(SEVS)}
NOME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
# Nome de pacote so entra num comando se for "limpo": o nome vem da maquina inventariada e uma maquina comprometida
# poderia informar um nome como "x; rm -rf /" para ser copiado e colado por alguem.
PKG_SEGURO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_:~-]{0,100}$")
REINICIA = re.compile(r"^(linux-(image|modules|generic|headers|aws|kvm|oem|azure|gcp|hwe|signed)|kernel|glibc|libc6|libc-bin|"
                      r"systemd|libsystemd|udev|dbus|grub|shim|openssl|libssl|microcode|intel-microcode)", re.I)
BANCO = re.compile(r"(mysql|mariadb|postgres|mongodb|redis|sqlite)", re.I)
CONTEINER = re.compile(r"^(docker|containerd|runc|lxd|podman)", re.I)
WEB = re.compile(r"^(nginx|apache2|httpd|haproxy)", re.I)


def norm_sev(s):
    return s if s in ("Critical", "High", "Medium", "Low") else "Outra"


def contar(buckets):
    """Buckets de uma agregacao terms por gravidade -> {Critical, High, Medium, Low, Outra, total}."""
    r = {k: 0 for k in SEVS}
    for b in buckets or []:
        r[norm_sev(b["key"])] += b["doc_count"]
    r["total"] = sum(r[k] for k in SEVS)
    return r


# ---------------------------------------------------------------- versoes (dpkg/rpm, de forma aproximada)
def _peso(c):
    if c == "~":
        return -1
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _cmp_trecho(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        pa, pb = re.match(r"\D*", a[i:]).group(), re.match(r"\D*", b[j:]).group()
        i, j = i + len(pa), j + len(pb)
        for k in range(max(len(pa), len(pb))):
            x = _peso(pa[k]) if k < len(pa) else 0
            y = _peso(pb[k]) if k < len(pb) else 0
            if x != y:
                return -1 if x < y else 1
        da, db = re.match(r"\d*", a[i:]).group(), re.match(r"\d*", b[j:]).group()
        i, j = i + len(da), j + len(db)
        x, y = int(da or 0), int(db or 0)
        if x != y:
            return -1 if x < y else 1
    return 0


def _partes(v):
    ep, resto = "0", v
    if re.match(r"^\d+:", v):
        ep, resto = v.split(":", 1)
    up, rev = (resto.rsplit("-", 1) + [""])[:2] if "-" in resto else (resto, "")
    return int(ep), up, rev


def vercmp(a, b):
    """-1, 0, 1. Ordem do dpkg (serve tambem para as versoes do rpm e do Windows na pratica)."""
    ea, ua, ra = _partes(a or "")
    eb, ub, rb = _partes(b or "")
    if ea != eb:
        return -1 if ea < eb else 1
    return _cmp_trecho(ua, ub) or _cmp_trecho(ra, rb)


def parse_cond(cond):
    """(tipo, versao): 'corrigido' | 'ate' | 'sem' | 'outro'."""
    c = (cond or "").strip()
    m = re.match(r"^Package less than or equal to (.+)$", c)
    if m:
        return "ate", m.group(1).strip()
    m = re.match(r"^Package less than (.+)$", c)
    if m:
        return "corrigido", m.group(1).strip()
    if c.startswith("Package default status"):
        return "sem", None
    return "outro", None


def maior_versao(versoes):
    melhor = None
    for v in versoes:
        if melhor is None or vercmp(v, melhor) > 0:
            melhor = v
    return melhor


def gerenciador(tipo):
    return {"deb": "apt", "rpm": "dnf", "snap": "snap", "windows": "windows-so", "win": "windows-prog"}.get(tipo, "outro")


# ---------------------------------------------------------------- cliente do indexador
class Indexador:
    """Cliente minimo (so _search). A cadeia do certificado e validada com a CA do Wazuh; o nome nao, porque o
    certificado do indexador so tem o IP 127.0.0.1 no SAN."""

    def __init__(self, url, usuario, senha, ca, timeout=40):
        self.url, self.timeout = url.rstrip("/"), timeout
        self.ctx = ssl.create_default_context(cafile=ca)
        self.ctx.check_hostname = False
        self.auth = "Basic " + base64.b64encode(("%s:%s" % (usuario, senha)).encode()).decode()

    def buscar(self, corpo, indice=INDICE):
        req = urllib.request.Request(self.url + "/" + indice + "/_search", data=json.dumps(corpo).encode(),
                                     headers={"Content-Type": "application/json", "Authorization": self.auth})
        with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as r:
            return json.load(r)


class Cache:
    """Resultados pesados ficam em memoria por alguns minutos (o Wazuh so reavalia a cada ~1 h)."""

    def __init__(self, ttl=300):
        self.ttl, self._d, self._l = ttl, {}, threading.Lock()

    def obter(self, chave, fn):
        agora = time.time()
        with self._l:
            v = self._d.get(chave)
            if v and agora - v[0] < self.ttl:
                return v[1]
        dado = fn()
        with self._l:
            self._d[chave] = (time.time(), dado)
            if len(self._d) > 200:
                for k in sorted(self._d, key=lambda x: self._d[x][0])[:50]:
                    del self._d[k]
        return dado


# ---------------------------------------------------------------- tipo de maquina e status do agente
def tipo_maquina(so, plataforma):
    """Estacao = Windows de usuario (10/11); servidor = Linux e Windows Server."""
    s = (so or "").lower()
    if plataforma == "windows" or "windows" in s:
        return "Servidor" if "server" in s else "Estação"
    return "Servidor"


def status_agentes(ix):
    """{nome_do_agente: {'status', 'visto'}} a partir do indice de monitoramento do Wazuh, ou None se o usuario de leitura
    ainda nao tem permissao nesse indice (o painel funciona sem isso)."""
    try:
        r = ix.buscar({"size": 0, "aggs": {"a": {"terms": {"field": "id", "size": 3000}, "aggs": {"u": {"top_hits": {
            "size": 1, "sort": [{"timestamp": "desc"}], "_source": ["name", "status", "lastKeepAlive"]}}}}}}, indice=INDICE_MON)
    except Exception:
        return None
    out = {}
    for b in r.get("aggregations", {}).get("a", {}).get("buckets", []):
        h = b["u"]["hits"]["hits"]
        if h and h[0]["_source"].get("name"):
            s = h[0]["_source"]
            out[s["name"]] = {"status": s.get("status", ""), "visto": (s.get("lastKeepAlive") or "")[:19]}
    return out


# ---------------------------------------------------------------- kernels (Ubuntu/Debian)
KERNEL_PKG = re.compile(r"^linux-(image|modules|headers)-(?:unsigned-)?(\d+\.\d+\.\d+-\d+)(?:-([a-z0-9+.-]+))?$")
KERNEL_RUN = re.compile(r"^(\d+\.\d+\.\d+-\d+)(?:-([a-z0-9+.-]+))?")


def analisar_kernels(kernel_em_uso, contagens):
    """contagens: {nome_do_pacote: registros_de_cve}. Kernels com versao MENOR que a em uso e do mesmo tipo podem ser removidos
    (apt autoremove); um linux-image MAIOR que o em uso significa reinicio pendente. So enxerga kernels que aparecem
    no indice de vulnerabilidades (um kernel novo e sem nenhuma CVE nao aparece)."""
    m = KERNEL_RUN.match(kernel_em_uso or "")
    r = {"em_uso": kernel_em_uso or "", "antigos": [], "novos": [], "registros_antigos": 0, "reiniciar": False}
    if not m:
        return r
    ver, flavor = m.group(1), m.group(2)
    for nome, n in contagens.items():
        k = KERNEL_PKG.match(nome)
        if not k or k.group(3) != flavor:
            continue
        c = vercmp(k.group(2), ver)
        if c < 0:
            r["antigos"].append(nome)
            r["registros_antigos"] += n
        elif c > 0 and k.group(1) == "image":
            r["novos"].append(nome)
    r["reiniciar"] = bool(r["novos"])
    return r


def kernels_resumo(ix, lista_servidores):
    corpo = {"size": 0, "query": {"bool": {"filter": [{"bool": {"minimum_should_match": 1, "should": [
        {"prefix": {F_PKG: "linux-image-"}}, {"prefix": {F_PKG: "linux-modules-"}}, {"prefix": {F_PKG: "linux-headers-"}}]}}]}},
        "aggs": {"a": {"terms": {"field": F_AGENTE, "size": 3000}, "aggs": {"p": {"terms": {"field": F_PKG, "size": 300}}}}}}
    kern = {s["nome"]: s["kernel"] for s in lista_servidores}
    reiniciar, antigos, total = [], [], 0
    for b in ix.buscar(corpo).get("aggregations", {}).get("a", {}).get("buckets", []):
        a = analisar_kernels(kern.get(b["key"], ""), {x["key"]: x["doc_count"] for x in b["p"]["buckets"]})
        if a["reiniciar"]:
            reiniciar.append({"nome": b["key"], "em_uso": a["em_uso"], "novo": max(a["novos"])})
        if a["registros_antigos"]:
            antigos.append({"nome": b["key"], "em_uso": a["em_uso"], "registros": a["registros_antigos"], "pacotes": len(a["antigos"])})
            total += a["registros_antigos"]
    antigos.sort(key=lambda x: -x["registros"])
    return {"reiniciar": reiniciar, "antigos": antigos[:15], "servidores_antigos": len(antigos), "registros_antigos": total}


# ---------------------------------------------------------------- consultas
def servidores(ix, status=None):
    corpo = {"size": 0, "aggs": {"a": {"terms": {"field": F_AGENTE, "size": 2000}, "aggs": {
        "sev": {"terms": {"field": F_SEV, "size": 10}},
        "info": {"top_hits": {"size": 1, "_source": ["agent.id", "host.os.full", "host.os.platform", "host.os.kernel"]}}}}}}
    lista = []
    for b in ix.buscar(corpo)["aggregations"]["a"]["buckets"]:
        src = (b["info"]["hits"]["hits"] or [{"_source": {}}])[0]["_source"]
        so = src.get("host", {}).get("os", {})
        c = contar(b["sev"]["buckets"])
        st = (status or {}).get(b["key"], {})
        lista.append({"nome": b["key"], "id": src.get("agent", {}).get("id", ""), "so": so.get("full", ""),
                      "plataforma": so.get("platform", ""), "kernel": so.get("kernel", ""),
                      "tipo": tipo_maquina(so.get("full", ""), so.get("platform", "")),
                      "agente": st.get("status", ""), "visto": st.get("visto", ""), **c})
    lista.sort(key=lambda x: (-x["Critical"], -x["High"], -x["Medium"], x["nome"].lower()))
    return lista


def _por_tipo(lista):
    t = {}
    for s in lista:
        d = t.setdefault(s["tipo"], {"servidores": 0, "com_critica": 0, **{k: 0 for k in SEVS}})
        d["servidores"] += 1
        d["com_critica"] += 1 if s["Critical"] else 0
        for k in SEVS:
            d[k] += s[k]
    return t


def resumo(ix, lista_servidores, enr=None):
    kev_ids = enr.kev_ids() if enr else []
    aggs = {
        "sev": {"terms": {"field": F_SEV, "size": 10}},
        "cves": {"cardinality": {"field": F_CVE, "precision_threshold": 40000}},
        "so": {"terms": {"field": F_PLAT, "size": 10}, "aggs": {
            "sev": {"terms": {"field": F_SEV, "size": 10}}, "ag": {"cardinality": {"field": F_AGENTE}}}},
        "pacotes": {"filter": {"terms": {F_SEV: ["Critical", "High", "Medium"]}}, "aggs": {
            "p": {"terms": {"field": F_PKG, "size": 12}, "aggs": {"ag": {"cardinality": {"field": F_AGENTE}}}}}},
        "crit": {"filter": {"term": {F_SEV: "Critical"}}, "aggs": {
            "c": {"terms": {"field": F_CVE, "size": 10}, "aggs": {"ag": {"cardinality": {"field": F_AGENTE}}}}}},
        "sem": {"filter": {"prefix": {F_COND: "Package default status"}}},
        "corr": {"filter": {"bool": {"filter": [{"prefix": {F_COND: "Package less than "}}],
                                     "must_not": [{"prefix": {F_COND: "Package less than or equal"}}]}}},
        "ano": {"date_histogram": {"field": "vulnerability.published_at", "calendar_interval": "year", "format": "yyyy",
                                   "min_doc_count": 1}, "aggs": {"sev": {"terms": {"field": F_SEV, "size": 10}}}}}
    if kev_ids:
        aggs["kev"] = {"filter": {"terms": {F_CVE: kev_ids}}, "aggs": {
            "cves": {"cardinality": {"field": F_CVE}}, "ag": {"cardinality": {"field": F_AGENTE}},
            "sev": {"terms": {"field": F_SEV, "size": 10}},
            "top": {"terms": {"field": F_CVE, "size": 12}, "aggs": {"ag": {"cardinality": {"field": F_AGENTE}}}},
            "top_ag": {"terms": {"field": F_AGENTE, "size": 8}}}}
    r = ix.buscar({"size": 0, "track_total_hits": True, "aggs": aggs})
    a = r["aggregations"]
    kev = {"cves": 0, "registros": 0, "servidores": 0, "top": [], "servidores_top": [], "gravidade": contar([])}
    if "kev" in a:
        k = a["kev"]
        kev = {"cves": k["cves"]["value"], "registros": k["doc_count"], "servidores": k["ag"]["value"],
               "gravidade": contar(k["sev"]["buckets"]),
               "top": [{"cve": b["key"], "servidores": b["ag"]["value"], "registros": b["doc_count"]} for b in k["top"]["buckets"]],
               "servidores_top": [{"nome": b["key"], "registros": b["doc_count"]} for b in k["top_ag"]["buckets"]]}
        for t in kev["top"]:
            info = enr.info(t["cve"])
            t["nome"] = (info["kev"] or {}).get("nome", "")
            t["epss"] = info["epss"]
            t["ransomware"] = bool((info["kev"] or {}).get("ransomware"))
    por_ano = []
    for b in a.get("ano", {}).get("buckets", []):
        por_ano.append({"ano": b["key_as_string"], "n": b["doc_count"], **contar(b["sev"]["buckets"])})
    criticas = [{"cve": b["key"], "n": b["doc_count"], "servidores": b["ag"]["value"]} for b in a["crit"]["c"]["buckets"]]
    for c in criticas:
        if enr:
            info = enr.info(c["cve"])
            c["kev"], c["epss"] = bool(info["kev"]), info["epss"]
    ativos = sum(1 for s in lista_servidores if s.get("agente") == "active")
    desc = sum(1 for s in lista_servidores if s.get("agente") not in ("active", ""))
    return {
        "gravidade": contar(a["sev"]["buckets"]), "total": r["hits"]["total"]["value"], "cves_distintas": a["cves"]["value"],
        "servidores": len(lista_servidores),
        "com_critica": sum(1 for s in lista_servidores if s["Critical"]),
        "sem_correcao": a["sem"]["doc_count"], "com_correcao": a["corr"]["doc_count"],
        "por_so": [{"so": b["key"], "servidores": b["ag"]["value"], **contar(b["sev"]["buckets"])} for b in a["so"]["buckets"]],
        "pacotes": [{"nome": b["key"], "n": b["doc_count"], "servidores": b["ag"]["value"]} for b in a["pacotes"]["p"]["buckets"]],
        "criticas": criticas, "kev": kev, "por_ano": por_ano, "tipos": _por_tipo(lista_servidores),
        "agentes": {"ativos": ativos, "desconectados": desc, "conhecido": ativos + desc > 0},
        "top_servidores": [{k: s[k] for k in ("nome", "so", "tipo", "Critical", "High", "Medium", "Low", "total")}
                           for s in lista_servidores[:10]],
    }


def criticas_chaves(ix):
    """Conjunto 'CVE|servidor' das CVEs criticas (para saber o que e novo). Ate 10.000 registros."""
    r = ix.buscar({"size": 10000, "_source": [F_CVE, F_AGENTE], "query": {"term": {F_SEV: "Critical"}}, "sort": [{F_CVE: "asc"}]})
    return {"%s|%s" % (h["_source"]["vulnerability"]["id"], h["_source"]["agent"]["name"]) for h in r["hits"]["hits"]}


def foto_diaria(resumo_, lista, kern=None):
    """Resumo compacto que vai para o historico (uma por dia)."""
    return {"t": int(time.time()), "grav": {k: resumo_["gravidade"][k] for k in SEVS}, "servidores": resumo_["servidores"],
            "com_critica": resumo_["com_critica"], "kev_cves": resumo_["kev"]["cves"], "kev_servidores": resumo_["kev"]["servidores"],
            "sem_correcao": resumo_["sem_correcao"], "com_correcao": resumo_["com_correcao"],
            "tipos": {t: {"servidores": d["servidores"], "Critical": d["Critical"], "High": d["High"], "Medium": d["Medium"]}
                      for t, d in resumo_["tipos"].items()},
            "reiniciar": len((kern or {}).get("reiniciar", [])), "registros_kernel_antigo": (kern or {}).get("registros_antigos", 0)}


def mudanca_periodo(serie, dias=7):
    """Compara a foto mais recente com a de ~`dias` dias antes (ou a mais antiga, se o historico for menor).
    -> dict com as duas contagens por gravidade e o total de criticas novas/corrigidas no intervalo, ou None sem 2 fotos."""
    fotos = [f for f in serie if f.get("dia") and f.get("grav")]
    if len(fotos) < 2:
        return None
    fim = fotos[-1]
    alvo = (datetime.strptime(fim["dia"], "%Y-%m-%d") - timedelta(days=dias)).strftime("%Y-%m-%d")
    ini = next((f for f in reversed(fotos[:-1]) if f["dia"] <= alvo), fotos[0])
    if ini is fim:
        return None
    entre = [f for f in fotos if ini["dia"] < f["dia"] <= fim["dia"]]
    return {"de": ini["dia"], "ate": fim["dia"], "dias": (datetime.strptime(fim["dia"], "%Y-%m-%d") - datetime.strptime(ini["dia"], "%Y-%m-%d")).days,
            "grav_ini": {k: ini["grav"].get(k, 0) for k in SEVS}, "grav_fim": {k: fim["grav"].get(k, 0) for k in SEVS},
            "novas": sum(f.get("novas", 0) for f in entre), "corrigidas": sum(f.get("corrigidas", 0) for f in entre)}


def pacotes(ix, enr=None, nomes=None, limite=400):
    """Um pacote/programa por linha, somando todos os servidores (ou so os de `nomes`): mostra onde um unico patch
    resolve mais."""
    q1 = {"terms": {F_SEV: ["Critical", "High", "Medium"]}}
    if nomes:
        q1 = {"bool": {"filter": [q1, {"terms": {F_AGENTE: list(nomes)}}]}}
    r = ix.buscar({"size": 0, "query": q1, "aggs": {"p": {
        "terms": {"field": F_PKG, "size": 2500}, "aggs": {"sev": {"terms": {"field": F_SEV, "size": 10}},
                                                          "ag": {"cardinality": {"field": F_AGENTE}},
                                                          "tipo": {"terms": {"field": F_TIPO, "size": 1}}}}}})
    lista = []
    for b in r["aggregations"]["p"]["buckets"]:
        sev = contar(b["sev"]["buckets"])
        tipo = (b["tipo"]["buckets"] or [{"key": ""}])[0]["key"]
        lista.append({"nome": b["key"], "tipo": tipo, "gerenciador": gerenciador(tipo), "servidores": b["ag"]["value"],
                      "n": b["doc_count"], "sev": {k: sev[k] for k in SEVS}})
    lista.sort(key=lambda x: (-x["sev"]["Critical"], -x["sev"]["High"], -x["sev"]["Medium"], x["nome"].lower()))
    lista = lista[:limite]
    if lista:  # versao a instalar e CVEs exploradas, so para os primeiros
        sub = {"cond": {"terms": {"field": F_COND, "size": 100}}}
        kev_ids = enr.kev_ids() if enr else []
        if kev_ids:
            sub["kev"] = {"filter": {"terms": {F_CVE: kev_ids}}}
        q2 = {"terms": {F_PKG: [p["nome"] for p in lista]}}
        if nomes:
            q2 = {"bool": {"filter": [q2, {"terms": {F_AGENTE: list(nomes)}}]}}
        r2 = ix.buscar({"size": 0, "query": q2, "aggs": {"p": {
            "terms": {"field": F_PKG, "size": max(limite, 10), "include": [p["nome"] for p in lista]}, "aggs": sub}}})
        extra = {}
        for b in r2["aggregations"]["p"]["buckets"]:
            fix = maior_versao([parse_cond(c["key"])[1] for c in b["cond"]["buckets"] if parse_cond(c["key"])[0] == "corrigido"])
            extra[b["key"]] = (fix, b.get("kev", {}).get("doc_count", 0))
        for p in lista:
            p["corrigir_para"], p["kev"] = extra.get(p["nome"], (None, 0))
    return lista


GRUPOS_FIXOS = {"todos": "Todas as máquinas", "tipo:Servidor": "Servidores", "tipo:Estação": "Estações de trabalho",
                "criticos": "Máquinas com vulnerabilidade crítica"}


def resolver_grupo(grupo, lista):
    """-> (titulo, [nomes]) ou None se o grupo nao existe. Grupos: todos, tipo:Servidor, tipo:Estação, so:<plataforma>, criticos."""
    if grupo == "todos":
        return GRUPOS_FIXOS[grupo], [s["nome"] for s in lista]
    if grupo in ("tipo:Servidor", "tipo:Estação"):
        t = grupo.split(":", 1)[1]
        return GRUPOS_FIXOS[grupo], [s["nome"] for s in lista if s["tipo"] == t]
    if grupo.startswith("so:") and re.match(r"^so:[a-z0-9._-]{1,30}$", grupo):
        pl = grupo[3:]
        return "Sistema: %s" % pl, [s["nome"] for s in lista if s["plataforma"] == pl]
    if grupo == "criticos":
        return GRUPOS_FIXOS[grupo], [s["nome"] for s in lista if s["Critical"] > 0]
    return None


def relatorio(ix, lista, nomes, titulo="", enr=None, detalhe=None, max_detalhe=8):
    """Dados de um relatorio para UM servidor, uma selecao ou um grupo. Ate `max_detalhe` maquinas ganham uma secao propria
    com o plano de correcao; acima disso, so o resumo, a tabela por maquina e os pacotes que mais resolvem."""
    pedidos = list(dict.fromkeys(nomes))
    por_nome = {s["nome"]: s for s in lista}
    sel = [por_nome[n] for n in pedidos if n in por_nome]
    nao = [n for n in pedidos if n not in por_nome]
    base = {"escopo": {"titulo": titulo or (sel[0]["nome"] if len(sel) == 1 else "%d máquinas" % len(sel)),
                       "nomes": [s["nome"] for s in sel], "nao_encontrados": nao}}
    if not sel:
        return base
    nm = [s["nome"] for s in sel]
    kev_ids = enr.kev_ids() if enr else []
    aggs = {"sev": {"terms": {"field": F_SEV, "size": 10}}, "sem": {"filter": {"prefix": {F_COND: "Package default status"}}},
            "corr": {"filter": {"bool": {"filter": [{"prefix": {F_COND: "Package less than "}}],
                                         "must_not": [{"prefix": {F_COND: "Package less than or equal"}}]}}}}
    if kev_ids:
        aggs["kev"] = {"filter": {"terms": {F_CVE: kev_ids}}, "aggs": {
            "cves": {"cardinality": {"field": F_CVE}}, "ag": {"cardinality": {"field": F_AGENTE}},
            "top": {"terms": {"field": F_CVE, "size": 15}, "aggs": {"ag": {"cardinality": {"field": F_AGENTE}}}}}}
    r = ix.buscar({"size": 0, "track_total_hits": True, "query": {"terms": {F_AGENTE: nm}}, "aggs": aggs})
    a = r["aggregations"]
    kev = {"cves": 0, "registros": 0, "servidores": 0, "top": []}
    if "kev" in a:
        k = a["kev"]
        kev = {"cves": k["cves"]["value"], "registros": k["doc_count"], "servidores": k["ag"]["value"],
               "top": [{"cve": b["key"], "servidores": b["ag"]["value"], "registros": b["doc_count"]} for b in k["top"]["buckets"]]}
        for t in kev["top"]:
            info = enr.info(t["cve"])
            t["nome"] = (info["kev"] or {}).get("nome", "")
            t["epss"] = info["epss"]
            t["ransomware"] = bool((info["kev"] or {}).get("ransomware"))
    detalhes = []
    if detalhe and len(sel) <= max_detalhe:
        for n in nm:
            d = detalhe(n)
            if d:
                detalhes.append({"info": d["info"], "pacotes": d["pacotes"][:15], "exploradas": d["exploradas"][:20], "plano": d["plano"],
                                 "kernels": d["kernels"], "gravidade": {k: sum(p["sev"][k] for p in d["pacotes"]) for k in SEVS}})
    tabela = [{k: s[k] for k in ("nome", "tipo", "so", "agente", "Critical", "High", "Medium", "Low", "total")} for s in sel]
    base.update({"gravidade": contar(a["sev"]["buckets"]), "total": r["hits"]["total"]["value"], "servidores": len(sel),
                 "com_critica": sum(1 for s in sel if s["Critical"]), "sem_correcao": a["sem"]["doc_count"],
                 "com_correcao": a["corr"]["doc_count"], "kev": kev, "tipos": _por_tipo(sel), "tabela": tabela,
                 "pacotes": pacotes(ix, enr, nm, 15), "detalhes": detalhes})
    return base


def pacote_detalhe(ix, nome):
    r = ix.buscar({"size": 0, "query": {"term": {F_PKG: nome}}, "aggs": {"a": {"terms": {"field": F_AGENTE, "size": 500}, "aggs": {
        "sev": {"terms": {"field": F_SEV, "size": 10}}, "ver": {"terms": {"field": F_VER, "size": 3}},
        "cond": {"terms": {"field": F_COND, "size": 100}}}}}})
    out = []
    for b in r["aggregations"]["a"]["buckets"]:
        sev = contar(b["sev"]["buckets"])
        fix = maior_versao([parse_cond(c["key"])[1] for c in b["cond"]["buckets"] if parse_cond(c["key"])[0] == "corrigido"])
        out.append({"nome": b["key"], "instalada": ", ".join(x["key"] for x in b["ver"]["buckets"]), "n": b["doc_count"],
                    "sev": {k: sev[k] for k in SEVS}, "corrigir_para": fix})
    out.sort(key=lambda x: (-x["sev"]["Critical"], -x["sev"]["High"], -x["sev"]["Medium"], x["nome"].lower()))
    return out


def servidor(ix, nome, enr=None):
    """Pacotes/programas do servidor, ja agregados por pacote, com a versao a instalar."""
    kev_ids = enr.kev_ids() if enr else []
    sub = {"tipo": {"terms": {"field": F_TIPO, "size": 1}}, "ver": {"terms": {"field": F_VER, "size": 3}},
           "sev": {"terms": {"field": F_SEV, "size": 10}}, "nota": {"max": {"field": F_NOTA}},
           "cond": {"terms": {"field": F_COND, "size": 300}}}
    if kev_ids:
        sub["kev"] = {"filter": {"terms": {F_CVE: kev_ids}}}
    corpo = {"size": 1, "_source": ["agent.id", "host.os.full", "host.os.platform", "host.os.kernel"],
             "track_total_hits": True, "query": {"term": {F_AGENTE: nome}},
             "aggs": {"pk": {"terms": {"field": F_PKG, "size": 5000}, "aggs": sub}}}
    r = ix.buscar(corpo)
    if not r["hits"]["hits"]:
        return None
    src = r["hits"]["hits"][0]["_source"]
    so = src.get("host", {}).get("os", {})
    pacotes_ = []
    for b in r["aggregations"]["pk"]["buckets"]:
        sev = contar(b["sev"]["buckets"])
        corrigidos, ate, sem = [], 0, 0
        for c in b["cond"]["buckets"]:
            tipo, ver = parse_cond(c["key"])
            if tipo == "corrigido":
                corrigidos.append(ver)
            elif tipo == "ate":
                ate += c["doc_count"]
            elif tipo == "sem":
                sem += c["doc_count"]
        tipo_pkg = (b["tipo"]["buckets"] or [{"key": ""}])[0]["key"]
        sev_max = next((s for s in SEVS if sev[s]), "Outra")
        pacotes_.append({
            "nome": b["key"], "tipo": tipo_pkg, "gerenciador": gerenciador(tipo_pkg),
            "instalada": ", ".join(x["key"] for x in b["ver"]["buckets"]), "n": b["doc_count"], "sev": {k: sev[k] for k in SEVS},
            "sev_max": sev_max, "nota": round(b["nota"]["value"] or 0, 1), "corrigir_para": maior_versao(corrigidos),
            "com_correcao": sum(c["doc_count"] for c in b["cond"]["buckets"] if parse_cond(c["key"])[0] == "corrigido"),
            "ate": ate, "sem_correcao": sem, "kev": b.get("kev", {}).get("doc_count", 0),
            "reinicia": bool(REINICIA.match(b["key"])) or tipo_pkg == "windows"})
    pacotes_.sort(key=lambda p: (0 if p["kev"] else 1, RANK[p["sev_max"]], -p["nota"], -p["n"], p["nome"].lower()))
    info = {"nome": nome, "id": src.get("agent", {}).get("id", ""), "so": so.get("full", ""),
            "plataforma": so.get("platform", ""), "kernel": so.get("kernel", ""), "total": r["hits"]["total"]["value"],
            "tipo": tipo_maquina(so.get("full", ""), so.get("platform", ""))}
    kern = analisar_kernels(info["kernel"], {p["nome"]: p["n"] for p in pacotes_ if p["nome"].startswith("linux-")})
    for p in pacotes_:
        p["kernel"] = "antigo" if p["nome"] in kern["antigos"] else ("novo" if p["nome"] in kern["novos"] else "")
    exploradas = []
    if kev_ids:
        rr = ix.buscar({"size": 100, "_source": FONTE, "query": {"bool": {"filter": [{"term": {F_AGENTE: nome}}, {"terms": {F_CVE: kev_ids}}]}},
                        "sort": [{F_NOTA: {"order": "desc", "unmapped_type": "float"}}, {F_CVE: "asc"}]})
        exploradas = enriquecer([_linha(h) for h in rr["hits"]["hits"]], enr)
    n_kev = sum(p["kev"] for p in pacotes_)
    return {"info": info, "pacotes": pacotes_, "plano": plano(info, pacotes_, kern, n_kev), "kernels": kern, "exploradas": exploradas}


def enriquecer(linhas, enr):
    for l in linhas:
        i = enr.info(l["cve"]) if enr else {"kev": None, "epss": None, "epss_pct": None}
        l["kev"] = bool(i["kev"])
        l["kev_prazo"] = (i["kev"] or {}).get("prazo", "")
        l["ransomware"] = bool((i["kev"] or {}).get("ransomware"))
        l["epss"] = round(i["epss"], 4) if i["epss"] is not None else None
    return linhas


def _quote_pkgs(nomes):
    return [n for n in nomes if PKG_SEGURO.match(n)]


def plano(info, pacotes, kern=None, n_kev=0):
    """Checklist 'antes de corrigir' + comandos para copiar. Nunca executa nada."""
    kern = kern or {"antigos": [], "novos": [], "registros_antigos": 0, "reiniciar": False}
    a_corrigir = [p for p in pacotes if p["corrigir_para"]]
    ger = {p["gerenciador"] for p in pacotes}
    nomes = [p["nome"] for p in pacotes]
    reinicia = [p["nome"] for p in a_corrigir if p["reinicia"]]
    antes = [
        {"t": "Snapshot ou backup", "d": "Tire um snapshot da máquina (Proxmox, VMware, Nutanix ou da nuvem) ou confirme o backup mais recente. "
                                         "É isso que permite voltar atrás se uma atualização quebrar algo."},
        {"t": "Janela de manutenção", "d": "Avise quem usa o serviço e escolha um horário de pouco uso."},
        {"t": "Teste antes", "d": "Se houver cópia de homologação, aplique lá primeiro. Se não houver, comece pelo servidor menos "
                                  "crítico do mesmo tipo."},
    ]
    if any(BANCO.search(n) for n in nomes):
        antes.append({"t": "Banco de dados", "d": "Há pacotes de banco de dados. Faça o dump antes (ex.: mysqldump ou pg_dump) e "
                                                   "confira o serviço depois da atualização."})
    if any(CONTEINER.match(n) for n in nomes):
        antes.append({"t": "Contêineres", "d": "Atualizar o Docker/containerd pode reiniciar os contêineres. Anote o `docker ps` "
                                               "e confira a política de reinício deles."})
    if any(WEB.match(n) for n in nomes):
        antes.append({"t": "Serviço web", "d": "O servidor web será reiniciado durante a atualização: haverá uma queda curta."})
    if reinicia or kern["reiniciar"]:
        extra = " Já existe um kernel mais novo instalado (%s): basta reiniciar para ativá-lo." % max(kern["novos"]) if kern["reiniciar"] else ""
        lista = ", ".join(reinicia[:6]) + (" e outros" if len(reinicia) > 6 else "")
        antes.append({"t": "Reinício necessário", "d": ("Entre as correções há kernel, glibc, systemd ou o próprio Windows (%s). "
                                                          "Sem reiniciar, a versão antiga continua em uso e a falha continua aberta." % lista if reinicia else
                                                          "Há atualização que só vale depois de reiniciar.") + extra})
    passos = []
    if "apt" in ger:
        seguros = _quote_pkgs([p["nome"] for p in a_corrigir if p["gerenciador"] == "apt"])
        passos += [{"t": "Atualizar a lista de pacotes", "c": "sudo apt update"},
                   {"t": "Ver o que será atualizado", "c": "apt list --upgradable"},
                   {"t": "Atualizar tudo (recomendado)", "c": "sudo apt upgrade -y"}]
        if seguros:
            passos.append({"t": "Ou só os pacotes com falha (os %d mais graves)" % min(len(seguros), 25),
                           "c": "sudo apt install --only-upgrade " + " ".join(seguros[:25])})
    if "dnf" in ger:
        seguros = _quote_pkgs([p["nome"] for p in a_corrigir if p["gerenciador"] == "dnf"])
        passos += [{"t": "Atualizar a lista de pacotes", "c": "sudo dnf makecache"},
                   {"t": "Aplicar só as correções de segurança (recomendado)", "c": "sudo dnf upgrade --security -y"}]
        if seguros:
            passos.append({"t": "Ou só os pacotes com falha (os %d mais graves)" % min(len(seguros), 25),
                           "c": "sudo dnf upgrade " + " ".join(seguros[:25])})
    if "snap" in ger:
        passos.append({"t": "Snaps", "c": "sudo snap refresh"})
    if (reinicia or kern["reiniciar"]) and ger & {"apt", "dnf"}:
        passos.append({"t": "Reiniciar (kernel/glibc/systemd na lista)", "c": "sudo reboot"})
    if kern["antigos"] and "apt" in ger:
        passos.append({"t": "DEPOIS de reiniciar: remover kernels antigos que não estão em uso (somem %d registros de CVE)" % kern["registros_antigos"],
                       "c": "sudo apt autoremove --purge -y"})
    if ger & {"apt", "dnf"}:
        passos.append({"t": "Depois: reinventariar no Wazuh sem esperar a hora cheia", "c": "sudo systemctl restart wazuh-agent"})
    notas = []
    if n_kev:
        notas.append("🔥 %d registro(s) deste servidor estão na lista da CISA de vulnerabilidades JÁ EXPLORADAS na prática. "
                     "Corrija primeiro os pacotes marcados com 🔥." % n_kev)
    if kern["antigos"] and "apt" not in ger:
        notas.append("Há kernels antigos instalados que não estão em uso: remova-os para reduzir os registros de CVE.")
    so = [p for p in pacotes if p["gerenciador"] == "windows-so"]
    if so:
        alvo = maior_versao([p["corrigir_para"] for p in so if p["corrigir_para"]])
        notas.append("Windows: instale as atualizações cumulativas (Windows Update ou WSUS/GPO) até a compilação %s ou mais nova%s. "
                     "Reinicie ao terminar." % (alvo or "mais recente", "" if alvo else " (o Wazuh não informou a versão alvo)"))
    prog = [p for p in pacotes if p["gerenciador"] == "windows-prog" and p["corrigir_para"]]
    if prog:
        notas.append("Programas do Windows (%d com versão corrigida): atualize pelo instalador do fabricante ou, quando houver, "
                     "com `winget upgrade` no PowerShell. Veja a coluna “Atualizar para”." % len(prog))
    sem = sum(p["sem_correcao"] for p in pacotes)
    if sem:
        notas.append("%d registros estão “sem correção publicada”: não há o que instalar agora. Reavalie quando o fabricante lançar "
                     "o patch, ou reduza o risco (desligar o serviço, fechar a porta, restringir o acesso)." % sem)
    if not a_corrigir and not passos and not notas:
        notas.append("Nenhuma correção com versão conhecida para este servidor.")
    return {"antes": antes, "passos": passos, "notas": notas, "reinicia": bool(reinicia or kern["reiniciar"])}


def _filtros(sevs, servidor_nome, q, corrigivel, kev_ids=None):
    f = []
    sv = [s for s in (sevs or []) if s in SEVS]
    if sv and len(sv) < len(SEVS):
        vals = [s for s in sv if s != "Outra"] + (["-", "None"] if "Outra" in sv else [])
        f.append({"terms": {F_SEV: vals}})
    if servidor_nome:
        f.append({"term": {F_AGENTE: servidor_nome}})
    if corrigivel:
        f.append({"prefix": {F_COND: "Package less than "}})
    if kev_ids is not None:  # so as exploradas ativamente (lista vazia = nenhuma)
        f.append({"terms": {F_CVE: kev_ids or ["CVE-0000-0000"]}})
    must_not = [{"prefix": {F_COND: "Package less than or equal"}}] if corrigivel else []
    if q:
        esc = re.sub(r"([\\*?])", r"\\\1", q.strip())[:80]
        f.append({"bool": {"minimum_should_match": 1, "should": [
            {"term": {F_CVE: q.strip().upper()}},
            {"wildcard": {F_PKG: {"value": "*%s*" % esc, "case_insensitive": True}}}]}})
    return {"bool": {"filter": f, "must_not": must_not}}


def _linha(h):
    s = h["_source"]
    v, p, ag = s.get("vulnerability", {}), s.get("package", {}), s.get("agent", {})
    tipo, ver = parse_cond(v.get("scanner", {}).get("condition"))
    return {"cve": v.get("id", ""), "sev": norm_sev(v.get("severity")), "nota": v.get("score", {}).get("base"),
            "servidor": ag.get("name", ""), "pacote": p.get("name", ""), "instalada": p.get("version", ""),
            "corrigir_para": ver if tipo == "corrigido" else None, "situacao": tipo,
            "publicada": (v.get("published_at") or "")[:10], "ref": v.get("reference", "")}


FONTE = ["vulnerability.id", "vulnerability.severity", "vulnerability.score.base", "vulnerability.published_at",
         "vulnerability.reference", "vulnerability.scanner.condition", "agent.name", "package.name", "package.version"]
ORDEM = [{F_NOTA: {"order": "desc", "unmapped_type": "float"}}, {F_CVE: "asc"}, {F_AGENTE: "asc"}]


def vulnerabilidades(ix, sevs, servidor_nome="", q="", corrigivel=False, pagina=0, tam=100, exploradas=False, enr=None):
    pagina = max(0, min(int(pagina), 9999 // tam))
    kev = (enr.kev_ids() if enr else []) if exploradas else None
    corpo = {"size": tam, "from": pagina * tam, "track_total_hits": True, "_source": FONTE,
             "query": _filtros(sevs, servidor_nome, q, corrigivel, kev), "sort": ORDEM}
    r = ix.buscar(corpo)
    total = r["hits"]["total"]["value"]
    return {"total": total, "pagina": pagina, "tam": tam, "limite": min(total, 10000),
            "itens": enriquecer([_linha(h) for h in r["hits"]["hits"]], enr)}


def vulnerabilidades_csv(ix, sevs, servidor_nome="", q="", corrigivel=False, exploradas=False, enr=None):
    kev = (enr.kev_ids() if enr else []) if exploradas else None
    r = ix.buscar({"size": 10000, "track_total_hits": True, "_source": FONTE,
                   "query": _filtros(sevs, servidor_nome, q, corrigivel, kev), "sort": ORDEM})
    return enriquecer([_linha(h) for h in r["hits"]["hits"]], enr)


def cves_do_pacote(ix, nome_servidor, pacote, enr=None):
    r = ix.buscar({"size": 500, "query": {"bool": {"filter": [{"term": {F_AGENTE: nome_servidor}}, {"term": {F_PKG: pacote}}]}},
                   "sort": [{F_NOTA: {"order": "desc", "unmapped_type": "float"}}, {F_CVE: "asc"}],
                   "_source": FONTE + ["vulnerability.description"]})
    itens = []
    for h in r["hits"]["hits"]:
        d = _linha(h)
        d["descricao"] = (h["_source"].get("vulnerability", {}).get("description") or "")[:400]
        itens.append(d)
    return enriquecer(itens, enr)


def csv_texto(cabecalho, linhas):
    """CSV com BOM (abre com acentos no Excel). Celulas que comecam com = + - @ ganham um apostrofo (formula injection)."""
    def cel(v):
        s = "" if v is None else str(v)
        if s[:1] in ("=", "+", "@") or (s[:1] == "-" and not re.match(r"^-?\d", s)):
            s = "'" + s
        return '"' + s.replace('"', '""') + '"'
    return "﻿" + "\r\n".join(";".join(cel(c) for c in l) for l in [cabecalho] + linhas) + "\r\n"
