"""Enriquecimento das CVEs com duas listas PUBLICAS e gratuitas:

* KEV (CISA, Known Exploited Vulnerabilities): CVEs que ja estao sendo exploradas de verdade.
* EPSS (FIRST): probabilidade (0 a 1) de a CVE ser explorada nos proximos 30 dias.

Baixa uma vez por dia e guarda em disco (se o servidor ficar sem internet, usa a ultima copia). Nada daqui e enviado
para fora: so baixamos as listas.
"""
import gzip
import io
import json
import os
import re
import threading
import time
import urllib.request

URL_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
URL_EPSS = "https://epss.cyentia.com/epss_scores-current.csv.gz"
LIMITE_KEV = 30 * 1024 * 1024
LIMITE_EPSS = 60 * 1024 * 1024
LIMITE_EPSS_DESCOMPRIMIDO = 250 * 1024 * 1024
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,10}$")


def baixar(url, limite, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "backdraft/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        dado = r.read(limite + 1)
    if len(dado) > limite:
        raise ValueError("arquivo maior que o limite (%d bytes)" % limite)
    return dado


def parse_kev(dado):
    """-> ({cve: info}, versao_do_catalogo)."""
    j = json.loads(dado)
    out = {}
    for v in j.get("vulnerabilities", []):
        cid = v.get("cveID")
        if isinstance(cid, str) and CVE_RE.match(cid):
            out[cid] = {"nome": str(v.get("vulnerabilityName", ""))[:160], "vendor": str(v.get("vendorProject", ""))[:80],
                        "produto": str(v.get("product", ""))[:80], "adicionada": str(v.get("dateAdded", ""))[:10],
                        "prazo": str(v.get("dueDate", ""))[:10], "ransomware": v.get("knownRansomwareCampaignUse") == "Known"}
    return out, str(j.get("catalogVersion", ""))[:40]


def parse_epss(dado):
    """-> ({cve: (score, percentil)}, data_do_modelo). O CSV comeca com uma linha '#model_version:...,score_date:...'."""
    bruto = gzip.GzipFile(fileobj=io.BytesIO(dado)).read(LIMITE_EPSS_DESCOMPRIMIDO + 1)
    if len(bruto) > LIMITE_EPSS_DESCOMPRIMIDO:
        raise ValueError("EPSS descomprimido grande demais")
    out, data = {}, ""
    for linha in bruto.decode("utf-8", "replace").splitlines():
        if linha.startswith("#"):
            m = re.search(r"score_date:([0-9T:\-\.Z]+)", linha)
            data = m.group(1)[:10] if m else data
            continue
        partes = linha.split(",")
        if len(partes) >= 3 and CVE_RE.match(partes[0]):
            try:
                out[partes[0]] = (float(partes[1]), float(partes[2]))
            except ValueError:
                pass
    return out, data


def _gravar(caminho, dado):
    tmp = caminho + ".tmp"
    with open(tmp, "wb") as f:
        f.write(dado)
    os.replace(tmp, caminho)


class Enriquecimento:
    def __init__(self, pasta="", baixar_fn=baixar):
        self.pasta, self.baixar, self._l = pasta, baixar_fn, threading.Lock()
        self.kev, self.epss = {}, {}
        self.kev_data = self.epss_data = ""
        self.atualizado_em = 0
        self.erro = ""
        self._carregar_cache()

    # ---- cache em disco
    def _arq(self, nome):
        return os.path.join(self.pasta, nome) if self.pasta else ""

    def _carregar_cache(self):
        for nome, fn in (("kev.json", self._aplicar_kev), ("epss.csv.gz", self._aplicar_epss)):
            arq = self._arq(nome)
            if arq and os.path.isfile(arq):
                try:
                    with open(arq, "rb") as f:
                        fn(f.read())
                    self.atualizado_em = max(self.atualizado_em, int(os.path.getmtime(arq)))
                except (OSError, ValueError):
                    pass

    def _aplicar_kev(self, dado):
        kev, versao = parse_kev(dado)
        if not kev:
            raise ValueError("catalogo KEV vazio")
        with self._l:
            self.kev, self.kev_data = kev, versao

    def _aplicar_epss(self, dado):
        epss, data = parse_epss(dado)
        if len(epss) < 1000:
            raise ValueError("EPSS com poucas linhas (%d)" % len(epss))
        with self._l:
            self.epss, self.epss_data = epss, data

    def atualizar(self):
        """Baixa as duas listas. Cada uma falha sozinha (a outra continua). Devolve os erros, se houver."""
        erros = []
        for nome, url, limite, fn in (("kev.json", URL_KEV, LIMITE_KEV, self._aplicar_kev),
                                      ("epss.csv.gz", URL_EPSS, LIMITE_EPSS, self._aplicar_epss)):
            try:
                dado = self.baixar(url, limite)
                fn(dado)  # valida ANTES de gravar: uma lista quebrada nunca substitui a boa
                if self.pasta:
                    _gravar(self._arq(nome), dado)
                self.atualizado_em = int(time.time())
            except Exception as e:  # rede, formato, disco
                erros.append("%s: %s" % (nome, str(e)[:120]))
        self.erro = "; ".join(erros)
        return erros

    # ---- consulta
    def kev_ids(self):
        with self._l:
            return sorted(self.kev)

    def info(self, cve):
        k = self.kev.get(cve)
        e = self.epss.get(cve)
        return {"kev": k, "epss": e[0] if e else None, "epss_pct": e[1] if e else None}

    def resumo(self):
        return {"kev_cves": len(self.kev), "kev_data": self.kev_data, "epss_cves": len(self.epss), "epss_data": self.epss_data,
                "atualizado_em": self.atualizado_em, "erro": self.erro}
