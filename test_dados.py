"""Testes da camada de dados (sem rede: o indexador e simulado)."""
import unittest

import dados as D
from enriquecimento import Enriquecimento


def bucket(chave, n, **sub):
    b = {"key": chave, "doc_count": n}
    b.update(sub)
    return b


def kev_fake():
    class E(Enriquecimento):
        def __init__(self):
            self.kev = {"CVE-2026-1": {"nome": "Falha do Firefox", "vendor": "Mozilla", "produto": "Firefox", "adicionada": "2026-10-01",
                                       "prazo": "2026-10-22", "ransomware": True}}
            self.epss = {"CVE-2026-1": (0.9712, 0.999), "CVE-2026-2": (0.004, 0.2)}
            self.kev_data = self.epss_data = "x"
            self.atualizado_em = 1
            self.erro = ""
            import threading
            self._l = threading.Lock()
    return E()


class FakeIx:
    """Devolve respostas fixas, no formato do OpenSearch, conforme as agregacoes pedidas."""

    def __init__(self):
        self.pedidos = []
        self.criticas = ["CVE-2026-1|srv-a", "CVE-2026-2|srv-a"]
        self.monitoramento = True

    def buscar(self, corpo, indice=None):
        self.pedidos.append((indice, corpo))
        aggs = corpo.get("aggs", {})
        if indice == D.INDICE_MON:
            if not self.monitoramento:
                raise OSError("403")
            return {"aggregations": {"a": {"buckets": [
                bucket("1", 3, u={"hits": {"hits": [{"_source": {"name": "srv-a", "status": "active", "lastKeepAlive": "2026-11-06T10:00:00+00:00"}}]}}),
                bucket("2", 3, u={"hits": {"hits": [{"_source": {"name": "srv-b", "status": "disconnected", "lastKeepAlive": "2026-10-01T10:00:00+00:00"}}]}})]}}}
        if "a" in aggs and "info" in aggs["a"].get("aggs", {}):  # servidores()
            return {"aggregations": {"a": {"buckets": [
                bucket("srv-b", 5, sev={"buckets": [bucket("High", 5)]},
                       info={"hits": {"hits": [{"_source": {"agent": {"id": "002"}, "host": {"os": {"full": "Windows 11 Pro", "platform": "windows", "kernel": ""}}}}]}}),
                bucket("srv-a", 9, sev={"buckets": [bucket("Critical", 2), bucket("Medium", 6), bucket("-", 1)]},
                       info={"hits": {"hits": [{"_source": {"agent": {"id": "001"}, "host": {"os": {"full": "Ubuntu 22.04", "platform": "ubuntu", "kernel": "5.15.0-110-generic"}}}}]}})]}}}
        if "a" in aggs and "p" in aggs["a"].get("aggs", {}) and "sev" not in aggs["a"]["aggs"]:  # kernels_resumo()
            return {"aggregations": {"a": {"buckets": [bucket("srv-a", 7, p={"buckets": [
                bucket("linux-image-5.15.0-100-generic", 4), bucket("linux-image-5.15.0-110-generic", 2), bucket("linux-image-5.15.0-120-generic", 1)]})]}}}
        if "a" in aggs and "ver" in aggs["a"].get("aggs", {}):  # pacote_detalhe()
            return {"aggregations": {"a": {"buckets": [bucket("srv-a", 3, sev={"buckets": [bucket("Critical", 3)]}, ver={"buckets": [bucket("1.0", 3)]},
                                                           cond={"buckets": [bucket("Package less than 2.0", 3)]})]}}}
        if "pk" in aggs:  # servidor()
            if corpo["query"]["term"][D.F_AGENTE] == "nao-existe":
                return {"hits": {"hits": [], "total": {"value": 0}}}
            return {"hits": {"total": {"value": 20}, "hits": [{"_source": {"agent": {"id": "001"}, "host": {"os": {"full": "Ubuntu 22.04", "platform": "ubuntu", "kernel": "5.15.0-110-generic"}}}}]},
                    "aggregations": {"pk": {"buckets": [
                        bucket("udev", 12, tipo={"buckets": [bucket("deb", 12)]}, ver={"buckets": [bucket("249.11-0ubuntu3", 12)]},
                               sev={"buckets": [bucket("Medium", 10), bucket("High", 2)]}, nota={"value": 7.8}, kev={"doc_count": 0},
                               cond={"buckets": [bucket("Package less than 249.11-0ubuntu3.19", 5), bucket("Package less than 249.11-0ubuntu3.21", 4),
                                                 bucket("Package less than 249.11-0ubuntu3.7", 2), bucket("Package default status", 1)]}),
                        bucket("x; rm -rf /", 3, tipo={"buckets": [bucket("deb", 3)]}, ver={"buckets": [bucket("1.0", 3)]},
                               sev={"buckets": [bucket("Critical", 3)]}, nota={"value": 9.8}, kev={"doc_count": 0},
                               cond={"buckets": [bucket("Package less than 2.0", 3)]}),
                        bucket("mysql-server", 5, tipo={"buckets": [bucket("deb", 5)]}, ver={"buckets": [bucket("8.0.36", 5)]},
                               sev={"buckets": [bucket("Low", 5)]}, nota={"value": 3.1}, kev={"doc_count": 0},
                               cond={"buckets": [bucket("Package default status", 5)]}),
                        bucket("firefox", 2, tipo={"buckets": [bucket("deb", 2)]}, ver={"buckets": [bucket("100.0", 2)]},
                               sev={"buckets": [bucket("Medium", 2)]}, nota={"value": 6.0}, kev={"doc_count": 2},
                               cond={"buckets": [bucket("Package less than 120.0", 2)]}),
                        bucket("linux-image-5.15.0-100-generic", 4, tipo={"buckets": [bucket("deb", 4)]}, ver={"buckets": [bucket("5.15.0-100", 4)]},
                               sev={"buckets": [bucket("High", 4)]}, nota={"value": 7.0}, kev={"doc_count": 0}, cond={"buckets": [bucket("Package less than 5.15.0-120", 4)]}),
                        bucket("linux-image-5.15.0-120-generic", 1, tipo={"buckets": [bucket("deb", 1)]}, ver={"buckets": [bucket("5.15.0-120", 1)]},
                               sev={"buckets": [bucket("Low", 1)]}, nota={"value": 3.0}, kev={"doc_count": 0}, cond={"buckets": [bucket("Package default status", 1)]})]}}}
        if "sev" in aggs and "sem" in aggs and "cves" not in aggs:  # relatorio(): agregado das maquinas escolhidas
            self.escopos = getattr(self, "escopos", []) + [corpo["query"]["terms"][D.F_AGENTE]]
            r = {"hits": {"total": {"value": 14}}, "aggregations": {"sev": {"buckets": [bucket("Critical", 2), bucket("High", 4), bucket("Medium", 8)]},
                                                                  "sem": {"doc_count": 3}, "corr": {"doc_count": 9}}}
            if "kev" in aggs:
                r["aggregations"]["kev"] = {"doc_count": 2, "cves": {"value": 1}, "ag": {"value": 1}, "top": {"buckets": [bucket("CVE-2026-1", 2, ag={"value": 1})]}}
            return r
        if "sev" in aggs and "cves" in aggs:  # resumo()
            r = {"hits": {"total": {"value": 20}}, "aggregations": {
                "sev": {"buckets": [bucket("Critical", 3), bucket("High", 2), bucket("-", 15)]}, "cves": {"value": 11},
                "so": {"buckets": [bucket("ubuntu", 20, sev={"buckets": [bucket("Critical", 3)]}, ag={"value": 2})]},
                "pacotes": {"p": {"buckets": [bucket("udev", 12, ag={"value": 2})]}},
                "crit": {"c": {"buckets": [bucket("CVE-2026-1", 3, ag={"value": 2})]}},
                "sem": {"doc_count": 4}, "corr": {"doc_count": 9},
                "ano": {"buckets": [{"key_as_string": "2025", "doc_count": 6, "sev": {"buckets": [bucket("High", 6)]}},
                                    {"key_as_string": "2026", "doc_count": 14, "sev": {"buckets": [bucket("Critical", 3), bucket("-", 11)]}}]}}}
            if "kev" in aggs:
                r["aggregations"]["kev"] = {"doc_count": 3, "cves": {"value": 1}, "ag": {"value": 2}, "sev": {"buckets": [bucket("Critical", 3)]},
                                            "top": {"buckets": [bucket("CVE-2026-1", 3, ag={"value": 2})]}, "top_ag": {"buckets": [bucket("srv-a", 3)]}}
            return r
        if "p" in aggs and "cond" in aggs["p"].get("aggs", {}):  # pacotes(), 2a consulta
            return {"aggregations": {"p": {"buckets": [bucket("firefox", 4, cond={"buckets": [bucket("Package less than 120.0", 3), bucket("Package less than 130.1", 1)]},
                                                         kev={"doc_count": 2})]}}}
        if "p" in aggs:  # pacotes(), 1a consulta
            return {"aggregations": {"p": {"buckets": [
                bucket("firefox", 4, sev={"buckets": [bucket("Critical", 2), bucket("High", 2)]}, ag={"value": 3}, tipo={"buckets": [bucket("win", 4)]}),
                bucket("zlib", 9, sev={"buckets": [bucket("Medium", 9)]}, ag={"value": 8}, tipo={"buckets": [bucket("deb", 9)]})]}}}
        if corpo.get("size") == 10000 and corpo.get("query", {}).get("term", {}).get(D.F_SEV) == "Critical":  # criticas_chaves()
            return {"hits": {"hits": [{"_source": {"vulnerability": {"id": k.split("|")[0]}, "agent": {"name": k.split("|")[1]}}} for k in self.criticas]}}
        if "bool" in corpo.get("query", {}) and any("terms" in f and D.F_CVE in f["terms"] for f in corpo["query"]["bool"].get("filter", [])):  # exploradas do servidor
            return {"hits": {"total": {"value": 1}, "hits": [{"_source": {"vulnerability": {"id": "CVE-2026-1", "severity": "Medium", "score": {"base": 6.0},
                                                                                           "scanner": {"condition": "Package less than 120.0"}},
                                                                          "agent": {"name": "srv-a"}, "package": {"name": "firefox", "version": "100.0"}}}]}}
        return {"hits": {"total": {"value": 0}, "hits": []}}


class TestVersoes(unittest.TestCase):
    def test_ordem(self):
        casos = [("249.11-0ubuntu3.19", "249.11-0ubuntu3.21", -1), ("249.11-0ubuntu3.21", "249.11-0ubuntu3.7", 1),
                 ("1:2.0-1", "9.9-1", 1), ("1.0~rc1", "1.0", -1), ("10.0.19045.6456", "10.0.19045.7807", -1),
                 ("4:1.55-457.module_el8.6.0+2766+8bf0b7ce", "3:1.49-2.el8", 1), ("2.0", "2.0", 0), ("1.10", "1.9", 1),
                 ("5.91.0", "6.23", -1), ("5.15.0-87", "5.15.0-202", -1)]
        for a, b, esperado in casos:
            self.assertEqual(D.vercmp(a, b), esperado, (a, b))
            self.assertEqual(D.vercmp(b, a), -esperado, (b, a))

    def test_maior(self):
        self.assertEqual(D.maior_versao(["249.11-0ubuntu3.19", "249.11-0ubuntu3.21", "249.11-0ubuntu3.7"]), "249.11-0ubuntu3.21")
        self.assertIsNone(D.maior_versao([]))

    def test_condicao(self):
        self.assertEqual(D.parse_cond("Package less than 1.2-3"), ("corrigido", "1.2-3"))
        self.assertEqual(D.parse_cond("Package less than or equal to 1.2"), ("ate", "1.2"))
        self.assertEqual(D.parse_cond("Package default status"), ("sem", None))
        self.assertEqual(D.parse_cond(None), ("outro", None))
        self.assertEqual(D.parse_cond("Package greater than 3"), ("outro", None))


class TestKernelETipo(unittest.TestCase):
    def test_tipo_maquina(self):
        self.assertEqual(D.tipo_maquina("Microsoft Windows 11 Pro", "windows"), "Estação")
        self.assertEqual(D.tipo_maquina("Microsoft Windows 10 Pro", "windows"), "Estação")
        self.assertEqual(D.tipo_maquina("Microsoft Windows Server 2022", "windows"), "Servidor")
        self.assertEqual(D.tipo_maquina("Ubuntu 22.04", "ubuntu"), "Servidor")
        self.assertEqual(D.tipo_maquina("", ""), "Servidor")

    def test_kernels(self):
        r = D.analisar_kernels("5.15.0-110-generic", {"linux-image-5.15.0-100-generic": 4, "linux-modules-5.15.0-100-generic": 3,
                                                       "linux-image-5.15.0-110-generic": 2, "linux-image-5.15.0-120-generic": 1,
                                                       "linux-image-6.8.0-1-lowlatency": 9, "udev": 5})
        self.assertEqual(sorted(r["antigos"]), ["linux-image-5.15.0-100-generic", "linux-modules-5.15.0-100-generic"])
        self.assertEqual(r["registros_antigos"], 7)
        self.assertEqual(r["novos"], ["linux-image-5.15.0-120-generic"])
        self.assertTrue(r["reiniciar"])  # outro "sabor" (lowlatency) nao conta; um image mais novo do mesmo sabor conta
        self.assertFalse(D.analisar_kernels("6.8.12-11-pve", {"linux-image-5.15.0-1-generic": 3})["antigos"])  # LXC: kernel do host
        self.assertFalse(D.analisar_kernels("", {"linux-image-5.15.0-1-generic": 3})["reiniciar"])

    def test_kernels_resumo(self):
        ix = FakeIx()
        k = D.kernels_resumo(ix, D.servidores(ix))
        self.assertEqual([x["nome"] for x in k["reiniciar"]], ["srv-a"])
        self.assertEqual(k["registros_antigos"], 4)
        self.assertEqual(k["servidores_antigos"], 1)


class TestAgregacoes(unittest.TestCase):
    def test_contar_agrupa_sem_classificacao(self):
        r = D.contar([bucket("Critical", 2), bucket("-", 3), bucket("None", 1), bucket("Low", 4)])
        self.assertEqual((r["Critical"], r["Low"], r["Outra"], r["total"]), (2, 4, 4, 10))

    def test_servidores_com_tipo_e_status(self):
        ix = FakeIx()
        st = D.status_agentes(ix)
        self.assertEqual(st["srv-b"]["status"], "disconnected")
        l = D.servidores(ix, st)
        self.assertEqual([x["nome"] for x in l], ["srv-a", "srv-b"])
        self.assertEqual((l[0]["Critical"], l[0]["Medium"], l[0]["Outra"], l[0]["plataforma"], l[0]["tipo"], l[0]["agente"]), (2, 6, 1, "ubuntu", "Servidor", "active"))
        self.assertEqual((l[1]["tipo"], l[1]["agente"]), ("Estação", "disconnected"))

    def test_status_sem_permissao_nao_quebra(self):
        ix = FakeIx()
        ix.monitoramento = False
        self.assertIsNone(D.status_agentes(ix))
        self.assertEqual(D.servidores(ix, None)[0]["agente"], "")  # painel funciona sem o status

    def test_resumo(self):
        ix = FakeIx()
        r = D.resumo(ix, D.servidores(ix, D.status_agentes(ix)), kev_fake())
        self.assertEqual((r["total"], r["gravidade"]["Critical"], r["gravidade"]["Outra"], r["com_critica"], r["sem_correcao"], r["com_correcao"]), (20, 3, 15, 1, 4, 9))
        self.assertEqual(r["top_servidores"][0]["nome"], "srv-a")
        self.assertEqual((r["kev"]["cves"], r["kev"]["servidores"], r["kev"]["top"][0]["ransomware"]), (1, 2, True))
        self.assertEqual(r["kev"]["top"][0]["epss"], 0.9712)
        self.assertEqual([a["ano"] for a in r["por_ano"]], ["2025", "2026"])
        self.assertEqual((r["tipos"]["Servidor"]["servidores"], r["tipos"]["Estação"]["servidores"], r["tipos"]["Servidor"]["Critical"]), (1, 1, 2))
        self.assertEqual((r["agentes"]["ativos"], r["agentes"]["desconectados"], r["agentes"]["conhecido"]), (1, 1, True))
        self.assertTrue(r["criticas"][0]["kev"])

    def test_resumo_sem_listas_kev(self):
        ix = FakeIx()
        r = D.resumo(ix, D.servidores(ix), None)
        self.assertEqual(r["kev"]["cves"], 0)
        self.assertFalse(r["agentes"]["conhecido"])

    def test_servidor_pega_a_maior_versao_corrigida(self):
        r = D.servidor(FakeIx(), "srv-a", kev_fake())
        udev = next(p for p in r["pacotes"] if p["nome"] == "udev")
        self.assertEqual(udev["corrigir_para"], "249.11-0ubuntu3.21")  # a maior entre .19, .21 e .7: resolve todas as CVEs
        self.assertEqual((udev["com_correcao"], udev["sem_correcao"], udev["sev_max"]), (11, 1, "High"))
        self.assertIsNone(next(p for p in r["pacotes"] if p["nome"] == "mysql-server")["corrigir_para"])
        self.assertEqual(r["pacotes"][0]["nome"], "firefox")  # exploradas (🔥) vem primeiro
        self.assertEqual(r["pacotes"][1]["sev_max"], "Critical")
        self.assertEqual(r["exploradas"][0]["cve"], "CVE-2026-1")
        self.assertTrue(r["exploradas"][0]["kev"])
        self.assertIsNone(D.servidor(FakeIx(), "nao-existe"))

    def test_servidor_kernels(self):
        r = D.servidor(FakeIx(), "srv-a", kev_fake())
        tags = {p["nome"]: p["kernel"] for p in r["pacotes"] if p["nome"].startswith("linux-image")}
        self.assertEqual(tags, {"linux-image-5.15.0-100-generic": "antigo", "linux-image-5.15.0-120-generic": "novo"})
        cmds = [x["c"] for x in r["plano"]["passos"]]
        self.assertIn("sudo apt autoremove --purge -y", cmds)
        self.assertLess(cmds.index("sudo reboot"), cmds.index("sudo apt autoremove --purge -y"))  # remover SO depois de reiniciar
        self.assertTrue(r["plano"]["reinicia"])

    def test_pacotes_por_servidores(self):
        l = D.pacotes(FakeIx(), kev_fake())
        self.assertEqual([p["nome"] for p in l], ["firefox", "zlib"])
        self.assertEqual((l[0]["servidores"], l[0]["sev"]["Critical"], l[0]["corrigir_para"], l[0]["kev"], l[0]["gerenciador"]), (3, 2, "130.1", 2, "windows-prog"))
        self.assertIsNone(l[1]["corrigir_para"])

    def test_pacote_detalhe(self):
        d = D.pacote_detalhe(FakeIx(), "x")
        self.assertEqual((d[0]["nome"], d[0]["corrigir_para"], d[0]["sev"]["Critical"]), ("srv-a", "2.0", 3))

    def test_foto_e_criticas(self):
        ix = FakeIx()
        l = D.servidores(ix)
        f = D.foto_diaria(D.resumo(ix, l, kev_fake()), l, D.kernels_resumo(ix, l))
        self.assertEqual((f["grav"]["Critical"], f["kev_cves"], f["reiniciar"]), (3, 1, 1))
        self.assertEqual(D.criticas_chaves(ix), {"CVE-2026-1|srv-a", "CVE-2026-2|srv-a"})

    def test_filtros(self):
        f = D._filtros(["Critical", "Medium"], "srv", "a*b?", True)["bool"]
        self.assertIn({"terms": {D.F_SEV: ["Critical", "Medium"]}}, f["filter"])
        wild = [x for x in f["filter"] if "bool" in x][0]["bool"]["should"][1]["wildcard"][D.F_PKG]["value"]
        self.assertEqual(wild, "*a\\*b\\?*")  # curinga digitado pelo usuario nao vira curinga
        self.assertTrue(f["must_not"])
        self.assertEqual(D._filtros(D.SEVS, "", "", False)["bool"]["filter"], [])  # todas as gravidades = sem filtro
        outra = D._filtros(["Outra"], "", "", False)["bool"]["filter"][0]["terms"][D.F_SEV]
        self.assertEqual(sorted(outra), ["-", "None"])
        self.assertEqual(D._filtros([], "", "", False, [])["bool"]["filter"], [{"terms": {D.F_CVE: ["CVE-0000-0000"]}}])  # sem lista KEV: nada, nunca "tudo"
        self.assertEqual(D._filtros([], "", "", False, ["CVE-1"])["bool"]["filter"], [{"terms": {D.F_CVE: ["CVE-1"]}}])

    def test_vulnerabilidades_enriquecidas(self):
        ix, enr = FakeIx(), kev_fake()
        r = D.vulnerabilidades(ix, ["Critical"], exploradas=True, enr=enr)
        corpo = ix.pedidos[-1][1]
        self.assertIn({"terms": {D.F_CVE: ["CVE-2026-1"]}}, corpo["query"]["bool"]["filter"])
        self.assertEqual(r["itens"][0]["kev"], True)

    def test_pagina_limitada(self):
        ix = FakeIx()
        D.vulnerabilidades(ix, ["Critical"], pagina=99999)
        self.assertLessEqual(ix.pedidos[-1][1]["from"] + ix.pedidos[-1][1]["size"], 10000)

    def test_enriquecer(self):
        l = D.enriquecer([{"cve": "CVE-2026-1"}, {"cve": "CVE-2026-2"}, {"cve": "CVE-9"}], kev_fake())
        self.assertEqual((l[0]["kev"], l[0]["ransomware"], l[0]["epss"]), (True, True, 0.9712))
        self.assertEqual((l[1]["kev"], l[1]["epss"], l[2]["epss"]), (False, 0.004, None))


class TestRelatorioPorEscopo(unittest.TestCase):
    def test_grupos(self):
        lista = D.servidores(FakeIx(), None)
        self.assertEqual(D.resolver_grupo("todos", lista)[1], ["srv-a", "srv-b"])
        self.assertEqual(D.resolver_grupo("tipo:Servidor", lista), ("Servidores", ["srv-a"]))
        self.assertEqual(D.resolver_grupo("tipo:Estação", lista)[1], ["srv-b"])
        self.assertEqual(D.resolver_grupo("so:ubuntu", lista), ("Sistema: ubuntu", ["srv-a"]))
        self.assertEqual(D.resolver_grupo("criticos", lista)[1], ["srv-a"])
        self.assertIsNone(D.resolver_grupo("so:../../etc", lista))  # nada fora do formato permitido
        self.assertIsNone(D.resolver_grupo("qualquer", lista))

    def test_um_servidor_tem_plano(self):
        ix, enr = FakeIx(), kev_fake()
        lista = D.servidores(ix, None)
        r = D.relatorio(ix, lista, ["srv-a"], "", enr, lambda n: D.servidor(ix, n, enr))
        self.assertEqual(r["escopo"]["titulo"], "srv-a")
        self.assertEqual((r["gravidade"]["Critical"], r["gravidade"]["Medium"], r["servidores"], r["total"]), (2, 8, 1, 14))
        self.assertEqual((r["kev"]["cves"], r["kev"]["top"][0]["ransomware"], r["kev"]["top"][0]["epss"]), (1, True, 0.9712))
        self.assertEqual(len(r["detalhes"]), 1)
        d = r["detalhes"][0]
        self.assertTrue(d["plano"]["passos"] and d["plano"]["antes"])
        self.assertEqual(d["exploradas"][0]["cve"], "CVE-2026-1")
        self.assertLessEqual(len(d["pacotes"]), 15)
        self.assertEqual(ix.escopos[-1], ["srv-a"])  # a consulta agregada ficou restrita as maquinas pedidas
        self.assertEqual(r["tabela"][0]["nome"], "srv-a")

    def test_muitas_maquinas_sem_detalhe_e_nao_encontrados(self):
        ix = FakeIx()
        lista = D.servidores(ix, None)
        r = D.relatorio(ix, lista, ["srv-a", "srv-b", "fantasma", "srv-a"], "Teste", None, lambda n: D.servidor(ix, n), max_detalhe=1)
        self.assertEqual(r["escopo"]["nomes"], ["srv-a", "srv-b"])  # sem duplicar
        self.assertEqual(r["escopo"]["nao_encontrados"], ["fantasma"])
        self.assertEqual((r["escopo"]["titulo"], r["detalhes"]), ("Teste", []))  # acima do limite: so o resumo
        self.assertEqual(r["kev"]["cves"], 0)  # sem listas KEV carregadas
        self.assertEqual(sorted(ix.escopos[-1]), ["srv-a", "srv-b"])

    def test_nada_encontrado(self):
        ix = FakeIx()
        r = D.relatorio(ix, D.servidores(ix, None), ["fantasma"])
        self.assertEqual((r["escopo"]["nomes"], r["escopo"]["nao_encontrados"]), ([], ["fantasma"]))
        self.assertNotIn("gravidade", r)

    def test_pacotes_filtra_por_servidores(self):
        ix = FakeIx()
        D.pacotes(ix, kev_fake(), ["srv-a"], 5)
        q1 = ix.pedidos[-2][1]["query"]
        self.assertIn({"terms": {D.F_AGENTE: ["srv-a"]}}, q1["bool"]["filter"])
        self.assertIn({"terms": {D.F_AGENTE: ["srv-a"]}}, ix.pedidos[-1][1]["query"]["bool"]["filter"])


class TestPlano(unittest.TestCase):
    def _plano(self):
        r = D.servidor(FakeIx(), "srv-a", kev_fake())
        return r["plano"], "\n".join(x["c"] for x in r["plano"]["passos"])

    def test_nome_perigoso_nunca_vai_para_comando(self):
        _, cmds = self._plano()
        self.assertNotIn("rm -rf", cmds)
        self.assertNotIn(";", cmds)
        self.assertIn("sudo apt install --only-upgrade firefox udev", cmds)  # a exploradas (firefox) vem primeiro

    def test_reinicio_banco_e_kev(self):
        p, cmds = self._plano()
        self.assertTrue(p["reinicia"])
        self.assertIn("sudo reboot", cmds)
        self.assertIn("sudo systemctl restart wazuh-agent", cmds)
        titulos = [x["t"] for x in p["antes"]]
        self.assertIn("Reinício necessário", titulos)
        self.assertIn("Banco de dados", titulos)
        self.assertIn("Snapshot ou backup", titulos)
        self.assertTrue(any("sem correção" in n for n in p["notas"]))
        self.assertTrue(any("🔥" in n for n in p["notas"]))

    def test_dnf_e_windows(self):
        pk = [{"nome": "openssl", "gerenciador": "dnf", "corrigir_para": "1.1.1k-9", "reinicia": True, "sem_correcao": 0, "ate": 0}]
        p = D.plano({"nome": "x"}, pk)
        self.assertIn("sudo dnf upgrade --security -y", [x["c"] for x in p["passos"]])
        win = [{"nome": "Microsoft Windows 10 Pro 10.0.19045.6456", "gerenciador": "windows-so", "corrigir_para": "10.0.19045.7807", "reinicia": True,
                "sem_correcao": 0, "ate": 0},
               {"nome": "WinRAR 5.91", "gerenciador": "windows-prog", "corrigir_para": "7.13", "reinicia": False, "sem_correcao": 0, "ate": 0}]
        p = D.plano({"nome": "w"}, win)
        self.assertEqual(p["passos"], [])
        self.assertTrue(any("10.0.19045.7807" in n for n in p["notas"]))
        self.assertTrue(any("winget" in n for n in p["notas"]))


class TestCsv(unittest.TestCase):
    def test_formula_neutralizada(self):
        t = D.csv_texto(["a"], [["=cmd|' /C calc'!A0"], ["+1+1"], ["@x"], ["-5"], ["-texto"], ['aspas"internas']])
        self.assertTrue(t.startswith("﻿"))
        self.assertIn("\"'=cmd", t)
        self.assertIn("\"'+1+1\"", t)
        self.assertIn("\"'@x\"", t)
        self.assertIn('"-5"', t)  # numero negativo de verdade segue como esta
        self.assertIn("\"'-texto\"", t)
        self.assertIn('"aspas""internas"', t)


if __name__ == "__main__":
    unittest.main()
