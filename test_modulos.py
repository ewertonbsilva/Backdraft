"""Testes de KEV/EPSS, historico, avisos e da rotina horaria (sem rede, sem Telegram/SMTP de verdade)."""
import gzip
import json
import os
import tempfile
import time
import unittest
from unittest import mock
from datetime import datetime

import avisos as _avisos
import backdraft as B
import dados as D
import enriquecimento as E
from avisos import Avisos, texto_novas, texto_semanal
from historico import Historico
from test_dados import FakeIx

KEV_JSON = json.dumps({"catalogVersion": "2026.11.05", "vulnerabilities": [
    {"cveID": "CVE-2026-1001", "vulnerabilityName": "Falha do Firefox", "vendorProject": "Mozilla", "product": "Firefox", "dateAdded": "2026-10-01",
     "dueDate": "2026-10-22", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "lixo; rm -rf", "vulnerabilityName": "x"}, {"cveID": "CVE-2025-2222", "vulnerabilityName": "y", "knownRansomwareCampaignUse": "Unknown"}]}).encode()


def epss_gz(n=1500):
    linhas = ["#model_version:v2025.03.14,score_date:2026-11-05T12:55:00Z", "cve,epss,percentile"]
    linhas += ["CVE-2026-%04d,0.%03d,0.5" % (i, i % 1000) for i in range(1, n)]
    linhas += ["CVE-2026-1001,0.97120,0.999", "lixo,1,1"]
    return gzip.compress("\n".join(linhas).encode())


class TestEnriquecimento(unittest.TestCase):
    def test_parse(self):
        kev, v = E.parse_kev(KEV_JSON)
        self.assertEqual((sorted(kev), v), (["CVE-2025-2222", "CVE-2026-1001"], "2026.11.05"))  # id mal formado e descartado
        self.assertTrue(kev["CVE-2026-1001"]["ransomware"])
        self.assertFalse(kev["CVE-2025-2222"]["ransomware"])
        epss, data = E.parse_epss(epss_gz())
        self.assertEqual(data, "2026-11-05")
        self.assertEqual(epss["CVE-2026-1001"], (0.9712, 0.999))
        self.assertNotIn("lixo", epss)

    def test_atualizar_cache_e_lista_ruim_nao_substitui(self):
        with tempfile.TemporaryDirectory() as pasta:
            fonte = {E.URL_KEV: KEV_JSON, E.URL_EPSS: epss_gz()}
            enr = E.Enriquecimento(pasta, baixar_fn=lambda url, limite, timeout=60: fonte[url])
            self.assertEqual(enr.atualizar(), [])
            self.assertEqual(enr.kev_ids(), ["CVE-2025-2222", "CVE-2026-1001"])
            self.assertEqual(enr.info("CVE-2026-1001")["epss"], 0.9712)
            self.assertTrue(enr.info("CVE-2026-1001")["kev"]["ransomware"])
            self.assertIsNone(enr.info("CVE-9")["kev"])
            # outra instancia le do disco, sem internet
            def sem_rede(url, limite, timeout=60):
                raise OSError("sem internet")
            enr2 = E.Enriquecimento(pasta, baixar_fn=sem_rede)
            self.assertEqual(len(enr2.kev), 2)
            self.assertEqual(len(enr2.epss) > 1000, True)
            erros = enr2.atualizar()
            self.assertEqual(len(erros), 2)  # os dois falharam...
            self.assertEqual(len(enr2.kev), 2)  # ...e a copia boa continua valendo
            # conteudo quebrado nunca substitui a lista boa
            fonte[E.URL_KEV] = b'{"vulnerabilities": []}'
            enr.baixar = lambda url, limite, timeout=60: fonte[url]
            self.assertEqual(len(enr.atualizar()), 1)
            self.assertEqual(len(enr.kev), 2)
            with open(os.path.join(pasta, "kev.json"), "rb") as f:
                self.assertIn(b"CVE-2026-1001", f.read())

    def test_limite_de_tamanho(self):
        class R:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n): return b"x" * n
        orig = E.urllib.request.urlopen
        E.urllib.request.urlopen = lambda *a, **k: R()
        try:
            with self.assertRaises(ValueError):
                E.baixar("https://x", 100)
        finally:
            E.urllib.request.urlopen = orig


class TestHistorico(unittest.TestCase):
    def test_uma_foto_por_dia_e_persistencia(self):
        with tempfile.TemporaryDirectory() as pasta:
            h = Historico(pasta)
            h.registrar({"dia": "2026-11-05", "grav": {"Critical": 10}})
            h.registrar({"dia": "2026-11-06", "grav": {"Critical": 9}})
            h.registrar({"dia": "2026-11-06", "grav": {"Critical": 8}})  # mesmo dia: substitui
            self.assertEqual([x["grav"]["Critical"] for x in h.serie()], [10, 8])
            self.assertEqual(Historico(pasta).ultima()["grav"]["Critical"], 8)
            self.assertEqual(len(Historico(pasta, maximo_dias=1).serie()), 2)  # limite so poda ao registrar
            h2 = Historico(pasta, maximo_dias=1)
            h2.registrar({"dia": "2026-11-07", "grav": {}})
            self.assertEqual(len(h2.serie()), 1)

    def test_novas_e_corrigidas(self):
        with tempfile.TemporaryDirectory() as pasta:
            h = Historico(pasta)
            self.assertEqual(h.comparar_criticas({"a|s1", "b|s1"}), (set(), set(), True))  # 1a vez: so grava a base
            n, c, primeira = h.comparar_criticas({"b|s1", "c|s2"})
            self.assertEqual((n, c, primeira), ({"c|s2"}, {"a|s1"}, False))
            self.assertEqual(Historico(pasta).comparar_criticas({"c|s2"})[1], {"b|s1"})  # sobreviveu ao reinicio


class Capturador(Avisos):
    def __init__(self, env, pasta=""):
        super().__init__(env, pasta)
        self.enviados = []

    def _telegram(self, texto):
        self.enviados.append(("tg", texto))

    def _email(self, assunto, texto):
        self.enviados.append(("mail", assunto, texto))


class TestAvisos(unittest.TestCase):
    ENV = {"TELEGRAM_BOT_TOKEN": "123:abc", "TELEGRAM_CHAT_ID": "-100", "SMTP_HOST": "smtp.x", "SMTP_FROM": "a@x", "SMTP_TO": "b@x, c@x",
           "AVISO_MIN_NOVAS": "2", "AVISO_INTERVALO_HORAS": "6"}

    def test_desligado_por_padrao(self):
        a = Avisos({})
        self.assertFalse(a.ativo)
        self.assertEqual(a.canais, [])
        self.assertFalse(a.pode_avisar_novas(50))
        self.assertEqual(a.enviar("x", "y"), ([], []))

    def test_canais_e_politica(self):
        with tempfile.TemporaryDirectory() as pasta:
            a = Capturador(self.ENV, pasta)
            self.assertEqual(a.canais, ["Telegram", "E-mail"])
            self.assertEqual(a.smtp_para, ["b@x", "c@x"])
            self.assertFalse(a.pode_avisar_novas(1))  # abaixo do minimo
            self.assertTrue(a.pode_avisar_novas(2, agora=1e9))
            a.marcou_novas(agora=1e9)
            self.assertFalse(a.pode_avisar_novas(5, agora=1e9 + 3600))  # intervalo de 6 h
            self.assertTrue(a.pode_avisar_novas(5, agora=1e9 + 7 * 3600))
            self.assertEqual(Capturador(self.ENV, pasta).estado["ultimo_novas"], 1e9)  # persistido

    def test_enviar_em_todos_os_canais_e_erro_isolado(self):
        a = Capturador(self.ENV)
        ok, erros = a.enviar("Assunto", "corpo")
        self.assertEqual((ok, erros), (["Telegram", "E-mail"], []))
        self.assertEqual(a.enviados[0], ("tg", "Assunto\n\ncorpo"))

        class Quebra(Capturador):
            def _telegram(self, texto):
                raise OSError("rede caiu com token 123:abc")
        q = Quebra(self.ENV)
        ok, erros = q.enviar("A", "b")
        self.assertEqual(ok, ["E-mail"])  # o e-mail sai mesmo com o Telegram fora
        self.assertEqual(len(erros), 1)

    @mock.patch.object(_avisos, "TZ", __import__("datetime").timezone(__import__("datetime").timedelta(hours=-5)))
    def test_semana(self):
        a = Capturador(self.ENV)
        seg_9h_local = datetime(2026, 11, 9, 14, 0).timestamp()  # relogio do teste e UTC: 14h UTC = 9h no fuso do teste (UTC-5)
        seg_7h_local = datetime(2026, 11, 9, 12, 0).timestamp()
        ter_9h_local = datetime(2026, 11, 10, 14, 0).timestamp()
        # o teste so e valido se o fuso do processo for UTC; usamos timestamps explicitos em UTC
        from datetime import timezone
        seg_9h_local = datetime(2026, 11, 9, 14, 0, tzinfo=timezone.utc).timestamp()
        seg_7h_local = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc).timestamp()
        ter_9h_local = datetime(2026, 11, 10, 14, 0, tzinfo=timezone.utc).timestamp()
        pend, sem = a.semana_pendente(seg_9h_local)
        self.assertTrue(pend)
        self.assertFalse(a.semana_pendente(seg_7h_local)[0])  # antes das 8h
        self.assertFalse(a.semana_pendente(ter_9h_local)[0])  # nao e segunda
        a.marcou_semana(sem)
        self.assertFalse(a.semana_pendente(seg_9h_local)[0])  # ja enviado nesta semana

    def test_textos(self):
        resumo = {"gravidade": {"Critical": 5, "High": 4, "Medium": 3, "Low": 2}, "servidores": 10, "com_critica": 6,
                  "kev": {"cves": 2, "servidores": 3}, "top_servidores": [{"nome": "srv-a", "Critical": 4, "High": 1}]}
        t = texto_novas({"CVE-1|srv-a", "CVE-2|srv-a", "CVE-3|srv-b"}, {"CVE-9|srv-c"}, resumo, "https://x")
        self.assertIn("3 CVE(s) CRÍTICA(S)", t)
        self.assertIn("srv-a: 2", t)
        self.assertIn("1 crítica(s) corrigida(s)", t)
        self.assertIn("exploradas ativamente", t)
        s = texto_semanal(resumo, [{"grav": {"Critical": 9}}, {"grav": {"Critical": 5}}], "https://x")
        self.assertIn("5 críticas", s)
        self.assertIn("srv-a: 4 críticas", s)


class TestMudancaPeriodo(unittest.TestCase):
    def _f(self, dia, crit, novas=0, corr=0):
        return {"dia": dia, "grav": {"Critical": crit, "High": 10, "Medium": 5, "Low": 1, "Untriaged": 0}, "novas": novas, "corrigidas": corr}

    def test_sem_historico_suficiente(self):
        self.assertIsNone(D.mudanca_periodo([]))
        self.assertIsNone(D.mudanca_periodo([self._f("2026-11-06", 5)]))

    def test_compara_com_sete_dias_antes(self):
        serie = [self._f("2026-10-28", 40), self._f("2026-10-30", 38, 1, 3), self._f("2026-11-01", 30, 0, 8),
                 self._f("2026-11-04", 28, 2, 4), self._f("2026-11-06", 25, 0, 3)]
        p = D.mudanca_periodo(serie, 7)
        self.assertEqual((p["de"], p["ate"], p["dias"]), ("2026-10-30", "2026-11-06", 7))   # a foto mais recente que seja de 7+ dias antes
        self.assertEqual((p["grav_ini"]["Critical"], p["grav_fim"]["Critical"]), (38, 25))
        self.assertEqual((p["novas"], p["corrigidas"]), (2, 15))                              # soma so do que veio DEPOIS da foto inicial

    def test_historico_curto_usa_a_foto_mais_antiga(self):
        p = D.mudanca_periodo([self._f("2026-11-05", 9), self._f("2026-11-06", 7, 0, 2)], 7)
        self.assertEqual((p["de"], p["dias"], p["corrigidas"]), ("2026-11-05", 1, 2))


class TestRelatorioConfidencial(unittest.TestCase):
    def test_resumo_traz_cobertura_e_periodo(self):
        with tempfile.TemporaryDirectory() as pasta:
            os.environ["MAQUINAS_ESPERADAS"] = "157"
            try:
                sv, ix = TestRotinaHoraria()._sv(pasta)
            finally:
                os.environ.pop("MAQUINAS_ESPERADAS")
            r = sv.resumo()
            self.assertEqual(r["cobertura"]["esperadas"], 157)
            self.assertEqual(r["cobertura"]["monitoradas"], r["servidores"])
            self.assertIn("periodo", r)


class TestRotinaHoraria(unittest.TestCase):
    def _sv(self, pasta, env=None):
        os.environ.update({"ALLOWED_USERS": "ana", "BACKDRAFT_SECRET": "x" * 40, "COOKIE_SECURE": "0", "INDEXER_PASS": "x"})
        cfg = B.Config()
        cfg.estado = pasta
        ix = FakeIx()
        sv = B.Servico(cfg, ix, E.Enriquecimento(""))
        sv.avisos = Capturador(env or TestAvisos.ENV, pasta)
        return sv, ix

    def test_primeira_foto_so_grava_a_base(self):
        with tempfile.TemporaryDirectory() as pasta:
            sv, ix = self._sv(pasta)
            f = sv.tirar_foto()
            self.assertEqual((f["novas"], f["corrigidas"]), (0, 0))
            self.assertEqual(sv.avisos.enviados, [])  # nunca avisa na primeira vez
            self.assertEqual(sv.hist.ultima()["grav"]["Critical"], 3)

    def test_novas_criticas_avisam_e_corrigidas_contam(self):
        with tempfile.TemporaryDirectory() as pasta:
            sv, ix = self._sv(pasta)
            sv.tirar_foto()
            ix.criticas = ["CVE-2026-2|srv-a", "CVE-2026-7|srv-a", "CVE-2026-8|srv-b"]  # 2 novas, 1 corrigida
            f = sv.tirar_foto()
            self.assertEqual((f["novas"], f["corrigidas"]), (2, 1))
            self.assertEqual(len([e for e in sv.avisos.enviados if e[0] == "tg"]), 1)
            self.assertIn("2 CVE(s) CRÍTICA(S)", sv.avisos.enviados[0][1])
            ix.criticas += ["CVE-2026-9|srv-b", "CVE-2026-10|srv-b"]  # mais 2, mas dentro do intervalo de 6 h: acumula, nao avisa
            f = sv.tirar_foto()
            self.assertEqual(f["novas"], 4)  # soma do dia
            self.assertEqual(len([e for e in sv.avisos.enviados if e[0] == "tg"]), 1)

    def test_resumo_traz_mudanca_e_kernels(self):
        with tempfile.TemporaryDirectory() as pasta:
            sv, ix = self._sv(pasta)
            sv.tirar_foto()
            r = sv.resumo()
            self.assertEqual(r["mudanca"]["novas"], 0)
            self.assertEqual(r["kernels"]["registros_antigos"], 4)
            self.assertEqual(r["avisos"]["canais"], ["Telegram", "E-mail"])
            self.assertEqual(r["agentes"]["desconectados"], 1)


if __name__ == "__main__":
    unittest.main()
