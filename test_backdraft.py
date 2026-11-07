"""Testes do servidor: sessao, login restrito, protecoes e rotas da API (indexador e broker simulados)."""
import http.client
import json
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

import backdraft as B
import dados as D
from test_dados import FakeIx

SECRET = b"x" * 40


class TestSessao(unittest.TestCase):
    def test_token(self):
        t = B.criar_token(SECRET, "ana", "Ana", 1000, 1000)
        self.assertEqual(B.ler_token(SECRET, t, 900, 28800, agora=1100)["u"], "ana")
        self.assertIsNone(B.ler_token(SECRET, t, 900, 28800, agora=2000))      # inativa
        self.assertIsNone(B.ler_token(SECRET, t, 90000, 28800, agora=40000))   # velha demais
        self.assertIsNone(B.ler_token(b"y" * 40, t, 900, 28800, agora=1100))   # outra chave
        corpo, assin = t.split(".")
        self.assertIsNone(B.ler_token(SECRET, corpo + "A." + assin, 900, 28800, agora=1100))  # adulterado
        self.assertIsNone(B.ler_token(SECRET, "lixo", 900, 28800))

    def test_ip_e_limitador(self):
        import ipaddress
        redes = [ipaddress.ip_network("198.51.100.0/24")]
        self.assertTrue(B.ip_permitido(redes, "198.51.100.7"))
        self.assertFalse(B.ip_permitido(redes, "8.8.8.8"))
        self.assertFalse(B.ip_permitido(redes, "lixo"))
        self.assertTrue(B.ip_permitido([], "8.8.8.8"))
        l = B.Limitador(3, 100)
        for _ in range(3):
            l.falha("a", agora=10)
        self.assertTrue(l.bloqueado("a", agora=50))
        self.assertFalse(l.bloqueado("a", agora=200))
        l.ok("a")
        self.assertFalse(l.bloqueado("a", agora=50))

    def test_token_lembrar_de_mim(self):
        t = B.criar_token(SECRET, "ana", "Ana", 1000, 1000, lembrar=True)
        n = B.criar_token(SECRET, "ana", "Ana", 1000, 1000)
        # 2 dias depois: so a sessao "lembrada" (idle 3 dias / max 7 dias) continua valida
        self.assertEqual(B.ler_token(SECRET, t, 900, 28800, agora=1000 + 172800, idle_m=259200, max_m=604800)["u"], "ana")
        self.assertIsNone(B.ler_token(SECRET, n, 900, 28800, agora=1000 + 172800, idle_m=259200, max_m=604800))
        self.assertIsNone(B.ler_token(SECRET, t, 900, 28800, agora=1000 + 700000, idle_m=900000, max_m=604800))  # passou do maximo
        self.assertIsNone(B.ler_token(SECRET, t, 900, 28800, agora=1000 + 172800))  # sem limites m: vale o normal

    def test_ordenar_brokers_por_rede(self):
        import ipaddress
        a = {"nome": "A", "redes": [ipaddress.ip_network("192.0.2.0/24")]}
        b = {"nome": "B", "redes": [ipaddress.ip_network("198.51.100.0/24")]}
        nomes = lambda ip: [x["nome"] for x in B.ordenar_brokers([a, b], ip)]
        self.assertEqual(nomes("192.0.2.45"), ["A", "B"])
        self.assertEqual(nomes("198.51.100.30"), ["B", "A"])   # rede do B: tenta o B primeiro e o A fica de reserva
        self.assertEqual(nomes("203.0.113.5"), ["A", "B"])   # rede desconhecida: ordem configurada
        self.assertEqual(nomes("lixo"), ["A", "B"])

    def test_autenticar_escolhe_broker_e_cai_para_o_outro(self):
        import ipaddress, os
        os.environ.update({"BROKER_A_HOST": "a.test", "BROKER_A_REDES": "192.0.2.0/24",
                           "BROKER_B_HOST": "b.test", "BROKER_B_REDES": "198.51.100.0/24"})
        try:
            cfg = B.Config()
        finally:
            for k in ("BROKER_A_HOST", "BROKER_A_REDES", "BROKER_B_HOST", "BROKER_B_REDES"):
                os.environ.pop(k)
        self.assertEqual([b["host"] for b in cfg.brokers], ["a.test", "b.test"])
        chamadas, fora = [], set()
        orig = B._autenticar_em
        def falso(c, b, u, s):
            chamadas.append(b["host"])
            if b["host"] in fora:
                raise B.LdapIndisponivel("fora")
            return ((True, "Nome") if s == "ok" else (False, None))
        B._autenticar_em = falso
        try:
            self.assertEqual(B.autenticar(cfg, "ana", "ok", "198.51.100.30"), (True, "Nome"))
            self.assertEqual(chamadas, ["b.test"])                       # IP da rede B: foi direto ao broker B
            chamadas.clear(); fora.add("b.test")
            self.assertEqual(B.autenticar(cfg, "ana", "ok", "198.51.100.30"), (True, "Nome"))
            self.assertEqual(chamadas, ["b.test", "a.test"])            # B fora do ar: cai para o A
            chamadas.clear()
            self.assertEqual(B.autenticar(cfg, "ana", "errada", "192.0.2.45"), (False, None))
            self.assertEqual(chamadas, ["a.test"])                       # senha errada e definitiva: nao tenta o outro
            fora.add("a.test"); fora.add("b.test")
            with self.assertRaises(B.LdapIndisponivel):
                B.autenticar(cfg, "ana", "ok", "192.0.2.45")
        finally:
            B._autenticar_em = orig

    def test_usuarios_locais(self):
        import os
        h = B.gerar_hash_senha("senha-bem-longa-123", 1000)
        self.assertTrue(B.verificar_senha("senha-bem-longa-123", h))
        self.assertFalse(B.verificar_senha("outra-senha", h))
        self.assertFalse(B.verificar_senha("x", "lixo"))
        self.assertFalse(B.verificar_senha("x", "md5:1:aa:bb"))
        os.environ["LOCAL_USERS"] = "Ana|" + h + ",bia|" + B.gerar_hash_senha("bia-senha-123456", 1000)
        try:
            cfg = B.Config()
        finally:
            os.environ.pop("LOCAL_USERS")
        self.assertEqual(sorted(cfg.usuarios_locais), ["ana", "bia"])
        self.assertEqual(B.autenticar(cfg, "ana", "senha-bem-longa-123"), (True, "ana"))
        self.assertEqual(B.autenticar(cfg, "ANA", "errada"), (False, None))
        self.assertEqual(B.autenticar(cfg, "ana", ""), (False, None))
        self.assertEqual(B.autenticar(cfg, "zeca", "qualquer"), (False, None))  # sem LDAP configurado: simplesmente recusa

    def test_ldap_nao_configurado_por_padrao(self):
        cfg = B.Config()
        self.assertEqual(cfg.brokers, [])
        self.assertEqual(cfg.titulo, "Backdraft")

    def test_titulo_com_organizacao(self):
        import os
        os.environ["ORG_NOME"] = "Minha Empresa"
        try:
            self.assertEqual(B.Config().titulo, "Minha Empresa · Backdraft")
        finally:
            os.environ.pop("ORG_NOME")

    def test_escapar_rdn(self):
        self.assertEqual(B.escapar_rdn("a,b=c"), "a\\,b\\=c")


class TestServidor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os
        os.environ.update({"ALLOWED_USERS": "ana,bia", "BACKDRAFT_SECRET": SECRET.decode(), "COOKIE_SECURE": "0", "INDEXER_PASS": "x"})
        cls.cfg = B.Config()
        cls.ix = FakeIx()
        cls.sv = B.Servico(cls.cfg, cls.ix)
        cls._auth_orig = B.autenticar
        B.autenticar = lambda cfg, u, s, ip="", log=None: ((s == "ok"), "Nome " + u) if u != "fora" else (_ for _ in ()).throw(B.LdapIndisponivel("x"))
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), B.criar_handler(cls.sv))
        cls.porta = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        B.autenticar = cls._auth_orig
        cls.srv.shutdown()

    def req(self, metodo, caminho, corpo=None, cookie=None, cab=None):
        c = http.client.HTTPConnection("127.0.0.1", self.porta, timeout=10)
        h = {"Host": "127.0.0.1:%d" % self.porta}
        if cookie:
            h["Cookie"] = cookie
        h.update(cab or {})
        if corpo is not None:
            h["Content-Type"] = "application/x-www-form-urlencoded"
        c.request(metodo, caminho, body=corpo, headers=h)
        r = c.getresponse()
        dado = r.read()
        return r, dado

    def logar(self, usuario="ana", senha="ok"):
        r, _ = self.req("POST", "/login", "usuario=%s&senha=%s" % (usuario, senha), cab={"Origin": "http://127.0.0.1:%d" % self.porta})
        return r

    def cookie(self, usuario="ana"):
        r = self.logar(usuario)
        self.assertEqual(r.status, 303)
        return r.getheader("Set-Cookie").split(";")[0]

    def test_sem_sessao(self):
        r, _ = self.req("GET", "/")
        self.assertEqual((r.status, r.getheader("Location")), (303, "/login"))
        r, _ = self.req("GET", "/api/resumo")
        self.assertEqual(r.status, 401)
        r, corpo = self.req("GET", "/login")
        self.assertEqual(r.status, 200)
        self.assertIn(b"Backdraft", corpo)

    def test_login_fluxo(self):
        self.assertEqual(self.logar("ana", "errada").status, 401)
        self.assertEqual(self.logar("intruso", "ok").status, 403)  # autenticou no broker, mas nao esta em ALLOWED_USERS
        self.assertEqual(self.logar("fora", "ok").status, 503)     # broker fora do ar nao vira "senha errada"
        r = self.logar("ana", "ok")
        self.assertEqual(r.status, 303)
        sc = r.getheader("Set-Cookie")
        self.assertIn("HttpOnly", sc)
        self.assertIn("SameSite=Strict", sc)

    def test_lembrar_de_mim(self):
        r, corpo = self.req("GET", "/login")
        self.assertIn(b'name="lembrar"', corpo)
        cab = {"Origin": "http://127.0.0.1:%d" % self.porta}
        r, _ = self.req("POST", "/login", "usuario=ana&senha=ok", cab=cab)
        self.assertNotIn("Max-Age", r.getheader("Set-Cookie"))               # sem marcar: cookie de sessao
        r, _ = self.req("POST", "/login", "usuario=ana&senha=ok&lembrar=1", cab=cab)
        sc = r.getheader("Set-Cookie")
        self.assertIn("Max-Age=604800", sc)                                  # marcado: persistente por 7 dias
        self.assertIn("HttpOnly", sc)
        r, _ = self.req("GET", "/api/resumo", cookie=sc.split(";")[0], cab={"X-Atividade": "1"})
        self.assertEqual(r.status, 200)
        self.assertIn("Max-Age=", r.getheader("Set-Cookie") or "")           # a renovacao mantem o cookie persistente

    def test_cabecalhos_e_origem(self):
        r, _ = self.req("GET", "/login")
        self.assertIn("default-src 'none'", r.getheader("Content-Security-Policy"))
        self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
        r, _ = self.req("POST", "/login", "usuario=ana&senha=ok", cab={"Origin": "http://evil.example"})
        self.assertEqual(r.status, 403)  # CSRF

    def test_estaticos(self):
        r, _ = self.req("GET", "/static/app.css")
        self.assertEqual(r.status, 200)
        r, _ = self.req("GET", "/static/..%2f..%2fbackdraft.py")
        self.assertEqual(r.status, 404)
        r, _ = self.req("GET", "/static/../backdraft.py")
        self.assertEqual(r.status, 404)

    def test_api(self):
        ck = self.cookie()
        r, corpo = self.req("GET", "/api/resumo", cookie=ck)
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(corpo)["gravidade"]["Critical"], 3)
        r, corpo = self.req("GET", "/api/servidores", cookie=ck)
        self.assertEqual([s["nome"] for s in json.loads(corpo)["servidores"]], ["srv-a", "srv-b"])
        r, corpo = self.req("GET", "/api/servidor?nome=srv-a", cookie=ck)
        self.assertEqual(r.status, 200)
        self.assertIn("plano", json.loads(corpo))
        r, corpo = self.req("GET", "/api/servidor?nome=nao-existe", cookie=ck)
        self.assertEqual(r.status, 404)
        r, _ = self.req("GET", "/api/servidor?nome=a%3Bb%7Cc", cookie=ck)
        self.assertEqual(r.status, 400)
        r, _ = self.req("GET", "/api/cves?servidor=srv-a", cookie=ck)
        self.assertEqual(r.status, 400)
        r, _ = self.req("GET", "/api/rota-inexistente", cookie=ck)
        self.assertEqual(r.status, 404)
        r, corpo = self.req("GET", "/api/vulns?sev=Critical,Medium&pagina=0", cookie=ck)
        self.assertEqual(r.status, 200)
        r, corpo = self.req("GET", "/api/vulns.csv?sev=Critical", cookie=ck)
        self.assertEqual(r.status, 200)
        self.assertIn("attachment", r.getheader("Content-Disposition"))

    def test_rotas_novas(self):
        ck = self.cookie()
        r, corpo = self.req("GET", "/api/resumo", cookie=ck)
        d = json.loads(corpo)
        for chave in ("kev", "por_ano", "tipos", "agentes", "kernels", "enriquecimento", "avisos", "top_servidores"):
            self.assertIn(chave, d)
        r, corpo = self.req("GET", "/api/pacotes", cookie=ck)
        self.assertEqual([p["nome"] for p in json.loads(corpo)["pacotes"]], ["firefox", "zlib"])
        r, corpo = self.req("GET", "/api/pacote?nome=firefox", cookie=ck)
        self.assertEqual(json.loads(corpo)["servidores"][0]["nome"], "srv-a")
        r, _ = self.req("GET", "/api/pacote?nome=", cookie=ck)
        self.assertEqual(r.status, 400)
        r, corpo = self.req("GET", "/api/historico", cookie=ck)
        self.assertEqual(r.status, 200)
        self.assertIn("serie", json.loads(corpo))
        r, corpo = self.req("GET", "/api/avisos", cookie=ck)
        self.assertEqual((json.loads(corpo)["ativo"], json.loads(corpo)["canais"]), (False, []))
        r, corpo = self.req("GET", "/api/vulns?sev=Critical&exploradas=1", cookie=ck)
        self.assertEqual(r.status, 200)
        r, corpo = self.req("GET", "/api/servidores", cookie=ck)
        self.assertEqual(json.loads(corpo)["agentes_conhecido"], True)
        r, corpo = self.req("GET", "/relatorio", cookie=ck)
        self.assertEqual(r.status, 200)
        self.assertIn(b"relatorio.js", corpo)
        r, _ = self.req("GET", "/relatorio")
        self.assertEqual(r.status, 303)  # sem sessao
        for arq in ("charts.js", "relatorio.js", "relatorio.css", "icone.svg"):
            r, _ = self.req("GET", "/static/" + arq)
            self.assertEqual(r.status, 200, arq)

    def test_relatorio_por_escopo(self):
        ck = self.cookie()
        r, corpo = self.req("GET", "/api/relatorio?servidores=srv-a", cookie=ck)
        d = json.loads(corpo)
        self.assertEqual((r.status, d["escopo"]["nomes"], len(d["detalhes"])), (200, ["srv-a"], 1))
        r, corpo = self.req("GET", "/api/relatorio?servidores=srv-a%2Csrv-b%2Cfantasma", cookie=ck)
        d = json.loads(corpo)
        self.assertEqual((d["escopo"]["nomes"], d["escopo"]["nao_encontrados"]), (["srv-a", "srv-b"], ["fantasma"]))
        r, corpo = self.req("GET", "/api/relatorio?grupo=tipo%3AServidor", cookie=ck)
        self.assertEqual((r.status, json.loads(corpo)["escopo"]["titulo"]), (200, "Servidores"))
        r, corpo = self.req("GET", "/api/relatorio?grupo=todos", cookie=ck)
        self.assertEqual(json.loads(corpo)["servidores"], 2)
        for ruim in ("grupo=qualquer", "servidores=", "servidores=a%3Bb", "servidores=" + ",".join("m%d" % i for i in range(61))):
            r, _ = self.req("GET", "/api/relatorio?" + ruim, cookie=ck)
            self.assertEqual(r.status, 400, ruim)
        r, _ = self.req("GET", "/api/relatorio?grupo=todos")
        self.assertEqual(r.status, 401)  # sem sessao

    def test_teste_de_aviso_sem_canal(self):
        ck = self.cookie()
        r, corpo = self.req("POST", "/api/avisos/testar", "", cookie=ck, cab={"Origin": "http://127.0.0.1:%d" % self.porta})
        self.assertEqual(r.status, 400)
        r, _ = self.req("POST", "/api/avisos/testar", "", cab={"Origin": "http://127.0.0.1:%d" % self.porta})
        self.assertEqual(r.status, 401)
        r, _ = self.req("POST", "/api/avisos/testar", "", cookie=ck, cab={"Origin": "http://evil.example"})
        self.assertEqual(r.status, 403)

    def test_sessao_so_estende_com_atividade(self):
        ck = self.cookie()
        r, _ = self.req("GET", "/api/servidores", cookie=ck)
        self.assertIsNone(r.getheader("Set-Cookie"))
        r, _ = self.req("GET", "/api/servidores", cookie=ck, cab={"X-Atividade": "1"})
        self.assertIsNotNone(r.getheader("Set-Cookie"))

    def test_erro_do_indexador_vira_502_sem_detalhe(self):
        ck = self.cookie()
        original = self.sv.ix
        class Quebrado:
            def buscar(self, corpo, indice=None):
                raise OSError("senha=segredo no detalhe")
        self.sv.ix = Quebrado()
        self.sv.cache = D.Cache(0)
        try:
            r, corpo = self.req("GET", "/api/vulns?sev=Critical", cookie=ck)
        finally:
            self.sv.ix = original
            self.sv.cache = D.Cache(300)
        self.assertEqual(r.status, 502)
        self.assertNotIn(b"segredo", corpo)

    def test_logout(self):
        ck = self.cookie()
        r, _ = self.req("POST", "/logout", "", cookie=ck, cab={"Origin": "http://127.0.0.1:%d" % self.porta})
        self.assertEqual(r.status, 303)
        self.assertIn("Max-Age=0", r.getheader("Set-Cookie"))


if __name__ == "__main__":
    unittest.main()
