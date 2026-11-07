"""Historico em disco: uma foto por dia (para as curvas de tendencia) e o conjunto de CVEs criticas conhecidas
(para saber o que e NOVO e o que foi CORRIGIDO desde a ultima vez). Arquivos pequenos, gravacao atomica.
"""
import json
import os
import threading
from datetime import datetime

from dados import TZ


class Historico:
    def __init__(self, pasta="", maximo_dias=800):
        self.pasta, self.maximo, self._l = pasta, maximo_dias, threading.Lock()
        self._fotos = []  # uma por dia, em ordem
        self._criticas = None  # set de "CVE|servidor" ou None se nunca gravado
        self._carregar()

    def _arq(self, nome):
        return os.path.join(self.pasta, nome) if self.pasta else ""

    def _carregar(self):
        arq = self._arq("historico.jsonl")
        if arq and os.path.isfile(arq):
            try:
                with open(arq, encoding="utf-8") as f:
                    for linha in f:
                        try:
                            self._fotos.append(json.loads(linha))
                        except ValueError:
                            pass
            except OSError:
                pass
        arq = self._arq("criticas.json")
        if arq and os.path.isfile(arq):
            try:
                with open(arq, encoding="utf-8") as f:
                    self._criticas = set(json.load(f))
            except (OSError, ValueError, TypeError):
                self._criticas = None

    def _gravar_fotos(self):
        arq = self._arq("historico.jsonl")
        if not arq:
            return
        tmp = arq + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for x in self._fotos:
                f.write(json.dumps(x, ensure_ascii=False, separators=(",", ":")) + "\n")
        os.replace(tmp, arq)

    def registrar(self, foto):
        """Uma foto por dia: a do mesmo dia SUBSTITUI a anterior (fica a mais recente do dia)."""
        foto = dict(foto)
        foto.setdefault("dia", datetime.now(TZ).strftime("%Y-%m-%d"))
        with self._l:
            if self._fotos and self._fotos[-1].get("dia") == foto["dia"]:
                self._fotos[-1] = foto
            else:
                self._fotos.append(foto)
            del self._fotos[:-self.maximo]
            try:
                self._gravar_fotos()
            except OSError as e:
                print("historico: nao consegui gravar: %s" % e, flush=True)

    def serie(self, n=120):
        with self._l:
            return list(self._fotos[-n:])

    def ultima(self):
        with self._l:
            return self._fotos[-1] if self._fotos else None

    def comparar_criticas(self, atuais):
        """Compara com o conjunto anterior e GRAVA o atual. -> (novas, corrigidas, primeira_vez)."""
        atuais = set(atuais)
        with self._l:
            ant = self._criticas
            self._criticas = atuais
            arq = self._arq("criticas.json")
            if arq:
                try:
                    tmp = arq + ".tmp"
                    with open(tmp, "w", encoding="utf-8") as f:
                        json.dump(sorted(atuais), f)
                    os.replace(tmp, arq)
                except OSError as e:
                    print("historico: nao consegui gravar criticas: %s" % e, flush=True)
        if ant is None:
            return set(), set(), True
        return atuais - ant, ant - atuais, False
