// Relatório de vulnerabilidades (para imprimir ou salvar em PDF). Três modos, pela URL:
//   /relatorio                    -> visão geral de toda a rede
//   /relatorio?servidores=a,b     -> um servidor ou uma seleção (com plano de correção por máquina, até 8)
//   /relatorio?grupo=tipo:Servidor -> um grupo (todos, tipo:Servidor, tipo:Estação, so:ubuntu, criticos)
// Mesmos dados e gráficos do painel; nada de fora. Todo texto entra por textContent.
(function () {
    'use strict';
    var C = window.Charts, el = C.el, fmt = C.fmt, SEV = C.SEV, SEV_PT = C.SEV_PT;
    var BASE = document.body.getAttribute('data-base') || '';
    var params = new URLSearchParams(location.search);
    var USUARIO = document.body.getAttribute('data-usuario') || '';
    var GERADO = '';
    var ORG = document.body.getAttribute('data-org') || '';
    function $(id) { return document.getElementById(id); }
    function limpa(n) { while (n.firstChild) n.removeChild(n.firstChild); }
    function dia(d) { return d && d.length >= 10 ? d.slice(8, 10) + '/' + d.slice(5, 7) : d; }
    function partes(o) { return SEV.slice(0, 4).map(function (s) { return { n: o[s] || 0, cls: 's-' + s, t: SEV_PT[s] }; }); }
    function pct(v) { return v === null || v === undefined ? '—' : (v * 100 < 1 ? '<1' : (v * 100).toFixed(v * 100 < 10 ? 1 : 0).replace('.', ',')) + '%'; }
    function get(c) {
        return fetch(BASE + c, { credentials: 'same-origin', headers: { 'Accept': 'application/json', 'X-Atividade': '1' } }).then(function (r) {
            if (r.status === 401) { location.href = BASE + '/login'; throw new Error('sessao'); }
            return r.json().then(function (d) { if (!r.ok) throw new Error(d.erro || 'erro'); return d; });
        });
    }
    function sec(pai, titulo, cls) { var s = el('section', 'rel-sec ' + (cls || '')); s.appendChild(el('h2', '', titulo)); pai.appendChild(s); return s; }
    function tab(cols, linhas) {
        var t = el('table', 'rel-tab'), th = el('thead'), tr = el('tr');
        cols.forEach(function (c) { tr.appendChild(el('th', c.num ? 'num' : '', c.t)); }); th.appendChild(tr); t.appendChild(th);
        var tb = el('tbody');
        linhas.forEach(function (l) { var r = el('tr'); cols.forEach(function (c) { r.appendChild(el('td', c.num ? 'num' : '', String(c.f(l)))); }); tb.appendChild(r); });
        t.appendChild(tb); return t;
    }
    function cabecalho(raiz, titulo, sub, data) {
        var cab = el('header', 'rel-cab');
        var img = el('img'); img.src = BASE + '/static/logo.svg'; img.alt = ''; cab.appendChild(img);
        var t = el('div'); t.appendChild(el('h1', '', titulo));
        if (sub) t.appendChild(el('p', 'rel-escopo', sub));
        if (ORG) t.appendChild(el('p', '', ORG));
        t.appendChild(el('p', 'rel-data', 'Gerado em ' + data + ' (horário do servidor) · dados do Wazuh')); cab.appendChild(t);
        GERADO = data;
        raiz.appendChild(cab);
        raiz.appendChild(el('p', 'rel-conf', 'CONFIDENCIAL · USO INTERNO: lista máquinas, versões e vulnerabilidades exploráveis. Não encaminhe a quem não precisa conhecê-lo.'));
    }
    function kpis(pai, g, kevN) {
        var k = el('div', 'rel-kpis');
        [['Críticas', g.Critical, 'Critical'], ['Altas', g.High, 'High'], ['Médias', g.Medium, 'Medium'], ['Baixas', g.Low, 'Low'], ['Exploradas 🔥', kevN, 'Kev']].forEach(function (a) {
            var c = el('div', 'kpi ' + a[2]); c.appendChild(el('div', 'kpi-t', a[0])); var l = el('div', 'kpi-l'); l.appendChild(el('div', 'valor', fmt(a[1]))); c.appendChild(l); k.appendChild(c);
        });
        pai.appendChild(k);
    }
    function rodape(raiz) { raiz.appendChild(el('p', 'rel-rodape', (USUARIO ? 'Gerado por ' + USUARIO + ' em ' + GERADO + '. ' : '') + 'Fonte: Wazuh (módulo Vulnerability Detection), CISA KEV e FIRST EPSS. O inventário é refeito a cada cerca de 1 hora. Software compilado à mão não é detectado. Os comandos são sugestões: aplique só depois do “Antes de corrigir” (snapshot, janela e teste).')); }
    // "Em resumo": o que o gestor precisa ler primeiro (situação, tendência, prioridade, maior ganho e se os dados são confiáveis)
    function executivo(pai, itens) {
        var s = sec(pai, 'Em resumo', 'rel-exec sem-quebra'), ul = el('ul', 'rel-exec-l');
        itens.forEach(function (i) { if (i) ul.appendChild(el('li', i.alerta ? 'rel-alerta' : '', i.t)); });
        s.appendChild(ul);
    }
    function pctN(a, b) { return b ? Math.round(100 * a / b) : 0; }
    function sinal(n) { return (n > 0 ? '+' : '') + fmt(n); }
    function itemMudanca(p) {
        if (!p) return { t: 'Tendência: ainda não há histórico suficiente para comparar com períodos anteriores.' };
        var a = p.grav_ini.Critical, b = p.grav_fim.Critical, dc = b - a;
        return { t: 'Tendência (' + p.dias + ' dia' + (p.dias === 1 ? '' : 's') + ', desde ' + dia(p.de) + '): críticas ' + (dc === 0 ? 'estáveis em ' + fmt(b) : 'de ' + fmt(a) + ' para ' + fmt(b) + ' (' + sinal(dc) + ')') +
            '; altas ' + fmt(p.grav_ini.High) + ' → ' + fmt(p.grav_fim.High) + '. CVEs críticas novas: ' + fmt(p.novas) + ', corrigidas: ' + fmt(p.corrigidas) + '.' };
    }
    function itemCobertura(c) {
        if (!c || (!c.conhecido && !c.esperadas)) return null;
        var t = 'Cobertura: ' + fmt(c.monitoradas) + (c.esperadas ? ' de ' + fmt(c.esperadas) + ' máquinas monitoradas (' + pctN(c.monitoradas, c.esperadas) + '%). As outras ' + fmt(Math.max(0, c.esperadas - c.monitoradas)) + ' não aparecem neste relatório.' : ' máquinas monitoradas.');
        if (c.desconectados) t += ' ' + fmt(c.desconectados) + ' com agente desconectado: os dados delas podem estar desatualizados.';
        return { t: t, alerta: !!(c.desconectados || (c.esperadas && c.monitoradas < c.esperadas)) };
    }
    function itemGanho(lista) {
        var p = lista && lista[0];
        return p ? { t: 'Maior ganho: atualizar “' + p.nome + '” resolve ' + fmt(p.n) + ' registros em ' + fmt(p.servidores) + ' máquina' + (p.servidores === 1 ? '' : 's') + '.' } : null;
    }
    function tabelaKev(pai, lista) {
        pai.appendChild(tab([{ t: 'CVE', f: function (l) { return l.cve; } }, { t: 'O que é', f: function (l) { return (l.nome || '').slice(0, 70) + (l.ransomware ? ' (ransomware)' : ''); } },
            { t: 'Máquinas', num: true, f: function (l) { return fmt(l.servidores); } }, { t: 'EPSS', num: true, f: function (l) { return pct(l.epss); } }], lista));
    }

    // ============================================================ visão geral da rede
    function renderGeral(raiz) {
        return Promise.all([get('/api/resumo'), get('/api/historico')]).then(function (x) {
            var d = x[0], serie = x[1].serie || [], g = d.gravidade, kev = d.kev;
            limpa(raiz);
            cabecalho(raiz, 'Relatório de vulnerabilidades', 'Visão geral de toda a rede', d.gerado_em);
            executivo(raiz, [
                { t: 'Situação: ' + fmt(d.com_critica) + ' de ' + fmt(d.servidores) + ' máquinas (' + pctN(d.com_critica, d.servidores) + '%) têm ao menos uma vulnerabilidade crítica; ' + fmt(g.Critical) + ' registros críticos e ' + fmt(g.High) + ' altos no total.' },
                itemMudanca(d.periodo),
                kev.cves ? { t: 'Prioridade 1: ' + fmt(kev.cves) + ' CVE(s) já exploradas na prática (lista da CISA), em ' + fmt(kev.servidores) + ' máquinas. Corrigir antes de tudo.', alerta: true } : { t: 'Nenhuma CVE da lista da CISA (exploradas) foi encontrada.' },
                itemGanho(d.pacotes),
                itemCobertura(d.cobertura)]);
            var s1 = sec(raiz, 'Resumo');
            s1.appendChild(el('p', 'rel-resumo', fmt(d.com_critica) + ' dos ' + fmt(d.servidores) + ' servidores e estações monitorados têm ao menos uma vulnerabilidade crítica. ' +
                'No total são ' + fmt(g.Critical) + ' registros críticos, ' + fmt(g.High) + ' altos, ' + fmt(g.Medium) + ' médios e ' + fmt(g.Low) + ' baixos. ' +
                (d.total ? Math.round(100 * d.com_correcao / d.total) + '% dos registros já têm correção publicada: bastam as atualizações. ' : '') +
                (kev.cves ? fmt(kev.cves) + ' CVE(s) estão na lista da CISA de vulnerabilidades já exploradas na prática, em ' + fmt(kev.servidores) + ' máquinas.' : '')));
            kpis(s1, g, kev.cves);
            var gr = el('div', 'rel-2col');
            var a = sec(gr, 'Por gravidade', 'sem-quebra'); a.appendChild(C.donut(SEV.map(function (s) { return { t: SEV_PT[s], n: g[s], cls: 's-' + s }; }), { v: C.curto(g.total), r: 'registros' }));
            var b = sec(gr, 'Tendência', 'sem-quebra');
            b.appendChild(C.linhas(serie.map(function (f) { return dia(f.dia); }), [
                { t: 'Críticas', cls: 's-Critical', v: serie.map(function (f) { return f.grav.Critical; }) }, { t: 'Altas', cls: 's-High', v: serie.map(function (f) { return f.grav.High; }) },
                { t: 'Médias', cls: 's-Medium', v: serie.map(function (f) { return f.grav.Medium; }) }]));
            raiz.appendChild(gr);
            var s2 = sec(raiz, 'Máquinas com mais críticas', 'sem-quebra');
            s2.appendChild(C.pilha(d.top_servidores.map(function (s) { return { t: s.nome, sub: s.tipo + ' · ' + s.so, partes: partes(s), total: fmt(s.Critical) + ' crít.' }; })));
            if (kev.cves) { tabelaKev(sec(raiz, '🔥 Exploradas ativamente (CISA): corrigir primeiro', 'sem-quebra'), kev.top); }
            var s4 = sec(raiz, 'Onde um patch resolve mais', 'sem-quebra');
            s4.appendChild(tab([{ t: 'Pacote / programa', f: function (l) { return l.nome; } }, { t: 'Máquinas', num: true, f: function (l) { return fmt(l.servidores); } },
                { t: 'Registros', num: true, f: function (l) { return fmt(l.n); } }], d.pacotes.slice(0, 10)));
            var s5 = sec(raiz, 'Por sistema', 'sem-quebra');
            s5.appendChild(tab([{ t: 'Sistema', f: function (l) { return l.so; } }, { t: 'Máquinas', num: true, f: function (l) { return fmt(l.servidores); } },
                { t: 'Críticas', num: true, f: function (l) { return fmt(l.Critical); } }, { t: 'Altas', num: true, f: function (l) { return fmt(l.High); } },
                { t: 'Médias', num: true, f: function (l) { return fmt(l.Medium); } }], d.por_so));
            var s6 = sec(raiz, 'Recomendações', 'sem-quebra'), ul = el('ol', 'rel-rec');
            if (kev.cves) ul.appendChild(el('li', '', 'Corrigir primeiro as ' + fmt(kev.cves) + ' CVE(s) da lista da CISA (já exploradas), nas ' + fmt(kev.servidores) + ' máquinas afetadas.'));
            ul.appendChild(el('li', '', 'Atualizar os pacotes com correção publicada (' + fmt(d.com_correcao) + ' registros): é a ação de menor esforço e maior efeito.'));
            if (d.kernels && d.kernels.registros_antigos) ul.appendChild(el('li', '', 'Remover kernels antigos que não estão em uso (apt autoremove, depois do reinício): elimina ' + fmt(d.kernels.registros_antigos) + ' registros em ' + fmt(d.kernels.servidores_antigos) + ' servidores.'));
            if (d.kernels && d.kernels.reiniciar.length) ul.appendChild(el('li', '', 'Reiniciar ' + fmt(d.kernels.reiniciar.length) + ' servidor(es) que já têm kernel novo instalado.'));
            if (d.tipos['Estação']) ul.appendChild(el('li', '', 'Estações Windows (' + fmt(d.tipos['Estação'].servidores) + '): atualizar Windows e navegadores por GPO/WSUS; boa parte do total vem de poucos programas.'));
            ul.appendChild(el('li', '', 'Antes de aplicar em servidores: snapshot, janela de manutenção e teste (o painel traz a lista por servidor).'));
            s6.appendChild(ul);
            rodape(raiz);
        });
    }

    // ============================================================ um servidor, seleção ou grupo
    function secaoServidor(raiz, d) {
        var i = d.info, g = d.gravidade, pl = d.plano;
        var s = el('section', 'rel-servidor');
        s.appendChild(el('h2', 'rel-srv-t', i.nome));
        s.appendChild(el('p', 'rel-srv-sub', i.tipo + ' · ' + i.so + (i.kernel ? ' · kernel em uso ' + i.kernel : '')));
        kpis(s, g, d.exploradas.length);
        if (d.exploradas.length) {
            var k = sec(s, '🔥 Já exploradas na prática: corrigir primeiro', 'sem-quebra');
            k.appendChild(tab([{ t: 'CVE', f: function (l) { return l.cve; } }, { t: 'Pacote', f: function (l) { return l.pacote; } }, { t: 'Instalada', f: function (l) { return l.instalada; } },
                { t: 'Atualizar para', f: function (l) { return l.corrigir_para || (l.situacao === 'sem' ? 'sem correção publicada' : '—'); } },
                { t: 'EPSS', num: true, f: function (l) { return pct(l.epss); } }, { t: 'Prazo CISA', f: function (l) { return l.kev_prazo || '—'; } }], d.exploradas));
        }
        var p = sec(s, 'Pacotes e programas a atualizar (os 15 mais graves)', 'sem-quebra');
        p.appendChild(tab([{ t: 'Gravidade', f: function (x) { return SEV_PT[x.sev_max]; } }, { t: 'Pacote / programa', f: function (x) { return (x.kev ? '🔥 ' : '') + x.nome + (x.kernel === 'antigo' ? ' (kernel antigo, removível)' : (x.kernel === 'novo' ? ' (kernel novo: reinicie)' : '')); } },
            { t: 'Instalada', f: function (x) { return x.instalada; } },
            { t: 'Atualizar para', f: function (x) { return x.corrigir_para || (x.sem_correcao ? 'sem correção publicada' : (x.ate ? 'versão desconhecida' : '—')); } },
            { t: 'CVEs', num: true, f: function (x) { return fmt(x.n); } }, { t: 'Crít.', num: true, f: function (x) { return x.sev.Critical; } }], d.pacotes));
        var a = sec(s, '1. Antes de corrigir', 'sem-quebra'), ul = el('ul', 'rel-antes');
        pl.antes.forEach(function (x) { var li = el('li'); li.appendChild(el('b', '', '☐ ' + x.t + ': ')); li.appendChild(document.createTextNode(x.d)); ul.appendChild(li); });
        a.appendChild(ul);
        if (pl.passos.length) {
            var c = sec(s, '2. Comandos (como administrador, depois do item 1)', 'sem-quebra');
            pl.passos.forEach(function (x) { c.appendChild(el('p', 'rel-cmd-t', x.t)); c.appendChild(el('pre', 'rel-cmd', x.c)); });
        }
        if (pl.notas.length) { var n = sec(s, 'Observações', 'sem-quebra'); pl.notas.forEach(function (t) { n.appendChild(el('p', 'rel-nota', t)); }); }
        raiz.appendChild(s);
    }
    function renderEscopo(raiz) {
        return get('/api/relatorio?' + params.toString()).then(function (d) {
            limpa(raiz);
            var e = d.escopo, um = e.nomes.length === 1;
            cabecalho(raiz, 'Relatório de vulnerabilidades', (um ? 'Servidor: ' : (params.get('grupo') ? 'Grupo: ' : 'Seleção: ')) + e.titulo + (um ? '' : ' (' + fmt(e.nomes.length) + ' máquinas)'), d.gerado_em);
            if (!e.nomes.length) { raiz.appendChild(el('p', 'erro', 'Nenhuma máquina encontrada para este pedido.')); return; }
            if (e.nao_encontrados.length) raiz.appendChild(el('p', 'rel-nota', 'Não encontrados (ignorados): ' + e.nao_encontrados.join(', ')));
            var g = d.gravidade, kev = d.kev;
            var desc0 = d.tabela.filter(function (l) { return l.agente && l.agente !== 'active'; }).length;
            executivo(raiz, [
                { t: (um ? 'Situação: ' : 'Situação: ' + fmt(d.com_critica) + ' de ' + fmt(d.servidores) + ' máquinas têm vulnerabilidade crítica; ') + fmt(g.Critical) + ' registros críticos, ' + fmt(g.High) + ' altos, ' + fmt(g.Medium) + ' médios.' },
                kev.cves ? { t: 'Prioridade 1: ' + fmt(kev.cves) + ' CVE(s) já exploradas na prática (lista da CISA). Corrigir antes de tudo.', alerta: true } : { t: 'Nenhuma CVE da lista da CISA (exploradas) foi encontrada.' },
                itemGanho(d.pacotes),
                d.total ? { t: pctN(d.com_correcao, d.total) + '% dos registros já têm correção publicada: bastam as atualizações.' } : null,
                desc0 ? { t: fmt(desc0) + ' máquina' + (desc0 === 1 ? '' : 's') + ' com agente desconectado: os dados ' + (desc0 === 1 ? 'dela podem' : 'delas podem') + ' estar desatualizados.', alerta: true } : null]);
            var s1 = sec(raiz, 'Resumo');
            s1.appendChild(el('p', 'rel-resumo', (um ? 'Esta máquina tem ' : fmt(d.com_critica) + ' das ' + fmt(d.servidores) + ' máquinas deste relatório têm vulnerabilidade crítica. Ao todo são ') +
                fmt(g.Critical) + ' registros críticos, ' + fmt(g.High) + ' altos, ' + fmt(g.Medium) + ' médios e ' + fmt(g.Low) + ' baixos. ' +
                (d.total ? Math.round(100 * d.com_correcao / d.total) + '% têm correção publicada: bastam as atualizações. ' : '') +
                (kev.cves ? fmt(kev.cves) + ' CVE(s) estão na lista da CISA de vulnerabilidades já exploradas na prática' + (um ? '.' : ', em ' + fmt(kev.servidores) + ' máquinas.') : 'Nenhuma CVE da lista da CISA (exploradas) foi encontrada.')));
            if (!um) kpis(s1, g, kev.cves);  // numa maquina so, os KPIs ficam na secao dela
            var gr = el('div', 'rel-2col');
            var a = sec(gr, 'Por gravidade', 'sem-quebra'); a.appendChild(C.donut(SEV.map(function (s) { return { t: SEV_PT[s], n: g[s], cls: 's-' + s }; }), { v: C.curto(g.total), r: 'registros' }));
            var b = sec(gr, 'Tem correção?', 'sem-quebra'), desc = Math.max(0, d.total - d.com_correcao - d.sem_correcao);
            b.appendChild(C.donut([{ t: 'Com correção', n: d.com_correcao, cls: 's-ok' }, { t: 'Sem correção publicada', n: d.sem_correcao, cls: 's-sem' }, { t: 'Versão desconhecida', n: desc, cls: 's-desc' }],
                { v: d.total ? Math.round(100 * d.com_correcao / d.total) + '%' : '0%', r: 'é só atualizar' }));
            raiz.appendChild(gr);
            if (!um) {
                var s2 = sec(raiz, 'Por máquina', 'sem-quebra');
                s2.appendChild(tab([{ t: 'Máquina', f: function (l) { return l.nome; } }, { t: 'Tipo', f: function (l) { return l.tipo; } }, { t: 'Sistema', f: function (l) { return l.so; } },
                    { t: 'Críticas', num: true, f: function (l) { return fmt(l.Critical); } }, { t: 'Altas', num: true, f: function (l) { return fmt(l.High); } },
                    { t: 'Médias', num: true, f: function (l) { return fmt(l.Medium); } }].concat(d.tabela.some(function (l) { return l.agente; }) ? [{ t: 'Agente', f: function (l) { return l.agente === 'active' ? 'ativo' : (l.agente ? 'desconectado' : '—'); } }] : []),
                    d.tabela.slice().sort(function (x, y) { return y.Critical - x.Critical || y.High - x.High; })));
            }
            if (kev.cves && !d.detalhes.length) tabelaKev(sec(raiz, '🔥 Exploradas ativamente (CISA): corrigir primeiro', 'sem-quebra'), kev.top);
            if (!um && d.pacotes.length) {
                var s4 = sec(raiz, 'Onde um patch resolve mais (neste grupo)', 'sem-quebra');
                s4.appendChild(tab([{ t: 'Pacote / programa', f: function (l) { return (l.kev ? '🔥 ' : '') + l.nome; } }, { t: 'Máquinas', num: true, f: function (l) { return fmt(l.servidores); } },
                    { t: 'Crít.', num: true, f: function (l) { return fmt(l.sev.Critical); } }, { t: 'Altas', num: true, f: function (l) { return fmt(l.sev.High); } },
                    { t: 'Atualizar para', f: function (l) { return l.corrigir_para || '—'; } }], d.pacotes));
            }
            if (d.detalhes.length) d.detalhes.forEach(function (x) { secaoServidor(raiz, x); });
            else if (!um) raiz.appendChild(el('p', 'rel-nota', 'Para ver o plano de correção de cada máquina, gere o relatório de uma máquina (ou de uma seleção de até 8).'));
            rodape(raiz);
        });
    }

    var raiz = $('rel');
    (params.get('servidores') || params.get('grupo') ? renderEscopo(raiz) : renderGeral(raiz)).catch(function (e) {
        if (e.message !== 'sessao') { limpa(raiz); raiz.appendChild(el('p', 'erro', e.message && e.message !== 'erro' ? e.message : 'Não foi possível montar o relatório.')); }
    });
    $('imprimir').addEventListener('click', function () { window.print(); });
})();
