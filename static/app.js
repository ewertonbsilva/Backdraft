// Backdraft. Todo texto vem do servidor e entra via textContent (nunca innerHTML): nomes de pacote, versões e
// descrições vêm das máquinas inventariadas e do feed de CVEs.
(function () {
    'use strict';
    var C = window.Charts, el = C.el, fmt = C.fmt;
    var BASE = document.body.getAttribute('data-base') || '';
    var SEV = C.SEV, SEV_PT = C.SEV_PT;
    var estado = { sel: {}, filtrados: [], servidores: [], agentesConhecido: false, sevs: { Critical: true, High: true, Medium: true, Low: false, Outra: false }, pagina: 0, pacotes: null, plano: null };
    var aba = 'geral', timerBusca = null, atividade = false, timerGeral = null;

    // ------------------------------------------------------------ utilidades
    function $(id) { return document.getElementById(id); }
    function limpa(n) { while (n.firstChild) n.removeChild(n.firstChild); }
    function aviso(msg) { var a = $('aviso'); a.hidden = !msg; a.textContent = msg || ''; }
    function qs(o) {
        return Object.keys(o).filter(function (k) { return o[k] !== '' && o[k] !== null && o[k] !== undefined && o[k] !== false; })
            .map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(o[k] === true ? '1' : o[k]); }).join('&');
    }
    function api(caminho, usuario) {
        var h = { 'Accept': 'application/json' };
        if (usuario || atividade) { h['X-Atividade'] = '1'; atividade = false; }
        return fetch(BASE + caminho, { credentials: 'same-origin', headers: h }).then(function (r) {
            if (r.status === 401) { location.href = BASE + '/login'; throw new Error('sessao'); }
            if (r.status === 403) { aviso('Acesso negado: este endereço de rede não está liberado para o painel.'); throw new Error('sessao'); }
            return r.json().then(function (d) { if (!r.ok) throw new Error(d.erro || 'erro'); return d; });
        });
    }
    function falha(e) { if (e.message !== 'sessao') aviso(e.message && e.message !== 'erro' ? e.message : 'Não foi possível consultar o painel.'); }
    function atualizado(t) { $('atualizado').textContent = t || ''; }
    function selo(sev) { return el('span', 'sev ' + sev, SEV_PT[sev] || sev); }
    function nota(v) { return v === null || v === undefined ? '—' : Number(v).toFixed(1).replace('.', ','); }
    function pct(v) { return v === null || v === undefined ? '—' : (v * 100 < 1 ? '<1' : (v * 100).toFixed(v * 100 < 10 ? 1 : 0).replace('.', ',')) + '%'; }
    function dia(d) { return d && d.length >= 10 ? d.slice(8, 10) + '/' + d.slice(5, 7) : d; }
    function partes(o) { return SEV.slice(0, 4).map(function (s) { return { n: o[s] || 0, cls: 's-' + s, t: SEV_PT[s] }; }); }

    function tabela(t, cols, linhas, o) {
        o = o || {};
        var ord = t._ord || (t._ord = { k: o.ordem || null, asc: !!o.asc });
        limpa(t);
        if (!linhas.length) { var r0 = el('tr'), d0 = el('td', 'vazio', o.vazio || 'Nada para mostrar.'); d0.colSpan = cols.length; r0.appendChild(d0); t.appendChild(r0); return; }
        var dados = linhas.slice();
        if (ord.k) {
            var col = cols.filter(function (c) { return c.k === ord.k; })[0] || {}, ch = col.ord || ord.k;
            dados.sort(function (a, b) {
                var x = a[ch], y = b[ch], r;
                r = (typeof x === 'number' && typeof y === 'number') ? x - y : String(x == null ? '' : x).localeCompare(String(y == null ? '' : y), 'pt-BR', { numeric: true });
                return ord.asc ? r : -r;
            });
        }
        var cab = el('tr');
        cols.forEach(function (c) {
            var th = el('th', (c.num ? 'num ' : '') + (o.semOrdem ? '' : 'ord'), c.t + (ord.k === c.k ? (ord.asc ? ' ▲' : ' ▼') : ''));
            if (!o.semOrdem) {
                th.tabIndex = 0;
                var f = function () { if (ord.k === c.k) ord.asc = !ord.asc; else { ord.k = c.k; ord.asc = !c.num; } tabela(t, cols, linhas, o); };
                th.addEventListener('click', f);
                th.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') f(); });
            }
            cab.appendChild(th);
        });
        var th = el('thead'); th.appendChild(cab); t.appendChild(th);
        var tb = el('tbody');
        dados.slice(0, o.limite || 2000).forEach(function (l) {
            var tr = el('tr');
            if (o.clique) {
                tr.className = 'clicavel'; tr.tabIndex = 0;
                tr.addEventListener('click', function () { o.clique(l); });
                tr.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') o.clique(l); });
            }
            cols.forEach(function (c) {
                var td = el('td', (c.num ? 'num ' : '') + (c.cls || ''));
                var v = c.f ? c.f(l) : l[c.k];
                if (v instanceof Node) td.appendChild(v); else td.textContent = v === null || v === undefined ? '' : String(v);
                tr.appendChild(td);
            });
            tb.appendChild(tr);
        });
        t.appendChild(tb);
    }
    function linkCve(id) {
        var a = el('a', 'ext', id);
        a.href = 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(id);
        a.target = '_blank'; a.rel = 'noopener noreferrer';
        a.addEventListener('click', function (e) { e.stopPropagation(); });
        return a;
    }
    function cveCelula(l) {
        var s = el('span'); s.appendChild(linkCve(l.cve));
        if (l.kev) { var f = el('span', 'tag-kev', '🔥'); f.title = 'Já explorada ativamente (lista da CISA)' + (l.kev_prazo ? ' · prazo CISA: ' + l.kev_prazo : '') + (l.ransomware ? ' · usada em ransomware' : ''); s.appendChild(f); }
        return s;
    }
    function atualizarPara(l) {
        if (l.corrigir_para) return l.corrigir_para;
        return l.situacao === 'sem' ? 'sem correção publicada' : (l.situacao === 'ate' ? 'versão corrigida desconhecida' : '—');
    }
    function cartaoVazio(box, msg) { limpa(box); box.appendChild(el('div', 'vazio', msg)); }

    // ------------------------------------------------------------ abas
    function mostrar(nome) {
        aba = nome;
        Array.prototype.forEach.call(document.querySelectorAll('#abas button'), function (b) { b.classList.toggle('ativa', b.getAttribute('data-aba') === nome); });
        Array.prototype.forEach.call(document.querySelectorAll('.aba'), function (a) { a.hidden = a.id !== 'aba-' + nome; });
        aviso('');
        if (nome === 'geral') carregarGeral(true);
        if (nome === 'servidores') carregarServidores();
        if (nome === 'pacotes') carregarPacotes();
        if (nome === 'vulns') carregarVulns(false);
        if (nome === 'corrigir') prepararCorrigir();
        if (nome === 'ajuda') montarAjuda();
    }

    // ------------------------------------------------------------ visão geral (dashboard)
    function carregarGeral(usuario) {
        Promise.all([api('/api/resumo', usuario), api('/api/historico'), listaServidores().catch(function () { return []; }),
            api('/api/pacotes').then(function (d) { estado.pacotes = d.pacotes; return d.pacotes; }).catch(function () { return []; })]).then(function (x) {
            desenharGeral(x[0], x[1].serie || [], x[2], x[3]);
            atualizado(x[0].gerado_em);
        }).catch(falha);
    }
    function delta(serie, chave, atual) {
        if (serie.length < 2) return null;
        var ant = serie[serie.length - 2].grav ? serie[serie.length - 2].grav[chave] : null;
        return ant === null || ant === undefined ? null : atual - ant;
    }
    function kpi(box, cfg) {
        var c = el('div', 'kpi ' + (cfg.cls || ''));
        c.appendChild(el('div', 'kpi-t', cfg.t));
        var l = el('div', 'kpi-l'); l.appendChild(el('div', 'valor', fmt(cfg.v)));
        var sp = cfg.spark && C.spark(cfg.spark, cfg.cls); if (sp) l.appendChild(sp);
        c.appendChild(l);
        if (cfg.sub) c.appendChild(el('div', 'sub', cfg.sub));
        if (cfg.delta !== null && cfg.delta !== undefined) {
            var d = el('div', 'delta ' + (cfg.delta > 0 ? 'sobe' : (cfg.delta < 0 ? 'desce' : 'igual')), (cfg.delta > 0 ? '▲ +' : (cfg.delta < 0 ? '▼ ' : '● ')) + fmt(cfg.delta) + ' vs. dia anterior');
            c.appendChild(d);
        }
        box.appendChild(c);
    }
    function desenharGeral(d, serie, lista, pacotes) {
        var g = d.gravidade, kev = d.kev;
        // ---- hero
        var hero = $('hero'); limpa(hero);
        var tx = el('div', 'hero-tx');
        var h = el('h1'); h.appendChild(el('b', '', fmt(d.com_critica))); h.appendChild(document.createTextNode(' de ' + fmt(d.servidores) + ' servidores têm vulnerabilidade crítica'));
        tx.appendChild(h);
        var ul = el('ul', 'hero-pontos');
        if (kev.cves) ul.appendChild(el('li', 'kev', '🔥 ' + fmt(kev.cves) + ' CVE(s) já exploradas na prática (CISA) em ' + fmt(kev.servidores) + ' servidores'));
        if (d.mudanca && d.mudanca.novas !== null && d.mudanca.novas !== undefined)
            ul.appendChild(el('li', '', 'Hoje: ' + fmt(d.mudanca.novas) + ' crítica(s) nova(s) · ' + fmt(d.mudanca.corrigidas) + ' corrigida(s)'));
        ul.appendChild(el('li', '', fmt(d.com_correcao) + ' registros têm correção publicada: é só atualizar'));
        if (d.kernels && d.kernels.reiniciar.length) ul.appendChild(el('li', '', fmt(d.kernels.reiniciar.length) + ' servidor(es) com kernel novo instalado esperando reinício'));
        tx.appendChild(ul); hero.appendChild(tx);
        var kp = el('div', 'kpis-hero');
        var ult = function (ch) { return serie.slice(-14).map(function (f) { return f.grav ? f.grav[ch] : 0; }); };
        kpi(kp, { t: 'Críticas', v: g.Critical, cls: 'Critical', spark: ult('Critical'), delta: delta(serie, 'Critical', g.Critical), sub: 'resolver primeiro' });
        kpi(kp, { t: 'Altas', v: g.High, cls: 'High', spark: ult('High'), delta: delta(serie, 'High', g.High) });
        kpi(kp, { t: 'Médias', v: g.Medium, cls: 'Medium', spark: ult('Medium'), delta: delta(serie, 'Medium', g.Medium) });
        kpi(kp, { t: 'Baixas', v: g.Low, cls: 'Low', spark: ult('Low') });
        kpi(kp, { t: 'Exploradas 🔥', v: kev.cves, cls: 'Kev', sub: kev.cves ? 'CVEs na lista da CISA' : (d.enriquecimento.kev_cves ? 'nenhuma nos seus servidores' : 'lista ainda sendo baixada') });
        hero.appendChild(kp);

        // ---- gravidade (rosca)
        var b = $('g-grav'); limpa(b);
        b.appendChild(C.donut(SEV.map(function (s) { return { t: SEV_PT[s], n: g[s], cls: 's-' + s }; }), { v: C.curto(g.total), r: 'registros' }));
        // ---- tendência
        b = $('g-trend'); limpa(b);
        b.appendChild(C.linhas(serie.map(function (f) { return dia(f.dia); }), [
            { t: 'Críticas', cls: 's-Critical', v: serie.map(function (f) { return f.grav.Critical; }) },
            { t: 'Altas', cls: 's-High', v: serie.map(function (f) { return f.grav.High; }) },
            { t: 'Médias', cls: 's-Medium', v: serie.map(function (f) { return f.grav.Medium; }) }]));
        // ---- tem correção?
        b = $('g-corr'); limpa(b);
        var desc = Math.max(0, d.total - d.com_correcao - d.sem_correcao);
        b.appendChild(C.donut([{ t: 'Com correção', n: d.com_correcao, cls: 's-ok' }, { t: 'Sem correção publicada', n: d.sem_correcao, cls: 's-sem' }, { t: 'Versão desconhecida', n: desc, cls: 's-desc' }],
            { v: d.total ? Math.round(100 * d.com_correcao / d.total) + '%' : '0%', r: 'é só atualizar' }));
        // ---- servidores com mais críticas
        b = $('g-top'); limpa(b);
        b.appendChild(C.pilha(d.top_servidores.map(function (s) {
            return { t: s.nome, sub: s.tipo, partes: partes(s), total: fmt(s.Critical) + ' crít.', clique: function () { irCorrigir(s.nome); } };
        })));
        // ---- por sistema
        b = $('g-so'); limpa(b);
        b.appendChild(C.pilha(d.por_so.map(function (s) { return { t: s.so, sub: fmt(s.servidores) + ' servidores', partes: partes(s), total: C.curto(s.total) }; })));
        // ---- estações x servidores
        b = $('g-tipo'); limpa(b);
        var tp = Object.keys(d.tipos).map(function (k) { var x = d.tipos[k]; return { t: k === 'Servidor' ? 'Servidores' : 'Estações', sub: fmt(x.servidores) + ' máquinas · ' + fmt(x.com_critica) + ' com crítica', partes: partes(x), total: C.curto(x.Critical + x.High + x.Medium + x.Low) }; });
        b.appendChild(C.pilha(tp));
        // ---- exploradas
        desenharKev(d);
        // ---- pacotes
        b = $('g-pkg'); limpa(b);
        var top = (pacotes && pacotes.length) ? pacotes.slice(0, 10).map(function (p) {
            return { t: p.nome, sub: fmt(p.servidores) + ' servidor(es)' + (p.corrigir_para ? ' · atualizar para ' + p.corrigir_para : ''), partes: partes(p.sev), total: C.curto(p.sev.Critical) + ' crít.', clique: function () { irPacote(p.nome); } };
        }) : d.pacotes.slice(0, 10).map(function (p) {
            return { t: p.nome, sub: fmt(p.servidores) + ' servidor(es)', partes: [{ n: p.n, cls: 's-Pacote', t: 'registros' }], total: C.curto(p.n), clique: function () { irPacote(p.nome); } };
        });
        b.appendChild(C.pilha(top));
        // ---- por ano
        b = $('g-ano'); limpa(b);
        b.appendChild(C.colunas(d.por_ano.slice(-14).map(function (a) { return { t: a.ano, partes: partes(a).concat([{ n: a.Outra, cls: 's-Outra', t: 'Sem classificação' }]) }; })));
        // ---- kernels
        desenharKernels(d.kernels);
        // ---- agentes
        desenharAgentes(d, lista);
    }
    function desenharKev(d) {
        var b = $('g-kev'), kev = d.kev, en = d.enriquecimento; limpa(b);
        if (!en.kev_cves) { b.appendChild(el('div', 'vazio', 'A lista da CISA ainda não foi baixada' + (en.erro ? ' (' + en.erro + ')' : '') + '. O painel tenta de novo a cada hora.')); return; }
        if (!kev.cves) { b.appendChild(el('div', 'vazio ok', '✅ Nenhuma das ' + fmt(en.kev_cves) + ' CVEs da lista da CISA aparece nos seus servidores.')); return; }
        var grade = el('div', 'kev-grade');
        var esq = el('div', 'kev-lista');
        kev.top.forEach(function (t) {
            var c = el('div', 'kev-item'); var cab = el('div', 'kev-cab'); cab.appendChild(linkCve(t.cve));
            if (t.ransomware) cab.appendChild(el('span', 'tag-rans', 'ransomware'));
            c.appendChild(cab); c.appendChild(el('div', 'kev-nome', t.nome || ''));
            var m = el('div', 'kev-meta'); m.appendChild(el('span', '', fmt(t.servidores) + ' servidor(es)')); m.appendChild(el('span', '', 'EPSS ' + pct(t.epss)));
            c.appendChild(m); c.addEventListener('click', function () { irVulns(t.cve); }); c.tabIndex = 0;
            esq.appendChild(c);
        });
        var dir = el('div', 'kev-lado');
        dir.appendChild(el('h3', '', 'Servidores mais expostos'));
        dir.appendChild(C.pilha(kev.servidores_top.map(function (s) { return { t: s.nome, partes: [{ n: s.registros, cls: 's-Kev', t: 'registros exploráveis' }], total: fmt(s.registros), clique: function () { irCorrigir(s.nome); } }; })));
        dir.appendChild(el('p', 'nota', 'Fonte: CISA KEV (' + fmt(en.kev_cves) + ' CVEs no catálogo) e EPSS (FIRST), listas públicas. EPSS é a chance estimada de exploração em 30 dias.'));
        grade.appendChild(esq); grade.appendChild(dir); b.appendChild(grade);
    }
    function desenharKernels(k) {
        var b = $('g-kern'); limpa(b);
        if (!k || (!k.reiniciar.length && !k.antigos.length)) { b.appendChild(el('div', 'vazio ok', '✅ Nenhum kernel antigo sobrando nem reinício pendente detectado.')); return; }
        var grade = el('div', 'dois-col');
        var a = el('div'); a.appendChild(el('h3', '', 'Reinício pendente (' + k.reiniciar.length + ')'));
        a.appendChild(el('p', 'nota', 'Já existe kernel mais novo instalado, mas o servidor segue no antigo.'));
        a.appendChild(C.pilha(k.reiniciar.map(function (s) { return { t: s.nome, sub: s.em_uso + ' → ' + s.novo.replace(/^linux-image-/, ''), partes: [{ n: 1, cls: 's-Medium', t: 'reiniciar' }], total: '↻', clique: function () { irCorrigir(s.nome); } }; })));
        var z = el('div'); z.appendChild(el('h3', '', 'Kernels antigos removíveis (' + fmt(k.servidores_antigos) + ' servidores)'));
        z.appendChild(el('p', 'nota', fmt(k.registros_antigos) + ' registros de CVE somem com um “apt autoremove --purge”, sem atualizar nada.'));
        z.appendChild(C.pilha(k.antigos.slice(0, 8).map(function (s) { return { t: s.nome, sub: fmt(s.pacotes) + ' pacotes · em uso ' + s.em_uso, partes: [{ n: s.registros, cls: 's-Pacote', t: 'registros' }], total: C.curto(s.registros), clique: function () { irCorrigir(s.nome); } }; })));
        grade.appendChild(a); grade.appendChild(z); b.appendChild(grade);
    }
    function desenharAgentes(d, lista) {
        var b = $('g-agentes'); limpa(b);
        if (!d.agentes.conhecido) {
            b.appendChild(el('div', 'vazio', 'Status dos agentes indisponível: o usuário de leitura (backdraft-read) ainda não tem permissão no índice wazuh-monitoring-*. Os dados de vulnerabilidade seguem normais.'));
            return;
        }
        var grade = el('div', 'dois-col');
        grade.appendChild(C.donut([{ t: 'Ativos', n: d.agentes.ativos, cls: 's-ok' }, { t: 'Desconectados', n: d.agentes.desconectados, cls: 's-Critical' }], { v: String(d.agentes.ativos + d.agentes.desconectados), r: 'agentes' }));
        var z = el('div'); z.appendChild(el('h3', '', 'Desconectados com mais críticas'));
        z.appendChild(el('p', 'nota', 'Os dados deles podem estar velhos: reinstale o agente ou retire do Wazuh.'));
        z.appendChild(C.pilha(lista.filter(function (s) { return s.agente && s.agente !== 'active'; }).slice(0, 8).map(function (s) {
            return { t: s.nome, sub: 'visto em ' + (s.visto || '—').replace('T', ' '), partes: partes(s), total: fmt(s.Critical) + ' crít.', clique: function () { irCorrigir(s.nome); } };
        })));
        grade.appendChild(z); b.appendChild(grade);
    }

    // ------------------------------------------------------------ servidores
    function listaServidores() {
        return estado.servidores.length ? Promise.resolve(estado.servidores) :
            api('/api/servidores').then(function (d) { estado.servidores = d.servidores; estado.agentesConhecido = d.agentes_conhecido; return d.servidores; });
    }
    function preencherSelects() {
        ['v-serv', 'c-serv'].forEach(function (id) {
            var s = $(id); if (s.options.length > 1) return;
            estado.servidores.forEach(function (x) { var o = el('option', '', x.nome); o.value = x.nome; s.appendChild(o); });
        });
        var gr = $('s-grupo');
        if (gr && gr.options.length <= 6) {
            var plats = {};
            estado.servidores.forEach(function (x) { if (x.plataforma && !plats[x.plataforma]) { plats[x.plataforma] = 1; var o = el('option', '', 'Só sistema: ' + x.plataforma); o.value = 'so:' + x.plataforma; gr.appendChild(o); } });
        }
        var so = $('s-so');
        if (so.options.length === 1) {
            var vistos = {};
            estado.servidores.forEach(function (x) { if (x.plataforma && !vistos[x.plataforma]) { vistos[x.plataforma] = 1; var o = el('option', '', x.plataforma); o.value = x.plataforma; so.appendChild(o); } });
        }
    }
    function carregarServidores() { listaServidores().then(function () { preencherSelects(); desenharServidores(); }).catch(falha); }
    function desenharServidores() {
        var q = $('s-q').value.trim().toLowerCase(), so = $('s-so').value, tipo = $('s-tipo').value, crit = $('s-crit').checked, desc = $('s-desc').checked;
        var l = estado.servidores.filter(function (x) {
            return (!q || (x.nome + ' ' + x.so).toLowerCase().indexOf(q) >= 0) && (!so || x.plataforma === so) && (!tipo || x.tipo === tipo) &&
                (!crit || x.Critical > 0) && (!desc || (x.agente && x.agente !== 'active'));
        });
        estado.filtrados = l.map(function (x) { return x.nome; });
        $('n-serv').textContent = fmt(l.length) + ' de ' + fmt(estado.servidores.length) + ' máquinas. Clique em uma linha para ver o plano de correção.' +
            (estado.agentesConhecido ? '' : ' (Status do agente indisponível: falta permissão de leitura no índice de monitoramento.)');
        atualizarSel();
        tabela($('t-serv'), [
            { k: '_sel', t: '', ord: 'nome', f: function (x) {
                var c = el('input'); c.type = 'checkbox'; c.checked = !!estado.sel[x.nome]; c.setAttribute('aria-label', 'Selecionar ' + x.nome);
                c.addEventListener('click', function (e) { e.stopPropagation(); alternarSel(x.nome, c.checked); });
                return c; } },
            { k: 'nome', t: 'Servidor' }, { k: 'tipo', t: 'Tipo', f: function (x) { return el('span', 'tag-tipo ' + (x.tipo === 'Servidor' ? 'srv' : 'est'), x.tipo); } },
            { k: 'so', t: 'Sistema' },
            { k: 'agente', t: 'Agente', f: function (x) { var s = el('span', 'tag-ag ' + (x.agente === 'active' ? 'on' : (x.agente ? 'off' : 'nd')), x.agente === 'active' ? 'ativo' : (x.agente ? 'desconectado' : '—')); if (x.visto) s.title = 'visto em ' + x.visto.replace('T', ' '); return s; } },
            { k: 'Critical', t: 'Críticas', num: true }, { k: 'High', t: 'Altas', num: true }, { k: 'Medium', t: 'Médias', num: true },
            { k: 'Low', t: 'Baixas', num: true }, { k: 'total', t: 'Total', num: true }], l,
            { ordem: 'Critical', clique: function (x) { irCorrigir(x.nome); } });
    }

    // ------------------------------------------------------------ selecao de máquinas e relatórios
    var LIMITE_SEL = 60;
    function nomesSel() { return Object.keys(estado.sel).filter(function (n) { return estado.sel[n]; }); }
    function atualizarSel() {
        var n = nomesSel().length;
        $('n-sel').textContent = n ? fmt(n) + ' máquina(s) selecionada(s)' + (n > LIMITE_SEL ? ' (máximo ' + LIMITE_SEL + ' por relatório: use um grupo)' : '.') : 'Nenhuma máquina selecionada.';
        $('s-rel').disabled = !n || n > LIMITE_SEL;
    }
    function alternarSel(nome, marcado) { if (marcado) estado.sel[nome] = true; else delete estado.sel[nome]; atualizarSel(); }
    function abrirRelatorio(params) { window.open(BASE + '/relatorio?' + qs(params), '_blank', 'noopener'); }
    $('s-todos').addEventListener('click', function () { estado.filtrados.forEach(function (n) { estado.sel[n] = true; }); desenharServidores(); });
    $('s-limpar').addEventListener('click', function () { estado.sel = {}; desenharServidores(); });
    $('s-rel').addEventListener('click', function () { abrirRelatorio({ servidores: nomesSel().join(',') }); });
    $('s-grupo').addEventListener('change', function () { var g = $('s-grupo').value; if (g) abrirRelatorio({ grupo: g }); $('s-grupo').value = ''; });
    $('c-rel').addEventListener('click', function () { if ($('c-serv').value) abrirRelatorio({ servidores: $('c-serv').value }); });

    // ------------------------------------------------------------ por pacote
    var GER = { apt: 'Linux (apt)', dnf: 'Linux (dnf)', snap: 'Snap', 'windows-so': 'Windows (sistema)', 'windows-prog': 'Programa Windows', outro: 'Outro' };
    function carregarPacotes() {
        var f = estado.pacotes ? Promise.resolve(estado.pacotes) : api('/api/pacotes', true).then(function (d) { estado.pacotes = d.pacotes; atualizado(d.gerado_em); return d.pacotes; });
        f.then(desenharPacotes).catch(falha);
    }
    function desenharPacotes() {
        var q = $('p-q').value.trim().toLowerCase(), ger = $('p-ger').value, kev = $('p-kev').checked;
        var l = (estado.pacotes || []).filter(function (p) { return (!q || p.nome.toLowerCase().indexOf(q) >= 0) && (!ger || p.gerenciador === ger) && (!kev || p.kev > 0); })
            .map(function (p) { return Object.assign({ c: p.sev.Critical, h: p.sev.High, m: p.sev.Medium }, p); });
        $('n-pkgs').textContent = fmt(l.length) + ' pacotes (os 400 com mais críticas). Clique para ver em quais servidores estão.';
        tabela($('t-pkgs'), [
            { k: 'nome', t: 'Pacote / programa', f: function (p) { var s = el('span', '', p.nome); if (p.kev) { var f = el('span', 'tag-kev', '🔥'); f.title = fmt(p.kev) + ' registro(s) de CVEs exploradas ativamente'; s.appendChild(f); } return s; } },
            { k: 'gerenciador', t: 'Tipo', f: function (p) { return GER[p.gerenciador] || p.gerenciador; } },
            { k: 'servidores', t: 'Servidores', num: true }, { k: 'c', t: 'Crít.', num: true }, { k: 'h', t: 'Altas', num: true }, { k: 'm', t: 'Méd.', num: true },
            { k: 'corrigir_para', t: 'Atualizar para', cls: 'versao', f: function (p) { return p.corrigir_para || '—'; } }], l,
            { ordem: 'c', clique: function (p) { abrirPacoteGeral(p.nome); } });
    }
    function irPacote(nome) { $('p-q').value = nome; mostrar('pacotes'); }
    function abrirPacoteGeral(pacote) {
        var cx = caixa(pacote, 'Em quais servidores este pacote aparece'), corpo = el('p', 'nota', 'Carregando…'); cx.appendChild(corpo);
        api('/api/pacote?' + qs({ nome: pacote }), true).then(function (d) {
            cx.removeChild(corpo);
            cx.appendChild(el('p', 'nota', fmt(d.servidores.length) + ' servidores. Clique em um para ver o plano de correção dele.'));
            var rol = el('div', 'rolagem'), tb = el('table'); rol.appendChild(tb); cx.appendChild(rol);
            tabela(tb, [{ k: 'nome', t: 'Servidor' }, { k: 'instalada', t: 'Instalada', cls: 'versao' }, { k: 'corrigir_para', t: 'Atualizar para', cls: 'versao', f: function (x) { return x.corrigir_para || '—'; } },
                { k: 'c', t: 'Crít.', num: true, f: function (x) { return x.sev.Critical; } }, { k: 'h', t: 'Altas', num: true, f: function (x) { return x.sev.High; } },
                { k: 'm', t: 'Méd.', num: true, f: function (x) { return x.sev.Medium; } }], d.servidores,
                { semOrdem: true, clique: function (x) { fecharModal(); irCorrigir(x.nome); } });
        }).catch(function (e) { corpo.textContent = e.message === 'sessao' ? '' : (e.message || 'Erro'); falha(e); });
    }

    // ------------------------------------------------------------ vulnerabilidades
    function montarChips() {
        var box = $('f-sev'); if (box.children.length) return;
        SEV.forEach(function (s) {
            var b = el('button', 'chip ' + s); b.type = 'button';
            b.appendChild(el('i')); b.appendChild(document.createTextNode(SEV_PT[s]));
            b.setAttribute('aria-pressed', estado.sevs[s] ? 'true' : 'false');
            b.addEventListener('click', function () { estado.sevs[s] = !estado.sevs[s]; b.setAttribute('aria-pressed', estado.sevs[s] ? 'true' : 'false'); estado.pagina = 0; carregarVulns(true); });
            box.appendChild(b);
        });
    }
    function filtrosVulns() {
        return { sev: SEV.filter(function (s) { return estado.sevs[s]; }).join(','), servidor: $('v-serv').value, q: $('v-q').value.trim(), corrigivel: $('v-corr').checked, exploradas: $('v-kev').checked };
    }
    function carregarVulns(usuario) {
        montarChips();
        listaServidores().then(preencherSelects).catch(function () {});
        var f = filtrosVulns();
        if (!f.sev) { limpa($('t-vulns')); $('n-vulns').textContent = 'Marque ao menos uma gravidade.'; $('v-pag').textContent = ''; return; }
        $('csv-vulns').href = BASE + '/api/vulns.csv?' + qs(f);
        api('/api/vulns?' + qs(Object.assign({ pagina: estado.pagina }, f)), usuario).then(function (d) {
            $('n-vulns').textContent = fmt(d.total) + ' registros' + (d.total > 10000 ? ' (a tela e o CSV mostram os 10.000 de maior nota; refine os filtros)' : '') + '. Ordenados pela nota (CVSS), da maior para a menor.';
            tabela($('t-vulns'), [
                { k: 'sev', t: 'Gravidade', f: function (l) { return selo(l.sev); } }, { k: 'nota', t: 'Nota', num: true, f: function (l) { return nota(l.nota); } },
                { k: 'cve', t: 'CVE', f: cveCelula }, { k: 'epss', t: 'EPSS', num: true, f: function (l) { return pct(l.epss); } },
                { k: 'servidor', t: 'Servidor' }, { k: 'pacote', t: 'Pacote' }, { k: 'instalada', t: 'Instalada', cls: 'versao' },
                { k: 'corrigir_para', t: 'Atualizar para', cls: 'versao', f: atualizarPara }, { k: 'publicada', t: 'Publicada' }], d.itens,
                { semOrdem: true, clique: function (l) { abrirPacote(l.servidor, l.pacote); } });
            var ultima = Math.max(0, Math.ceil(d.limite / d.tam) - 1);
            $('v-pag').textContent = 'Página ' + (d.pagina + 1) + ' de ' + (ultima + 1);
            $('v-ant').disabled = d.pagina <= 0; $('v-prox').disabled = d.pagina >= ultima;
        }).catch(falha);
    }
    function irVulns(texto) { $('v-q').value = texto; estado.pagina = 0; mostrar('vulns'); }

    // ------------------------------------------------------------ como corrigir
    function irCorrigir(nome) { mostrar('corrigir'); $('c-serv').value = nome; $('c-rel').disabled = !nome; carregarPlano(nome); }
    function prepararCorrigir() { listaServidores().then(preencherSelects).catch(falha); if ($('c-serv').value) carregarPlano($('c-serv').value); }
    function copiar(texto, botao) {
        var ok = function () { var t = botao.textContent; botao.textContent = 'Copiado'; setTimeout(function () { botao.textContent = t; }, 1500); };
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(texto).then(ok, function () { botao.textContent = 'Selecione e copie'; });
        else botao.textContent = 'Selecione e copie';
    }
    function carregarPlano(nome) {
        var res = $('c-res');
        if (!nome) { limpa(res); res.appendChild(el('p', 'nota', 'Escolha um servidor para ver o que atualizar, em que ordem, e o que fazer antes de corrigir.')); return; }
        limpa(res); res.appendChild(el('p', 'nota', 'Carregando…'));
        api('/api/servidor?' + qs({ nome: nome }), true).then(function (d) { estado.plano = d; desenharPlano(d); })
            .catch(function (e) { limpa(res); res.appendChild(el('p', 'erro', e.message === 'sessao' ? '' : (e.message || 'Erro'))); falha(e); });
    }
    function desenharPlano(d) {
        var res = $('c-res'), p = d.plano, i = d.info;
        limpa(res);
        var g = { Critical: 0, High: 0, Medium: 0, Low: 0, Outra: 0 };
        d.pacotes.forEach(function (x) { SEV.forEach(function (s) { g[s] += x.sev[s]; }); });
        var topo = el('div', 'kpis-plano');
        kpi(topo, { t: 'Críticas', v: g.Critical, cls: 'Critical' }); kpi(topo, { t: 'Altas', v: g.High, cls: 'High' });
        kpi(topo, { t: 'Médias', v: g.Medium, cls: 'Medium' }); kpi(topo, { t: 'Baixas', v: g.Low, cls: 'Low' });
        kpi(topo, { t: 'Exploradas 🔥', v: d.exploradas.length, cls: 'Kev', sub: 'registros na lista da CISA' });
        res.appendChild(topo);
        res.appendChild(el('p', 'nota', i.nome + ' · ' + i.tipo + ' · ' + i.so + (i.kernel ? ' · kernel em uso ' + i.kernel : '')));
        var plano = el('div', 'plano');

        if (d.exploradas.length) {
            var k = el('div', 'bloco kevb'); k.appendChild(el('h3', '', '🔥 Já exploradas na prática neste servidor: corrija primeiro'));
            var rol = el('div', 'rolagem'), tb = el('table'); rol.appendChild(tb); k.appendChild(rol); plano.appendChild(k);
            tabela(tb, [{ k: 'cve', t: 'CVE', f: cveCelula }, { k: 'sev', t: 'Gravidade', f: function (l) { return selo(l.sev); } }, { k: 'pacote', t: 'Pacote' },
                { k: 'instalada', t: 'Instalada', cls: 'versao' }, { k: 'corrigir_para', t: 'Atualizar para', cls: 'versao', f: atualizarPara },
                { k: 'epss', t: 'EPSS', num: true, f: function (l) { return pct(l.epss); } }, { k: 'kev_prazo', t: 'Prazo CISA' }], d.exploradas.slice(0, 30), { semOrdem: true });
        }
        var a = el('div', 'bloco antes'); a.appendChild(el('h3', '', '1. Antes de corrigir'));
        var ul = el('ul', 'lista-antes');
        p.antes.forEach(function (x) {
            var li = el('li'); li.appendChild(el('span', '', '☐'));
            var dv = el('div'); dv.appendChild(el('b', '', x.t + ': ')); dv.appendChild(document.createTextNode(x.d)); li.appendChild(dv); ul.appendChild(li);
        });
        a.appendChild(ul); plano.appendChild(a);
        if (p.passos.length) {
            var b = el('div', 'bloco passos'); b.appendChild(el('h3', '', '2. Comandos (copie e rode no servidor, como administrador)'));
            p.passos.forEach(function (x) {
                var c = el('div', 'cmd'); c.appendChild(el('div', 'cmd-t', x.t)); c.appendChild(el('code', '', x.c));
                var bt = el('button', 'botao pequeno', 'Copiar'); bt.type = 'button'; bt.addEventListener('click', function () { copiar(x.c, bt); });
                c.appendChild(bt); b.appendChild(c);
            });
            plano.appendChild(b);
        }
        if (p.notas.length) {
            var n = el('div', 'bloco notas'); n.appendChild(el('h3', '', p.passos.length ? '3. Observações' : '2. Observações'));
            p.notas.forEach(function (t) { n.appendChild(el('p', 'nota', t)); });
            plano.appendChild(n);
        }
        res.appendChild(plano);

        var cart = el('div', 'cartao larg'); cart.style.marginTop = '14px';
        cart.appendChild(el('h2', '', 'Pacotes e programas afetados'));
        var f = el('div', 'filtros'), sel = el('select'); sel.setAttribute('aria-label', 'Gravidade');
        [['mmh', 'Crítica, Alta e Média'], ['c', 'Só Críticas'], ['todas', 'Todas as gravidades']].forEach(function (o) { var op = el('option', '', o[1]); op.value = o[0]; sel.appendChild(op); });
        var corr = el('label', 'chk'), ck = el('input'); ck.type = 'checkbox'; corr.appendChild(ck); corr.appendChild(document.createTextNode(' só com versão corrigida'));
        f.appendChild(sel); f.appendChild(corr); cart.appendChild(f);
        var nt = el('p', 'nota'), rol2 = el('div', 'rolagem alta'), tb2 = el('table'); rol2.appendChild(tb2); cart.appendChild(nt); cart.appendChild(rol2);
        res.appendChild(cart);
        function redesenhar() {
            var m = sel.value;
            var l = d.pacotes.filter(function (x) {
                var ok = m === 'todas' ? true : (m === 'c' ? x.sev.Critical > 0 : (x.sev.Critical + x.sev.High + x.sev.Medium) > 0);
                return ok && (!ck.checked || x.corrigir_para);
            }).map(function (x) { return Object.assign({ rank: SEV.indexOf(x.sev_max) }, x); });
            nt.textContent = fmt(l.length) + ' de ' + fmt(d.pacotes.length) + ' pacotes. Os marcados com 🔥 vêm primeiro. Clique em uma linha para ver as CVEs.';
            tabela(tb2, [
                { k: 'rank', t: 'Gravidade', f: function (x) { return selo(x.sev_max); } }, { k: 'nota', t: 'Nota', num: true, f: function (x) { return nota(x.nota); } },
                { k: 'nome', t: 'Pacote / programa', f: function (x) {
                    var s = el('span', '', x.nome);
                    if (x.kev) { var k2 = el('span', 'tag-kev', '🔥'); k2.title = fmt(x.kev) + ' registro(s) de CVEs exploradas ativamente'; s.appendChild(k2); }
                    if (x.kernel === 'antigo') s.appendChild(el('span', 'tag-rein', 'kernel antigo: removível'));
                    if (x.kernel === 'novo') s.appendChild(el('span', 'tag-rein', 'kernel novo: reinicie'));
                    if (x.reinicia && x.corrigir_para && !x.kernel) s.appendChild(el('span', 'tag-rein', 'reinicia'));
                    return s; } },
                { k: 'instalada', t: 'Instalada', cls: 'versao' },
                { k: 'corrigir_para', t: 'Atualizar para', cls: 'versao', f: function (x) { return x.corrigir_para || (x.sem_correcao ? 'sem correção publicada' : (x.ate ? 'versão corrigida desconhecida' : '—')); } },
                { k: 'n', t: 'CVEs', num: true }, { k: 'c', t: 'Crít.', num: true, f: function (x) { return x.sev.Critical; } },
                { k: 'h', t: 'Altas', num: true, f: function (x) { return x.sev.High; } }, { k: 'm', t: 'Méd.', num: true, f: function (x) { return x.sev.Medium; } }], l,
                { ordem: 'rank', asc: true, clique: function (x) { abrirPacote(i.nome, x.nome); } });
        }
        sel.addEventListener('change', redesenhar); ck.addEventListener('change', redesenhar); redesenhar();
    }

    // ------------------------------------------------------------ modal
    function fecharModal() { var m = $('modal'); m.hidden = true; limpa(m); }
    function caixa(titulo) {
        var m = $('modal'); limpa(m); m.hidden = false;
        var cx = el('div', 'caixa'), cab = el('div', 'caixa-cab'), t = el('h2', '', titulo);
        var fe = el('button', 'fechar', 'Fechar'); fe.type = 'button'; fe.addEventListener('click', fecharModal);
        cab.appendChild(t); cab.appendChild(fe); cx.appendChild(cab); m.appendChild(cx);
        m.onclick = function (ev) { if (ev.target === m) fecharModal(); };
        return cx;
    }
    function abrirPacote(servidor, pacote) {
        var cx = caixa(pacote + ' · ' + servidor), corpo = el('p', 'nota', 'Carregando…'); cx.appendChild(corpo);
        api('/api/cves?' + qs({ servidor: servidor, pacote: pacote }), true).then(function (d) {
            cx.removeChild(corpo);
            cx.appendChild(el('p', 'nota', fmt(d.itens.length) + ' CVEs neste pacote (mais graves primeiro; no máximo 500).'));
            var rol = el('div', 'rolagem'), tb = el('table'); rol.appendChild(tb); cx.appendChild(rol);
            tabela(tb, [
                { k: 'sev', t: 'Gravidade', f: function (l) { return selo(l.sev); } }, { k: 'nota', t: 'Nota', num: true, f: function (l) { return nota(l.nota); } },
                { k: 'cve', t: 'CVE', f: cveCelula }, { k: 'epss', t: 'EPSS', num: true, f: function (l) { return pct(l.epss); } },
                { k: 'corrigir_para', t: 'Atualizar para', cls: 'versao', f: atualizarPara }, { k: 'publicada', t: 'Publicada' },
                { k: 'descricao', t: 'Descrição', cls: 'desc' }], d.itens, { semOrdem: true });
        }).catch(function (e) { corpo.textContent = e.message === 'sessao' ? '' : (e.message || 'Erro'); falha(e); });
    }

    // ------------------------------------------------------------ ajuda
    function montarAjuda() {
        var box = $('ajuda'); if (box.children.length) return;
        box.appendChild(el('h2', '', 'Como ler este painel'));
        var g = el('div', 'ajuda-g');
        function bl(t, ps) { var b = el('div', 'bloco'); b.appendChild(el('h3', '', t)); ps.forEach(function (x) { b.appendChild(el('p', '', x)); }); g.appendChild(b); }
        bl('Gravidade e nota', ['Crítica, Alta, Média e Baixa vêm da nota CVSS (0 a 10) de cada falha: quanto maior, mais fácil e mais danoso é explorar.',
            'Sem classificação: a falha ainda não recebeu nota. Não é “sem risco”.', 'As Críticas e as Médias aparecem marcadas por padrão (junto com as Altas, que ficam entre as duas).']);
        bl('🔥 Exploradas ativamente', ['A CISA (agência de segurança dos EUA) mantém uma lista pública de CVEs que já estão sendo usadas em ataques de verdade.',
            'Uma CVE com 🔥 deve ir para o início da fila, mesmo com nota média. O EPSS é a chance estimada (0 a 100%) de ser explorada nos próximos 30 dias.']);
        bl('“Tem correção?”', ['Com versão corrigida: o fabricante já publicou o patch. É só atualizar o pacote para a versão indicada (ou uma mais nova).',
            'Sem correção publicada: não há o que instalar agora. Reduza o risco (desligar o serviço, fechar a porta, restringir o acesso) e reavalie depois.',
            'Versão corrigida desconhecida: o Wazuh sabe que a versão instalada é afetada, mas não informa a versão corrigida.']);
        bl('Kernels', ['Ao atualizar o kernel, o antigo fica instalado. Cada kernel antigo carrega as suas próprias CVEs, que seguem aparecendo.',
            'Remover os que não estão em uso (apt autoremove --purge, DEPOIS de reiniciar no kernel novo) derruba esses registros sem atualizar mais nada.']);
        bl('De onde vêm os dados', ['Do Wazuh, que cruza os pacotes instalados em cada máquina com as bases de CVE (Canonical, Debian, AlmaLinux, NVD).',
            'O inventário de cada máquina é refeito a cada cerca de 1 hora. Depois de atualizar, a falha sai da lista no ciclo seguinte.',
            'Software compilado à mão, ou que não está no gerenciador de pacotes, não aparece.']);
        bl('O que este painel NÃO faz', ['Ele só lê e mostra. Não instala nada, não reinicia nada e não conecta nos servidores.',
            'Os comandos do “Como corrigir” são para uma pessoa copiar e rodar, depois de seguir a lista “Antes de corrigir”.',
            'Atualizar sem backup nem janela é o “backdraft”: abrir a porta de uma vez para um problema que estava contido.']);
        box.appendChild(g);
    }

    // ------------------------------------------------------------ eventos
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') fecharModal(); });
    ['click', 'keydown'].forEach(function (t) { document.addEventListener(t, function () { atividade = true; }, true); });
    Array.prototype.forEach.call(document.querySelectorAll('#abas button'), function (b) { b.addEventListener('click', function () { mostrar(b.getAttribute('data-aba')); }); });
    ['s-q'].forEach(function (id) { $(id).addEventListener('input', desenharServidores); });
    ['s-so', 's-tipo', 's-crit', 's-desc'].forEach(function (id) { $(id).addEventListener('change', desenharServidores); });
    $('p-q').addEventListener('input', desenharPacotes); $('p-ger').addEventListener('change', desenharPacotes); $('p-kev').addEventListener('change', desenharPacotes);
    $('v-q').addEventListener('input', function () { clearTimeout(timerBusca); timerBusca = setTimeout(function () { estado.pagina = 0; carregarVulns(true); }, 400); });
    ['v-serv', 'v-corr', 'v-kev'].forEach(function (id) { $(id).addEventListener('change', function () { estado.pagina = 0; carregarVulns(true); }); });
    $('v-ant').addEventListener('click', function () { estado.pagina = Math.max(0, estado.pagina - 1); carregarVulns(true); });
    $('v-prox').addEventListener('click', function () { estado.pagina += 1; carregarVulns(true); });
    $('c-serv').addEventListener('change', function () { $('c-rel').disabled = !$('c-serv').value; carregarPlano($('c-serv').value); });
    // a visão geral se atualiza sozinha (sem estender a sessão: só cliques e teclas estendem)
    timerGeral = setInterval(function () { if (aba === 'geral' && !document.hidden) carregarGeral(false); }, 300000);
    mostrar('geral');
})();
