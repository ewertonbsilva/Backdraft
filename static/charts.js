// Gráficos do Backdraft: SVG/HTML puro, sem bibliotecas e sem nada de fora (a CSP só deixa 'self').
// Todo texto entra por textContent. As cores vêm de classes do CSS (s-Critical, s-High...).
(function (w) {
    'use strict';
    var NS = 'http://www.w3.org/2000/svg';
    var SEV = ['Critical', 'High', 'Medium', 'Low', 'Outra'];
    var SEV_PT = { Critical: 'Crítica', High: 'Alta', Medium: 'Média', Low: 'Baixa', Outra: 'Sem classificação' };

    function el(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt !== undefined && txt !== null) e.textContent = txt; return e; }
    function sv(tag, attrs, txt) {
        var e = document.createElementNS(NS, tag);
        Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
        if (txt !== undefined) e.textContent = txt;
        return e;
    }
    function fmt(n) { return Number(n).toLocaleString('pt-BR'); }
    function curto(n) { n = Number(n); if (n >= 1e6) return (n / 1e6).toFixed(1).replace('.', ',') + ' mi'; if (n >= 1e4) return Math.round(n / 1e3) + ' mil'; if (n >= 1e3) return (n / 1e3).toFixed(1).replace('.', ',') + ' mil'; return String(n); }
    function tip(node, texto) { node.appendChild(sv('title', {}, texto)); return node; }
    function vazio(msg) { return el('div', 'vazio', msg || 'Sem dados.'); }

    // ------------------------------------------------------------ rosca
    // dados: [{t, n, cls}]; centro: {v, r}
    function donut(dados, centro) {
        var box = el('div', 'donut-box');
        var total = dados.reduce(function (a, d) { return a + d.n; }, 0);
        if (!total) { box.appendChild(vazio()); return box; }
        var s = sv('svg', { viewBox: '0 0 200 200', 'class': 'donut', role: 'img', 'aria-label': 'Gráfico de rosca' });
        var R = 74, C = 2 * Math.PI * R, acum = 0;
        s.appendChild(sv('circle', { cx: 100, cy: 100, r: R, 'class': 'donut-fundo' }));
        dados.forEach(function (d) {
            if (!d.n) return;
            var len = C * d.n / total;
            var c = sv('circle', { cx: 100, cy: 100, r: R, 'class': 'donut-fatia ' + (d.cls || ''), 'stroke-dasharray': Math.max(len - 1.5, 0.5) + ' ' + (C - Math.max(len - 1.5, 0.5)),
                'stroke-dashoffset': -acum, transform: 'rotate(-90 100 100)' });
            tip(c, d.t + ': ' + fmt(d.n) + ' (' + (100 * d.n / total).toFixed(1).replace('.', ',') + '%)');
            s.appendChild(c);
            acum += len;
        });
        if (centro) {
            s.appendChild(sv('text', { x: 100, y: 102, 'text-anchor': 'middle', 'class': 'donut-v' }, centro.v));
            s.appendChild(sv('text', { x: 100, y: 124, 'text-anchor': 'middle', 'class': 'donut-r' }, centro.r || ''));
        }
        box.appendChild(s);
        var ul = el('ul', 'legenda');
        dados.forEach(function (d) {
            var li = el('li'); li.appendChild(el('i', 'cor ' + (d.cls || '')));
            li.appendChild(el('span', 'rot', d.t)); li.appendChild(el('b', '', fmt(d.n)));
            li.appendChild(el('small', '', total ? (100 * d.n / total).toFixed(1).replace('.', ',') + '%' : ''));
            ul.appendChild(li);
        });
        box.appendChild(ul);
        return box;
    }

    // ------------------------------------------------------------ barras empilhadas horizontais (HTML)
    // linhas: [{t, sub, partes:[{n, cls, t}], total, clique}]
    function pilha(linhas, opt) {
        opt = opt || {};
        var box = el('div', 'pilha');
        if (!linhas.length) { box.appendChild(vazio()); return box; }
        var max = Math.max.apply(null, linhas.map(function (l) { return l.partes.reduce(function (a, p) { return a + p.n; }, 0); })) || 1;
        linhas.forEach(function (l) {
            var tot = l.partes.reduce(function (a, p) { return a + p.n; }, 0);
            var r = el('div', 'pilha-linha' + (l.clique ? ' clicavel' : ''));
            if (l.clique) { r.tabIndex = 0; r.addEventListener('click', l.clique); r.addEventListener('keydown', function (e) { if (e.key === 'Enter') l.clique(); }); }
            var nome = el('div', 'pilha-nome'); nome.appendChild(el('span', '', l.t)); if (l.sub) nome.appendChild(el('small', '', l.sub));
            nome.title = l.t + (l.sub ? ' · ' + l.sub : '');
            var trilho = el('div', 'pilha-trilho'), barra = el('div', 'pilha-barra');
            barra.style.width = Math.max(tot ? 3 : 0, 100 * tot / max) + '%';
            l.partes.forEach(function (p) {
                if (!p.n) return;
                var seg = el('span', 'seg ' + (p.cls || '')); seg.style.flexGrow = p.n; seg.title = (p.t || '') + ': ' + fmt(p.n);
                barra.appendChild(seg);
            });
            trilho.appendChild(barra);
            r.appendChild(nome); r.appendChild(trilho); r.appendChild(el('div', 'pilha-n', l.total !== undefined ? l.total : fmt(tot)));
            box.appendChild(r);
        });
        return box;
    }

    // ------------------------------------------------------------ colunas (empilhadas ou simples)
    // dados: [{t, partes:[{n, cls, t}]}]
    function colunas(dados, opt) {
        opt = opt || {};
        var box = el('div', 'colunas-box');
        if (!dados.length) { box.appendChild(vazio()); return box; }
        var W = 640, H = 230, ml = 44, mb = 28, mt = 10, mr = 8;
        var tot = dados.map(function (d) { return d.partes.reduce(function (a, p) { return a + p.n; }, 0); });
        var max = Math.max.apply(null, tot) || 1;
        var passo = Math.pow(10, Math.floor(Math.log(max) / Math.LN10)), topo = Math.ceil(max / passo) * passo;
        if (topo / passo > 5) passo *= 2;
        var s = sv('svg', { viewBox: '0 0 ' + W + ' ' + H, 'class': 'colunas', role: 'img', 'aria-label': 'Gráfico de colunas' });
        for (var v = 0; v <= topo; v += passo) {
            var y = mt + (H - mt - mb) * (1 - v / topo);
            s.appendChild(sv('line', { x1: ml, x2: W - mr, y1: y, y2: y, 'class': 'grade-h' }));
            s.appendChild(sv('text', { x: ml - 6, y: y + 3.5, 'text-anchor': 'end', 'class': 'eixo' }, curto(v)));
        }
        var larg = (W - ml - mr) / dados.length, bw = Math.min(40, larg * 0.62);
        dados.forEach(function (d, i) {
            var x = ml + larg * i + (larg - bw) / 2, base = H - mb;
            var g = sv('g', { 'class': 'coluna' });
            d.partes.forEach(function (p) {
                if (!p.n) return;
                var h = (H - mt - mb) * p.n / topo;
                base -= h;
                var r = sv('rect', { x: x, y: base, width: bw, height: Math.max(h, 0.8), rx: 2, 'class': p.cls || '' });
                tip(r, d.t + (p.t ? ' · ' + p.t : '') + ': ' + fmt(p.n));
                g.appendChild(r);
            });
            s.appendChild(g);
            s.appendChild(sv('text', { x: x + bw / 2, y: H - 9, 'text-anchor': 'middle', 'class': 'eixo' }, d.t));
        });
        box.appendChild(s);
        return box;
    }

    // ------------------------------------------------------------ linhas (tendência)
    // rotulos: ['06/11', ...]; series: [{t, cls, v:[...]}]
    function linhas(rotulos, series) {
        var box = el('div', 'linhas-box');
        if (rotulos.length < 2) {
            box.appendChild(vazio('O histórico começa hoje. A curva aparece a partir do segundo dia de coleta.'));
            if (rotulos.length === 1) {
                var ul = el('ul', 'legenda solta');
                series.forEach(function (s) { var li = el('li'); li.appendChild(el('i', 'cor ' + s.cls)); li.appendChild(el('span', 'rot', s.t)); li.appendChild(el('b', '', fmt(s.v[0]))); ul.appendChild(li); });
                box.appendChild(ul);
            }
            return box;
        }
        var W = 640, H = 230, ml = 46, mb = 28, mt = 12, mr = 14;
        var max = Math.max.apply(null, [1].concat.apply([], series.map(function (s) { return s.v; })));
        var passo = Math.pow(10, Math.floor(Math.log(max) / Math.LN10)), topo = Math.ceil(max / passo) * passo;
        if (topo / passo > 5) passo *= 2;
        var s = sv('svg', { viewBox: '0 0 ' + W + ' ' + H, 'class': 'linhas', role: 'img', 'aria-label': 'Gráfico de linhas' });
        for (var v = 0; v <= topo; v += passo) {
            var y = mt + (H - mt - mb) * (1 - v / topo);
            s.appendChild(sv('line', { x1: ml, x2: W - mr, y1: y, y2: y, 'class': 'grade-h' }));
            s.appendChild(sv('text', { x: ml - 6, y: y + 3.5, 'text-anchor': 'end', 'class': 'eixo' }, curto(v)));
        }
        var px = function (i) { return ml + (W - ml - mr) * i / (rotulos.length - 1); };
        var py = function (val) { return mt + (H - mt - mb) * (1 - val / topo); };
        var cada = Math.ceil(rotulos.length / 8);
        rotulos.forEach(function (r, i) { if (i % cada === 0 || i === rotulos.length - 1) s.appendChild(sv('text', { x: px(i), y: H - 9, 'text-anchor': 'middle', 'class': 'eixo' }, r)); });
        series.forEach(function (se) {
            var d = se.v.map(function (val, i) { return (i ? 'L' : 'M') + px(i).toFixed(1) + ' ' + py(val).toFixed(1); }).join(' ');
            s.appendChild(sv('path', { d: d + ' L' + px(se.v.length - 1).toFixed(1) + ' ' + (H - mb) + ' L' + px(0).toFixed(1) + ' ' + (H - mb) + ' Z', 'class': 'area ' + se.cls }));
            s.appendChild(sv('path', { d: d, 'class': 'linha ' + se.cls }));
            se.v.forEach(function (val, i) {
                var c = sv('circle', { cx: px(i), cy: py(val), r: 3.4, 'class': 'ponto ' + se.cls });
                tip(c, se.t + ' · ' + rotulos[i] + ': ' + fmt(val)); s.appendChild(c);
            });
        });
        box.appendChild(s);
        var ul = el('ul', 'legenda solta');
        series.forEach(function (se) { var li = el('li'); li.appendChild(el('i', 'cor ' + se.cls)); li.appendChild(el('span', 'rot', se.t)); ul.appendChild(li); });
        box.appendChild(ul);
        return box;
    }

    // ------------------------------------------------------------ minigráfico para KPI
    function spark(valores, cls) {
        if (!valores || valores.length < 2) return null;
        var W = 90, H = 26, max = Math.max.apply(null, valores), min = Math.min.apply(null, valores), f = max === min ? 1 : max - min;
        var d = valores.map(function (v, i) { return (i ? 'L' : 'M') + (W * i / (valores.length - 1)).toFixed(1) + ' ' + (H - 3 - (H - 6) * (v - min) / f).toFixed(1); }).join(' ');
        var s = sv('svg', { viewBox: '0 0 ' + W + ' ' + H, 'class': 'spark ' + (cls || ''), 'aria-hidden': 'true' });
        s.appendChild(sv('path', { d: d, 'class': 'spark-linha' }));
        return s;
    }

    w.Charts = { donut: donut, pilha: pilha, colunas: colunas, linhas: linhas, spark: spark, el: el, fmt: fmt, curto: curto, SEV: SEV, SEV_PT: SEV_PT, vazio: vazio };
})(window);
