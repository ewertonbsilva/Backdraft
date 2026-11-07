# Contribuindo com o Backdraft

Obrigado pelo interesse! Ideias, relatos de erro e *pull requests* são bem-vindos.

## Antes de começar

- Abra uma *issue* descrevendo o problema ou a ideia, principalmente para mudanças grandes.
- **Falha de segurança?** Não abra *issue* pública: veja [SECURITY.md](SECURITY.md).
- **Nunca** envie dados reais: nomes de máquinas, IPs, usuários, relatórios ou saídas do Wazuh da sua rede. Use exemplos fictícios (faixas de documentação como `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, e domínios `exemplo.com`).

## Ambiente de desenvolvimento

Não há nada para instalar: é Python 3.10+ da biblioteca padrão e JavaScript puro.

```bash
git clone https://github.com/ewertonbsilva/Backdraft.git && cd Backdraft
python -m unittest test_dados test_backdraft test_modulos -v
for f in static/*.js; do node --check "$f"; done     # opcional, precisa do Node só para checar a sintaxe
```

Os testes não precisam de Wazuh, LDAP, Telegram nem internet: tudo isso é simulado.

## O que esperamos de um *pull request*

1. **Testes.** Toda regra nova precisa de um teste. Toda correção de erro, de um teste que falhava antes.
2. **Segurança primeiro.** Em especial:
   - texto vindo do servidor entra na tela por `textContent`, **nunca** por `innerHTML`;
   - nenhum comando é montado com texto não validado (veja `PKG_SEGURO` em `dados.py`);
   - o painel continua **somente leitura**: nada que execute ou altere algo nos servidores;
   - sem segredos em código, em log ou em resposta.
3. **Sem dependências novas** no servidor nem no navegador (sem CDN, sem fontes externas). O `ldap3` é a única exceção, e é opcional.
4. **Mudanças pequenas e focadas**, com uma mensagem de *commit* que explique o porquê.
5. Atualize o `README.md` e o `.env.example` se mudar a configuração.

## Estilo

- Código e comentários em português, como no restante do projeto; nomes de variáveis em português sem acento.
- Mensagens na interface em português do Brasil, com a acentuação correta.
- Linhas de até ~130 caracteres; sem formatadores automáticos obrigatórios.

## Ideias que ajudam

A lista em "Ideias para o futuro" do README é um bom ponto de partida: acompanhamento de status por CVE, exportação CSV do relatório, imagem de contêiner, internacionalização.
