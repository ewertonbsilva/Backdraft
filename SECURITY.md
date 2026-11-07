# Política de segurança

## Reportando uma vulnerabilidade no Backdraft

Se você achou uma falha de segurança **no Backdraft** (por exemplo: contornar o login, injeção, XSS, vazamento de dados, execução de comandos), **não abra uma *issue* pública**.

Use o recurso de **relato privado de vulnerabilidades do GitHub** (aba *Security* do repositório, "Report a vulnerability"). Se ele não estiver disponível, entre em contato com os mantenedores por um canal privado indicado no perfil do repositório.

Inclua, se puder: a versão (ou o *commit*), como reproduzir, o impacto que você enxerga e, se houver, uma sugestão de correção. Pedimos um prazo razoável para corrigir antes da divulgação pública.

## O que está no escopo

- Autenticação, sessão e autorização do painel.
- Qualquer caminho em que dados vindos do Wazuh ou da rede virem **comando**, **HTML** ou **consulta** sem validação.
- Vazamento de segredos (`.env`, senhas, tokens) em logs, respostas ou arquivos.
- O instalador e a *unit* do systemd.

## Fora do escopo

- Falhas **no Wazuh**, no OpenSearch ou no `ldap3`: reporte aos projetos deles.
- Ataques que exigem acesso de administrador ao servidor onde o Backdraft roda.
- Painel exposto à internet sem as proteções recomendadas no README (firewall, `ALLOWED_IPS`, HTTPS).

## Princípios de projeto

O Backdraft mostra **onde estão as falhas da sua rede**. Por isso:

- é **somente leitura**: o usuário do indexador só tem permissão de leitura e o painel nunca executa nada nos servidores;
- tudo que vem de fora entra na tela por `textContent` e, em comandos, só se for "limpo";
- o acesso exige **autenticação e autorização** (`ALLOWED_USERS`), com limite de tentativas;
- segredos ficam no `.env` (fora do repositório) e nunca em log.

Se você encontrar algo que contradiz esses princípios, é uma falha que queremos corrigir.

## Boas práticas para quem instala

- Exponha o painel **apenas** na rede de administração e use HTTPS.
- Use senhas longas e únicas, de preferência guardadas num gerenciador de segredos.
- Trate os relatórios como **confidenciais**: eles listam máquinas, versões e vulnerabilidades exploráveis.
- Mantenha o Python e o sistema atualizados.
