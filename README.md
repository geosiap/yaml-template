# YAML Pipelines

Este repositório contém os arquivos que podem ser utilizados como template para as pipelines dos projetos.

## Playwright (testes E2E bloqueantes ou em paralelo)

Três peças que o projeto chama; o cabeçalho de cada arquivo traz o exemplo de uso:

| Peça | O que faz |
|---|---|
| `.github/workflows/playwright-selecionar.yml` | Lista os arquivos do push e consulta o mapa "arquivo → tag" do projeto de testes. Devolve `executar` (`tudo`, `tags`, `nenhum`) e o `grep` do Playwright. |
| `.github/workflows/playwright-testar.yml` | Roda os testes no runner próprio (browsers já instalados nele); cai para uma máquina do GitHub só se o runner não conseguir executar. Veredito, resumo e comentário na issue do commit quando falha. |
| `playwright/preparar` | Action que deixa browsers e bibliotecas prontos; em máquina fixa só reinstala as bibliotecas quando a versão do Playwright (ou a lista de browsers) muda. |

O projeto de testes precisa de um script de seleção e de um mapa (por padrão `ci/selecionar-testes.js` e `ci/mapa-telas.json` na pasta de testes); o contrato do script está no cabeçalho de `playwright-selecionar.yml`.
Nenhum valor específico de projeto fica aqui (runner, URL, repositório de issues, número de issue): tudo entra por `with:` no workflow do projeto.

