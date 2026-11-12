# YAML Pipelines

Este repositório contém os arquivos que podem ser utilizados como template para as pipelines dos projetos.

## Playwright (testes E2E bloqueantes ou em paralelo)

Três peças que o projeto chama; o cabeçalho de cada arquivo traz o exemplo de uso:

| Peça | O que faz |
|---|---|
| `.github/workflows/playwright-selecionar.yml` | Lista os arquivos do push e consulta o mapa "arquivo → tag" do projeto de testes. Devolve `executar` (`tudo`, `tags`, `nenhum`) e o `grep` do Playwright. |
| `.github/workflows/playwright-testar.yml` | Um job: roda os testes no runner próprio (browsers já instalados nele) ou, com `forcar-github`, em máquina do GitHub. Se falhar, comenta na issue do commit. |
| `playwright/preparar` | Action que deixa browsers e bibliotecas prontos; em máquina fixa só reinstala as bibliotecas quando a versão do Playwright (ou a lista de browsers) muda. |

O projeto de testes precisa de um script de seleção e de um mapa (por padrão `ci/selecionar-testes.js` e `ci/mapa-telas.json` na pasta de testes); o contrato do script está no cabeçalho de `playwright-selecionar.yml`.
Nenhum valor específico de projeto fica aqui (runner, URL, repositório de issues, número de issue): tudo entra por `with:` no workflow do projeto.

