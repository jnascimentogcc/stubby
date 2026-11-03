# stubby — Documento de Visão

Nov 3, 2026 · @Jorge Nascimento

## Visão

O stubby diz se o código de um projeto consegue mesmo chegar ao código vulnerável de uma dependência, e regista a resposta num documento OpenVEX que se pode rever, versionar e partilhar.

Os scanners atuais respondem "esta dependência tem um CVE". O stubby responde à pergunta seguinte: "isto afeta o meu projeto?". O objetivo é reduzir centenas de alertas a uma lista curta e justificada, onde cada veredicto cita evidência (ficheiro e linha) e assume um de três estados: afetado, não afetado ou inconclusivo.

Ambição: ser a ferramenta open-source de referência para análise de alcançabilidade em vários ecossistemas, com geração automática de VEX.

## Problema

Os developers recebem demasiados alertas de vulnerabilidades e não têm forma barata de saber quais importam.

- **Ruído:** um scanner de dependências sinaliza qualquer CVE numa versão instalada, mesmo que o código vulnerável nunca seja chamado. A equipa gasta tempo a triar alertas irrelevantes ou aprende a ignorá-los.
- **VEX quase inexistente na prática:** a regulação (por exemplo o Cyber Resilience Act da UE) e os clientes pedem cada vez mais declarações de que um produto não é afetado por um CVE, mas quase ninguém as gera de forma automática.
- **Advisories sem detalhe estruturado:** raramente indicam que função ou padrão de uso é perigoso. Essa informação está no texto livre e no commit de correção, que é difícil de processar só com regras.

## Público-alvo e casos de uso

O primeiro utilizador é o developer que mantém um projeto JS/TS e quer saber, antes de abrir um PR ou publicar uma release, que vulnerabilidades o afetam de facto.

| Utilizador | Necessidade | Como o stubby ajuda |
| --- | --- | --- |
| Developer local | Perceber que alertas exigem ação | Corre a CLI e recebe veredictos com evidência por ficheiro e linha |
| Mantenedor open-source | Responder a utilizadores que perguntam "o CVE X afeta-me?" | Publica um OpenVEX junto da release |
| Equipa de segurança | Reduzir a fila de triagem | Usa o VEX como rascunho para rever e aprovar |
| Fornecedor de software | Cumprir pedidos de clientes e regulação | Anexa declarações VEX ao produto |

Fora de âmbito para já: monitorização contínua, painéis web e gestão de vulnerabilidades em escala empresarial.

## Princípios de design

Cinco princípios decidem o que o stubby faz e, sobretudo, o que recusa fazer.

1. **Determinístico primeiro, LLM depois.** O LLM extrai o símbolo vulnerável do texto do advisory e do commit de correção; a análise estática decide se o código chega lá. O LLM só vê snippets mínimos e só nos casos ambíguos.
2. **Nunca dar falsa segurança.** Três veredictos: afetado, não afetado (só com evidência citada) e inconclusivo. Código dinâmico (`eval`, `import()` dinâmico, reflection, `getattr`) baixa a confiança; em dúvida, o resultado é inconclusivo.
3. **Evidência ou não conta.** Todo o veredicto cita ficheiro e linha, para o humano poder verificar.
4. **O output é um rascunho para revisão humana**, não uma garantia de segurança.
5. **Privacidade e provedores abertos.** Nunca se envia o repositório inteiro a uma API externa; a camada de LLM é abstrata (OpenAI primeiro, modelos locais depois).

## Panorama e diferenciação

Não há falta de scanners; falta uma opção aberta que combine alcançabilidade em vários ecossistemas com geração de VEX. Reescrever "mais um scanner de CVEs" não é o objetivo: o stubby consome os dados do OSV.dev e acrescenta a camada de decisão por cima.

| Ferramenta | Tipo | O que faz bem | Lacuna que o stubby ocupa |
| --- | --- | --- | --- |
| Trivy, Grype, OSV-Scanner | Scanners open-source | Encontram CVEs em dependências, imagens e lockfiles | Não dizem se o código vulnerável é alcançável |
| Dependabot | Alertas e PRs de upgrade | Integração nativa no GitHub | Alertas por versão instalada, sem análise de uso |
| Semgrep, CodeQL | Análise estática (SAST) | Padrões de código inseguro no próprio projeto | Foco no código do projeto, não em advisories de dependências |
| govulncheck | Alcançabilidade para Go | Referência de qualidade ao nível do símbolo | Só Go |
| Snyk, Endor Labs e similares | Plataformas comerciais | Alcançabilidade e priorização em escala | Fechadas e pagas; VEX nem sempre é o foco |

Nota: esta comparação resume o estado do mercado de forma aproximada, a partir de conhecimento geral até junho de 2026. Convém confirmar as capacidades de cada ferramenta antes de publicar o documento.

## Métricas de sucesso

A métrica que mais importa é a correção dos veredictos: sem números de precisão e recall, ninguém confia numa ferramenta que diz "não afetado". As metas abaixo são hipóteses de partida, a calibrar quando o benchmark existir.

| Métrica | Como se mede | Meta inicial |
| --- | --- | --- |
| Falsos "não afetado" | Casos do benchmark em que a ferramenta diz não afetado mas o CVE é alcançável | Zero tolerado; qualquer caso bloqueia a release |
| Precisão e recall | Benchmark de 20 a 30 casos reais (CVE, projeto de exemplo, veredicto esperado) | A definir após a primeira medição |
| Redução de ruído | Percentagem de alertas passados de "em investigação" a "não afetado" com evidência, em projetos reais | A definir após a v0.3 |
| Custo por scan | Chamadas e tokens de LLM por projeto | Baixo o suficiente para correr em cada PR |
| Adoção | Estrelas, instalações, issues abertas por terceiros | Primeiros utilizadores externos até à v0.4 |
| Contribuições | Casos de benchmark e adaptadores enviados pela comunidade | Primeiro adaptador de terceiros após a v0.6 |

## Riscos e mitigações

O maior risco é a ferramenta dar falsa segurança; os restantes são de escopo e de adoção.

| Risco | Impacto | Mitigação |
| --- | --- | --- |
| Falso "não afetado" | Um projeto vulnerável é dado como seguro | Veredicto só com evidência citada; três estados; código dinâmico gera "inconclusivo"; VEX tratado como rascunho; benchmark com tolerância zero |
| Alucinações do LLM | Símbolos vulneráveis inventados | O LLM só extrai o símbolo; a decisão é da análise estática; resposta validada contra o código do advisory ou do commit |
| Análise de dependências transitivas | O código chama a lib A, que chama a lib B vulnerável, e o scan não vê | Documentar a limitação na v1; tratar transitivas como "inconclusivo" até à v0.5 |
| Quatro ecossistemas ao mesmo tempo | Projeto nunca sai do chão | Começar só por JS/TS; adaptador por linguagem desde o primeiro dia |
| Privacidade do código | Utilizadores recusam enviar código a uma API externa | Enviar só snippets mínimos; suporte a modelos locais; modo sem LLM |
| Qualidade dos dados do OSV | Advisories sem símbolo ou versões afetadas incorretas | Mostrar a fonte; cair em "inconclusivo" quando falta informação |
| Custo de LLM | Scans caros em projetos grandes | Cache por advisory; LLM só nos casos ambíguos |

## Open-source e questões em aberto

O projeto nasce com licença Apache-2.0, desenvolvimento aberto e a contribuição mais valiosa bem definida: casos de benchmark.

- **Licença:** Apache-2.0, por incluir concessão explícita de patentes e ser comum em ferramentas de segurança.
- **Contribuir:** o caminho de entrada é enviar um caso de benchmark (um CVE real, um projeto pequeno e o veredicto esperado). Mudanças grandes devem ser discutidas numa issue antes.
- **Extensibilidade:** cada nova linguagem entra como um adaptador que implementa a mesma interface, o que permite contribuições de terceiros sem tocar no núcleo.
- **Governação:** mantenedor único no início, com decisões registadas em issues públicas; rever o modelo se surgirem mantenedores regulares.

Questões em aberto:

- [ ] O nome "stubby" está livre no PyPI e no GitHub, ou é preciso outro?
- [ ] Que formato de benchmark facilita contribuições (pasta por caso, ficheiro de metadados)?
- [ ] Como tratar monorepos com vários lockfiles na v0.2?
- [ ] Qual o limite de custo aceitável de LLM por scan para correr em CI?
- [ ] Vale a pena suportar CycloneDX VEX além de OpenVEX?
