# Plano de remediação de segurança — 29/07/2026

Levantamento e remediação realizados em **29/07/2026** sobre o commit `afbafcb`.
Todas as 5 fases abaixo foram implementadas e validadas nesta mesma sessão.

> **Continuação:** [`docs/seguranca-2026-07-30/`](../seguranca-2026-07-30/README.md)
> cobre `SEC-10` e `SEC-11` — dois CVEs (`GO-2026-5047`/`CVE-2026-46384` e
> `GO-2026-5048`) publicados em 27/07/2026, depois deste levantamento.

## Contexto

Este repositório é o fork `arquivei/avro` de `hamba/avro`, cujo upstream foi
descontinuado. A Qive assumiu a manutenção ativa — o que inclui responder pelas
vulnerabilidades do código, não só pelas das dependências.

Isso é relevante porque o achado mais grave ([SEC-01](#sec-01)) tem CVE público
(`CVE-2026-46385`) registrado contra `github.com/hamba/avro/v2` como **"all
versions, no known fixed version"**. O upstream não vai corrigir.

## Como o levantamento foi feito

| Ferramenta | O que achou |
|---|---|
| Trivy (`fs`, 15 pacotes do `go.mod`) | 0 vulnerabilidades, 0 misconfig, 0 secrets |
| govulncheck | 40 advisories — 21 alcançáveis, **todas** da stdlib, mais 1 de dependência |
| Revisão manual de código | 9 achados, incluindo os 4 de maior severidade |

**As duas ferramentas automatizadas não detectam vulnerabilidade no próprio
módulo sob análise.** O Trivy lê o `go.mod` (compara versões de dependências) e o
govulncheck analisa as dependências do main module — nenhum dos dois reporta o
código deste repositório. `SEC-01` a `SEC-06` e `SEC-09` só apareceram na
revisão manual.

Consequência prática: para este repo, scan de dependência **não substitui**
revisão de código nem fuzzing — daí a [Fase 5](#fase-5-prevenção).

## Achados

| ID | Título | Severidade | Fase | Estado |
|---|---|---|---|---|
| [SEC-01](#sec-01) | DoS por block count não validado (`CVE-2026-46385`) | Alta | 1 | ✅ Corrigido |
| [SEC-02](#sec-02) | Pré-alocação ilimitada no `arrayDecoder` | Alta | 1 | ✅ Corrigido |
| [SEC-03](#sec-03) | Panic/OOM por `size` de bloco OCF não validado | Alta | 2 | ✅ Corrigido |
| [SEC-04](#sec-04) | Bomba de descompressão nos codecs OCF | Alta | 2 | ✅ Corrigido |
| [SEC-05](#sec-05) | Injeção de código no gerador (`gen`) | Média | 4 | ✅ Corrigido |
| [SEC-06](#sec-06) | Aliasing de slab em `readBytes` | Baixa | 4 | ✅ Corrigido |
| [SEC-07](#sec-07) | `klauspost/compress` v1.18.2 (`GO-2026-5841`) | Baixa | 3 | ✅ Corrigido |
| [SEC-08](#sec-08) | Toolchain desatualizado e Go 1.24 (EOL) no CI | Média | 3 | ✅ Corrigido |
| [SEC-09](#sec-09) | `ReadArrayCB` sem consumo do callback ainda gira o count | Baixa | — | ⚠️ Documentado, não corrigido (ver justificativa) |

## Estado final

- [x] Fase 1 — Decoders do pacote raiz
- [x] Fase 2 — Pacote `ocf/`
- [x] Fase 3 — Dependências, toolchain, CI
- [x] Fase 4 — Gerador e hardening
- [x] Fase 5 — Prevenção

Validado com: `go build`/`go vet`/`golangci-lint` limpos (**1436 testes
passando**, 1387 originais + 49 novos), sem regressão de alocação nos
benchmarks (`B/op`/`allocs/op` idênticos à baseline
em todos os 6 benchmarks), saída do `avrogen` byte-a-byte idêntica para
schemas válidos, `govulncheck` sem findings de dependência.

Consolidado em um único commit na branch `security/fix-decoder-dos-and-hardening`,
com PR aberto contra `main`.

### CI descoberto quebrado ao abrir o PR (29/07/2026)

A primeira execução do CI no PR falhou por dois motivos **não relacionados**
ao conteúdo desta remediação:

1. `gertd/action-gotestsum@v3.0.0` (já usado pelo workflow antes desta
   sessão) parou de resolver — o repositório da action **sumiu do GitHub**
   (404) em algum momento entre a última execução bem-sucedida do `main`
   (16h16) e a primeira execução do PR (22h09) no mesmo dia. Substituído por
   `go install gotest.tools/gotestsum@v1.13.0` direto no step, eliminando a
   dependência de uma action de terceiro para algo que é só instalar um
   binário.
2. Com a matriz do CI já em Go 1.25/1.26 (Fase 3), o `golangci-lint` fixado
   em v2.6.2 (também pré-existente) passou a falhar com "exit code 2" — sintoma
   de incompatibilidade de versão com o toolchain novo, não um achado de lint de
   verdade. Atualizado para v2.12.2 (a mesma versão já usada localmente
   durante a Fase 1-5, mas que nunca tinha sido testada contra a versão
   *fixada* do CI).

O bump do `golangci-lint` teve uma consequência direta: os "3 achados
pré-existentes de `govet` sobre `reflect.Ptr`" mencionados em várias fases
deste documento — que eu tratei a sessão inteira como ruído de uma versão de
linter local mais nova que a do CI — **passaram a falhar de verdade** assim
que o CI passou a rodar a mesma versão. Não eram mais "pré-existentes e fora
de escopo": eram simplesmente invisíveis até este ponto. Corrigidos (junto
com 8 ocorrências idênticas em `codec_native.go`, `codec_union.go` e
`codec_record.go` que o linter não sinalizava mas usavam a mesma constante
depreciada) trocando `reflect.Ptr` por `reflect.Pointer` em todo o módulo.

### Release

Fases 1 e 2 fecham o CVE. Ao publicar, considerar:

- Publicar uma tag do fork e comunicar os consumidores internos.
- Reportar a correção ao [GHSA-w8j3-pq8g-8m7w](https://github.com/advisories/GHSA-w8j3-pq8g-8m7w),
  já que hoje a advisory lista `hamba/avro/v2` sem versão corrigida. O fork
  `iskorotkov/avro/v2` corrigiu em `v2.33.0` e serve de referência.

## Restrições que valeram para toda a remediação

Herdadas do `AGENTS.md`:

- **Não quebrar a API pública** — lib v2 com consumidores externos.
- **Não introduzir alocações no hot path** — validado com
  `go test -bench=. -benchmem` antes e depois de cada fase.
- **Não assumir plataforma 64-bit** — o CI compila para 386, arm, ppc64le, s390x.
- **Não alterar o module path** `github.com/arquivei/avro/v2`
  (era `github.com/hamba/avro/v2` à época desta sessão; renomeado em 30/07/2026).

---

# Catálogo de achados

Modelo de ameaça assumido: a biblioteca decodifica **payloads Avro binários,
arquivos OCF e schemas JSON vindos de fontes não confiáveis** (rede, Kafka,
Schema Registry, arquivos enviados por terceiros).

<a id="sec-01"></a>
## SEC-01 — DoS por block count não validado

| | |
|---|---|
| **Severidade** | Alta |
| **Referências** | `GO-2026-5046`, `CVE-2026-46385`, `GHSA-w8j3-pq8g-8m7w` |
| **Fase** | [1 — Decoders do pacote raiz](#fase-1--decoders-do-pacote-raiz) |

Os decoders de array e map iteram sobre um block count controlado pelo atacante
sem checar o estado de erro do `Reader` dentro do corpo do loop.
`Reader.ReadBlockHeader` devolve o count como `int64`. Um produtor hostil declara
um bloco de até `math.MaxInt64` elementos seguido de EOF, e o decoder tenta
aquela quantidade de iterações no-op antes de propagar o erro.

### Pontos afetados

| Arquivo:linha | Função | Observação |
|---|---|---|
| `codec_skip.go:155` | `sliceSkipDecoder.Decode` | sem checagem de `r.Error` |
| `codec_skip.go:186` | `mapSkipDecoder.Decode` | idem |
| `codec_map.go:118` | `mapDecoderUnmarshaler.Decode` | idem, e ainda cresce o map a cada iteração |
| `reader_generic.go:136` | `Reader.ReadArrayCB` | **API pública**, usada por `ReadNext` |
| `reader_generic.go:150` | `Reader.ReadMapCB` | **API pública**, usada por `ReadNext` |

Como `ReadNext` (`reader_generic.go:84,92`) usa os dois callbacks, **todo o
caminho de decode genérico (`any` / `map[string]any`) está exposto** — que é
justamente o usado em decode dinâmico via Schema Registry e em `soe/dynamic.go`.

Já corretos (checam `r.Error` dentro do loop): o loop interno de `arrayDecoder`
(`codec_array.go:65`) e `mapDecoder` (`codec_map.go:70`).

### Evidência

Payload de **6 bytes**: block header declarando `2^40` elementos, seguido de EOF.

```
payload: 6 bytes | count declarado: 1099511627776 | dados: ZERO (EOF imediato)

  sliceSkipDecoder                   AINDA RODANDO apos 5s   <-- DoS
  mapSkipDecoder                     AINDA RODANDO apos 5s   <-- DoS
  Reader.ReadArrayCB                 AINDA RODANDO apos 5s   <-- DoS
  Reader.ReadMapCB                   AINDA RODANDO apos 5s   <-- DoS
```

Reprodução:

```go
buf := &bytes.Buffer{}
w := avro.NewWriter(buf, 64)
w.WriteBlockHeader(int64(1)<<40, 0)
_ = w.Flush()
payload := buf.Bytes() // 6 bytes

// Trava indefinidamente (pré-fix):
r := avro.NewReader(bytes.NewReader(payload), 64)
r.ReadArrayCB(func(*avro.Reader) bool { return true })
```

### Por que não foi detectado pelas ferramentas automatizadas

O govulncheck **carregou** a OSV `GO-2026-5046` (o module path bate) mas emitiu
zero findings: ele não reporta vulnerabilidades no próprio main module. O Trivy
tampouco, pelo mesmo motivo.

### Correção implementada

Os 5 pontos afetados agora interrompem o loop no primeiro erro do `Reader`,
seguindo o mesmo padrão já usado em `arrayDecoder`/`mapDecoder`. Em
`ReadArrayCB`/`ReadMapCB` (API pública), o retorno `false` do callback também
passou a interromper a leitura — comportamento antes ignorado, agora
documentado no godoc.

Verificado com re-execução independente do PoC original (módulo Go isolado
apontando para o repo via `replace`, fora dos testes escritos nesta sessão):
`sliceSkipDecoder`, `mapSkipDecoder`, `Reader.ReadMapCB` e
`mapDecoderUnmarshaler` retornam em microssegundos.

---

<a id="sec-02"></a>
## SEC-02 — Pré-alocação ilimitada no `arrayDecoder`

| | |
|---|---|
| **Severidade** | Alta |
| **Local** | `codec_array.go:63` |
| **Fase** | [1 — Decoders do pacote raiz](#fase-1--decoders-do-pacote-raiz) |

Variante de SEC-01 **não descrita na advisory**. O `arrayDecoder` aloca
`count × sizeof(elem)` **antes de ler um único elemento**:

```go
size += int(l)
if size > r.cfg.getMaxSliceAllocSize() { /* erro */ }
sliceType.UnsafeGrow(ptr, size)   // <- aloca tudo de uma vez
```

O guard não protege: `getMaxSliceAllocSize()` (`config.go:300`) devolve por
padrão `maxAllocSize`, que é `1 << 48` em `config_x64.go` — **281 TB**. Ele
existe para evitar panic do runtime, não é defesa contra exaustão.

### Evidência

Mesmo payload de 6 bytes, decodificando em `any`:

```
runtime: out of memory
  reflect2.(*UnsafeSliceType).UnsafeGrow(..., 0x10000000000)
  avro.(*arrayDecoder).Decode  codec_array.go:63
```

6 bytes → tentativa de alocar 8 TB → OOM kill do processo.

### Correção implementada

`arrayDecoder` agora cresce o slice em blocos de `arrayGrowChunk` (1024)
elementos por vez, deixando o loop interno (que já checa `r.Error`)
interromper assim que os dados reais acabarem. O guard `MaxSliceAllocSize`
foi mantido como está, mas deixou de ser a única linha de defesa.

Verificado que decodificar um array legítimo de 3000 elementos num único
bloco (cruzando 2 fronteiras de chunk) continua correto, e que os 6
benchmarks do pacote raiz mantêm `B/op`/`allocs/op` idênticos à baseline.

---

<a id="sec-03"></a>
## SEC-03 — Panic/OOM por `size` de bloco OCF não validado

| | |
|---|---|
| **Severidade** | Alta |
| **Local** | `ocf/ocf.go:209` e `ocf/ocf.go:221` |
| **Fase** | [2 — Pacote `ocf/`](#fase-2--pacote-ocf) |

```go
count := d.reader.ReadLong()
size := d.reader.ReadLong()   // int64 vindo do arquivo, sem validação

switch {
case count > 0:
    data := make([]byte, size)   // sem checar sinal nem teto
```

`size` não é validado por sinal nem por limite superior, e **não passa pelo
`MaxByteSliceSize`** — esse guard só existe em `Reader.readBytes`, e aqui o
`make` é direto.

- `size` negativo → `panic: runtime error: makeslice: len out of range`
- `size` positivo grande → alocação ilimitada → OOM

Panic em biblioteca estoura no processo de quem consome. Ninguém envolve
`Decode` em `recover()`.

### Evidência

Arquivo OCF de **122 bytes** (header válido gerado pelo próprio `ocf.NewEncoder`
+ um block header hostil):

```
caso A: count=1, size=-1  (arquivo total: 122 bytes)
  size negativo          PANIC: runtime error: makeslice: len out of range

caso B: count=0, size=-1  (arquivo total: 122 bytes)
  size negativo (skip)   sem crash, err=decoder: invalid block
```

O caso B não estoura porque `case size > 0` é falso para `-1` e a execução cai na
checagem de sync. A linha 221 continua vulnerável a `size` positivo grande.

### Correção implementada

`readBlock()` agora valida `size` **antes** de qualquer `make()`: rejeita
negativo, e rejeita acima de um teto configurável (novo `ocf.WithMaxBlockSize`,
default 100 MiB, negativo desabilita — mesma convenção de `MaxByteSliceSize`).

---

<a id="sec-04"></a>
## SEC-04 — Bomba de descompressão nos codecs OCF

| | |
|---|---|
| **Severidade** | Alta |
| **Local** | `ocf/codec.go:87` (deflate), `:114` (snappy), `:179` (zstd) |
| **Fase** | [2 — Pacote `ocf/`](#fase-2--pacote-ocf) |

```go
func (c *DeflateCodec) Decode(b []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewBuffer(b))
	data, err := io.ReadAll(r)   // sem limite de saída
```

| Codec | Limite de saída |
|---|---|
| `DeflateCodec` | **nenhum** — `io.ReadAll` |
| `ZStandardCodec` | só via `WithDecoderMaxMemory` nas `DOptions`; default do klauspost é 64 GB |
| `SnappyCodec` | aloca o tamanho declarado no header do snappy (até ~4 GB) |

### Evidência

```
original: 200 MiB -> comprimido: 203840 bytes  (amplificacao 1029x)
DeflateCodec.Decode alocou 200 MiB sem reclamar (err=<nil>)
```

Amplificação de ~1029x medida com zeros. Um bloco de ~1 MB rende ~1 GB de RAM.

### Correção implementada

Os três codecs agora respeitam o **mesmo teto** de `WithMaxBlockSize` (um só
botão de ajuste, conforme decidido na Fase 2): `DeflateCodec` via
`io.LimitReader`; `SnappyCodec` checando `snappy.DecodedLen` antes de
descomprimir; `ZStandardCodec` via `zstd.WithDecoderMaxMemory` — com nota no
godoc de que um decoder zstd compartilhado (`WithZStandardDecoder`) não pode
herdar esse limite, já que é construído fora deste pacote.

---

<a id="sec-05"></a>
## SEC-05 — Injeção de código no gerador (`gen`)

| | |
|---|---|
| **Severidade** | Média (condicional) |
| **Local** | `gen/output_template.tmpl` (múltiplas interpolações — ver "atualização" abaixo) |
| **Fase** | [4 — Gerador e hardening do `Reader`](#fase-4--gerador-e-hardening-do-reader) |

O template usa `text/template` para emitir código Go. `Doc` e `Schema`
**eram** os únicos pontos já escapados antes desta remediação. Nomes de campo
e símbolos de enum são validados como `[A-Za-z_][A-Za-z0-9_]*` por
`validateName` (`schema.go:1631`) sob configuração padrão — mas
**`avro.SkipNameValidation` é uma variável global** e o README instrui
ativá-la para schemas legados com nomes inválidos. Com ela ligada, um
backtick no nome do campo escapava da struct tag e caía em posição de código.

### Evidência original

```
>>> INJECAO CONFIRMADA: 'func init()' presente no codigo gerado
  | 	type Rec struct {
  | 		A`+"`"+`... string `avro:"a` + "`" + `
  | func init() { println("PWNED AT BUILD TIME") }
```

Na descoberta inicial, foi confirmada a **primitiva** (conteúdo do schema
escapando do literal), mas não um payload que gerasse Go válido e
compilável. Isso mudou na implementação — ver abaixo.

### Descoberta durante a implementação: o vetor real era `.Name`, não só a struct tag

Ao escrever os testes de regressão, ficou claro que o vetor **dominante** no
payload acima não era a struct tag isolada, e sim `.Name` — o identificador Go
de tipo, campo e tipo do enum (`type {{ .Name }} struct`,
`{{ .Name }} {{ .Type }} ...`, `type {{ $t.Name }} string`), derivado de
`strcase.ToPascal(nome_bruto_do_schema)` e emitido **sem nenhum escape**,
direto como token de Go. Confirmado empiricamente que `strcase.ToPascal`
**preserva** backtick, parênteses e chaves em vez de filtrá-los.

Essa é uma posição de interpolação inteiramente separada da struct tag e do
valor do símbolo do enum — e como é posição de **identificador** (não de
string), não dá para "escapar" um backtick nela: a correção teve que ser
sanitizar o valor, não escapá-lo (posição de identificador em Go exige um
token, não aceita concatenação de literais — confirmado com um teste de
compilação direto: `Field Type `` `raw1` + "x" + `raw2` `` é erro de sintaxe).

O mesmo problema foi encontrado, de forma independente, no **nome da
constante do enum** (`{{ printf "%s%s" $t.Name . | upperCamel }}`, que
concatena o símbolo bruto com o nome do tipo e passa por `ToPascal` sem
filtrar).

Também achado no mesmo lote, fora do escopo original: `cmd/avrogen/main.go`
**reimplementa** a lógica de formatação de `gen/gen.go` de forma
independente (não chama `gen.StructFromSchema`) e tinha o mesmo bug de
"escreve saída malformada no arquivo antes de reportar o erro de
formatação" — corrigido junto.

### Correção implementada

- Struct tag (`gen/gen.go`, novo `buildTag`): renderizada como raw string
  (backtick) idêntica à saída anterior sempre que nenhum valor contiver
  backtick; cai para string interpretada (`strconv.Quote`) só quando
  necessário.
- Símbolo de enum: trocado para `{{ printf "%q" . }}`.
- `.Name` (tipo, campo, tipo do enum) e nome da constante do enum: sanitizados
  via nova função `sanitizeIdent` — remove todo caractere que não seja
  letra/dígito/underscore Unicode e garante que não comece com dígito. É
  *no-op* para qualquer nome que já satisfaça as regras de nome do Avro.
- `gen.go` e `cmd/avrogen/main.go`: não escrevem mais a saída quando a
  formatação falha.

### Verificação

Verificado com **compilação real** (`go build`, não só `go/parser`): um
schema hostil via `SkipNameValidation` gera um pacote Go que compila
(exit 0), com o nome do campo sanitizado para algo como
`AFuncInitPrintlnpwnedTypeDummyStructXStringx` e o payload original inerte
dentro da tag como string escapada — sem `func init()` nem `type dummy`
injetados.

Saída do `avrogen` comparada byte a byte (via `git stash`) antes/depois em
três cenários — schema básico, com `-tags`/`-encoders`/`-enums`, e um schema
com enum dedicado — **idêntica** nos três.

---

<a id="sec-06"></a>
## SEC-06 — Aliasing de slab em `readBytes`

| | |
|---|---|
| **Severidade** | Baixa |
| **Local** | `reader.go:302` |
| **Fase** | [4 — Gerador e hardening do `Reader`](#fase-4--gerador-e-hardening-do-reader) |

```go
dst := r.slab[:size]     // cap(dst) estende sobre a região das leituras seguintes
r.slab = r.slab[size:]
```

`dst` volta com capacidade sobrando. Um `append` no `[]byte` devolvido por
`ReadBytes` escreve na memória que respalda valores lidos depois — e
`ReadString` (`reader.go:277`) devolve string via `unsafe.Pointer` sobre esse
mesmo slab. Resultado possível: **mutação de uma string**, quebrando a
imutabilidade garantida pela linguagem.

Exige um padrão de uso específico do consumidor (append no resultado de
`ReadBytes` enquanto segura strings lidas depois), por isso severidade baixa.

### Correção implementada

Uma linha: `dst := r.slab[:size]` → `dst := r.slab[:size:size]` (full slice
expression), sem custo de performance.

Teste de regressão escrito e **confirmado discriminante**: rodado
propositalmente contra o `reader.go` pré-fix (via `git stash`), falha com
`mutated == "foobar"` (contaminado por uma leitura posterior) em vez do
esperado `"fooXYZ"`; passa limpo com o fix.

---

<a id="sec-07"></a>
## SEC-07 — `klauspost/compress` v1.18.2

| | |
|---|---|
| **Severidade** | Baixa |
| **Referências** | `GO-2026-5841`, `GHSA-259r-337f-4rfw` |
| **Fase** | [3 — Dependências, toolchain e CI](#fase-3--dependências-toolchain-e-ci) |

OOB read em `s2.NewDict`. Corrigido em **v1.18.7**.

Este repositório usa `zstd`, não `s2` — o govulncheck classifica como
`REQUIRED` (módulo exigido, símbolo não alcançado). Mesmo assim é o **único
achado de dependência que se propaga para consumidores**: o `go.mod` daqui pode
fixar a versão vulnerável via MVS no build de quem consome a lib.

Único achado de dependência do repositório. O Trivy não o reportou (0
vulnerabilidades em 15 pacotes); só apareceu no govulncheck.

### Correção implementada

`go get github.com/klauspost/compress@v1.18.7` (patch mínimo, não a v1.19.1 —
mantém o diff pequeno). Confirmado: `govulncheck` deixou de reportar
`GO-2026-5841`.

---

<a id="sec-08"></a>
## SEC-08 — Toolchain desatualizado e Go 1.24 (EOL) no CI

| | |
|---|---|
| **Severidade** | Média |
| **Local** | ambiente local e `.github/workflows/test.yml` |
| **Fase** | [3 — Dependências, toolchain e CI](#fase-3--dependências-toolchain-e-ci) |

O govulncheck reportou **21 vulnerabilidades da stdlib alcançáveis pelo código**
(`CALLED`), todas decorrentes do toolchain local estar em `go1.25.0`. Atingem
`crypto/tls`, `crypto/x509`, `net/url`, `encoding/asn1` e `encoding/pem` via
`registry/client.go` (HTTP/TLS) e `ocf/`. As correções vão de `go1.25.2` a
`go1.25.12`.

Duas ressalvas importantes:

- Isto é uma **biblioteca**. A stdlib não é artefato entregue — quem compila é o
  consumidor. É risco de ambiente de dev/CI, não algo que vaza para o usuário
  final da lib.
- O `actions/setup-go` resolve `"1.25"` para o último patch, então **o CI nunca
  ficou com stdlib desatualizada**.

O problema concreto no CI era outro: a matriz ainda incluía **Go 1.24, que
está EOL** desde o lançamento do 1.26 e não recebe mais patches de segurança.

### Correção implementada

- Matriz do CI (`test.yml`): `[1.24, 1.25]` → `[1.25, 1.26]`; job `build`:
  `1.25` → `1.26`.
- `go 1.24.0` **mantido** no `go.mod` (tirar da matriz de teste é diferente de
  encerrar suporte declarado; isso ficaria para uma decisão à parte).
- Go pinado em `1.26` no `mise.toml` (antes só tinha `claude = "latest"`) —
  evita que o toolchain local do time volte a divergir, causa raiz dos 21
  achados.

---

<a id="sec-09"></a>
## SEC-09 — `Reader.ReadArrayCB` sem consumo do callback ainda gira o count declarado

| | |
|---|---|
| **Severidade** | Baixa |
| **Local** | `reader_generic.go:132` |
| **Fase** | nenhuma — documentado, não corrigido (ver justificativa) |

Achado durante a verificação de fechamento da [SEC-01](#sec-01)/`CVE-2026-46385`
após a Fase 1. `ReadMapCB` (`reader_generic.go:149`) lê a chave do mapa
(`r.ReadString()`) **incondicionalmente** a cada iteração, então mesmo com um
callback vazio ele consome bytes e detecta EOF sozinho. `ReadArrayCB` não tem
leitura obrigatória equivalente — quem consome o elemento é inteiramente o
callback `fn`. Se `fn` nunca ler de `r`, o loop corrigido na Fase 1 (que só
olha `r.Error`) nunca vê erro, e roda as `l` iterações declaradas.

### Evidência

Payload de 6 bytes, mesmo do PoC da SEC-01, chamando `ReadArrayCB` direto com
um callback vazio:

```
Reader.ReadArrayCB    AINDA RODANDO apos 5s   <-- CVE-2026-46385 NAO CORRIGIDA (neste uso especifico)
```

### Por que não foi corrigido

**Não é o mecanismo que a CVE descreve, nem é alcançável por um atacante que
controla apenas os bytes do payload.** O único chamador interno de
`ReadArrayCB`/`ReadMapCB` é `Reader.ReadNext` (`reader_generic.go:84,92`), e o
callback dele sempre lê de `r` (`r.ReadNext(...)`). A lacuna só se manifesta
se código de terceiros chamar `Reader.ReadArrayCB` diretamente com um
callback que ignora o `*Reader` recebido — um padrão de uso que nenhum
caminho de decode desta biblioteca exercita. Pré-existente: o comportamento é
idêntico antes e depois da Fase 1.

Uma correção via `r.Peek()` proativo no início de cada iteração (detectaria
EOF independente do callback) foi considerada e descartada: um schema
`fixed` com `size: 0` é válido nesta lib (`schema.go:1364` só rejeita
negativo), e um array desse tipo no fim do stream se codifica em zero bytes —
o `Peek()` erraria "acabaram os dados" quando na verdade não sobra nada por
decodificar. Introduzir essa regressão de correção para fechar um caminho que
a CVE não cobre não foi considerado um bom custo-benefício.

**Mitigação aplicada**: o godoc de `ReadArrayCB` agora deixa explícito que
`fn` deve consumir de `r` a cada chamada — o contrato real da função, que
antes não estava documentado.

---

## Verificado e sem achado

Registrado para não virar retrabalho em auditorias futuras:

| Área | Conclusão |
|---|---|
| `codec_union.go:628` | bounds check correto, inclusive índice negativo |
| `codec_enum.go` + `EnumSchema.Symbol` (`schema.go:996`) | bounds check correto |
| `reader.go readBytes` (`:280`) | valida sinal e aplica `MaxByteSliceSize` (default 1 MiB) |
| Recursão de schema | testado com aninhamento de 200.000 níveis — o parser JSON rejeita antes de estourar a pilha. **Não** explorável |
| `registry/` | timeouts configurados, sem `InsecureSkipVerify`, credenciais só via `req.SetBasicAuth` |
| `soe/` | valida magic, comprimento mínimo e tamanho do fingerprint |
| Trivy — secrets e misconfig | nenhum |

---

# Fases de implementação

Cada fase foi desenhada como um MR independente, com escopo, critério de
aceite e verificação próprios — para permitir dividir o trabalho ou revisar
em pedaços menores, mesmo tendo sido implementadas em sequência nesta sessão.

<a id="fase-1--decoders-do-pacote-raiz"></a>
## Fase 1 — Decoders do pacote raiz

Corrige [SEC-01](#sec-01) (`CVE-2026-46385`) e [SEC-02](#sec-02).
**Dependências:** nenhuma.

**Objetivo**: fazer com que um payload Avro truncado ou hostil produza erro
imediato em vez de consumir CPU indefinidamente ou alocar memória sem limite.

**Escopo**: `codec_skip.go`, `codec_map.go`, `reader_generic.go` (sair do
loop no primeiro erro, 5 pontos) e `codec_array.go` (crescimento incremental
do slice). Sem mudança de assinatura pública, sem mudança de comportamento
para entrada válida.

**Testes de regressão** (`security_dos_test.go`, novo): 8 testes, um por
vetor (`sliceSkipDecoder`, `mapSkipDecoder`, `mapDecoderUnmarshaler`,
`ReadArrayCB`, `ReadMapCB`, `arrayDecoder` com destino `any` e tipado, mais um
teste de correção para array legítimo cruzando fronteira de chunk), cada um
rodando o decode em goroutine com timeout de 3s para nunca travar o CI.

- [x] Os 5 loops de SEC-01 interrompem no primeiro erro do reader
- [x] `arrayDecoder` não pré-aloca com base no count declarado
- [x] Teste de regressão para cada vetor, com timeout
- [x] `make ci` verde
- [x] Comportamento inalterado para payloads válidos
- [x] Sem regressão de alocação nos benchmarks

Risco: baixo (checagens adicionais em caminhos de erro); o ponto de maior
atenção foi `arrayDecoder` por tocar o hot path de decode de arrays — coberto
pelo benchmark como critério de aceite, não opcional.

---

<a id="fase-2--pacote-ocf"></a>
## Fase 2 — Pacote `ocf/`

Corrige [SEC-03](#sec-03) e [SEC-04](#sec-04). **Dependências:** nenhuma.

**Objetivo**: fazer com que um arquivo OCF malformado ou hostil produza erro,
nunca panic nem alocação ilimitada.

**Escopo**: `ocf/ocf.go` (validar `size` do bloco antes do `make`, novo
`WithMaxBlockSize`) e `ocf/codec.go` (limitar a saída da descompressão nos 3
codecs, usando o mesmo teto).

**Testes de regressão** (`ocf/security_dos_test.go`, novo): 7 testes —
`size` negativo (branch `count>0` e branch de skip com `count=0`), `size`
acima do teto, bomba de descompressão em cada um dos 3 codecs, e um teste de
correção garantindo que um arquivo OCF legítimo com `WithMaxBlockSize`
continua decodificando.

- [x] Nenhuma entrada faz o pacote `ocf` entrar em panic
- [x] `size` negativo e acima do teto viram erro
- [x] Os 3 codecs têm limite de saída
- [x] Teto configurável via `DecoderFunc`, com default documentado
- [x] Limitação do zstd com decoder compartilhado documentada no godoc
- [x] `make ci` verde

Risco: médio na teoria (um teto pode rejeitar arquivos legítimos com blocos
grandes) — mitigado com default folgado (100 MiB) e configurável.

---

<a id="fase-3--dependências-toolchain-e-ci"></a>
## Fase 3 — Dependências, toolchain e CI

Corrige [SEC-07](#sec-07) e [SEC-08](#sec-08). **Dependências:** nenhuma —
foi a fase de menor risco, sem tocar código de produção.

**Objetivo**: fechar o único achado de dependência e tirar do CI uma versão
de Go que não recebe mais patches de segurança.

**Escopo**: `go.mod`/`go.sum` (bump `klauspost/compress`), `.github/workflows/test.yml`
(matriz `[1.24,1.25]` → `[1.25,1.26]`), `mise.toml` (pinar Go).

- [x] `klauspost/compress` em v1.18.7 no `go.mod`/`go.sum`
- [x] Matriz do CI em `[1.25, 1.26]`, job `build` em 1.26
- [x] `go 1.24.0` mantido no `go.mod`
- [x] Go pinado no `mise.toml`
- [x] `make ci` verde
- [x] `govulncheck ./...` sem findings de dependência

Risco: baixo. Bump validado em cópia descartável antes mesmo da implementação
(build OK, 1387 testes); ajuste de CI não afeta artefato publicado.

---

<a id="fase-4--gerador-e-hardening-do-reader"></a>
## Fase 4 — Gerador e hardening do `Reader`

Corrige [SEC-05](#sec-05) e [SEC-06](#sec-06). **Dependência:** Fase 1 (o
ajuste em `reader.go` fica em código vizinho ao que a Fase 1 altera).

**Objetivo**: impedir que conteúdo controlado pelo schema escape para posição
de código no arquivo gerado, e eliminar o aliasing de memória no `Reader`.

**Escopo real** (maior que o planejado — ver [SEC-05](#sec-05) para a
descoberta feita durante a implementação): `gen/output_template.tmpl`,
`gen/gen.go` (`buildTag`, `sanitizeIdent`, `enumConstName`, não escrever saída
malformada), `cmd/avrogen/main.go` (mesmo bug de saída malformada, achado
fora do escopo original), `reader.go` (full slice expression).

**Testes de regressão**: `gen/security_injection_test.go` (novo — nome de
campo hostil e símbolo de enum hostil, cada um verificado com
`go/parser.ParseFile` checando ausência de `func init()`/`type dummy`
injetados), `cmd/avrogen/main_test.go` (novo teste garantindo que nenhum
arquivo é criado quando a formatação falha), `reader_test.go` (novo teste de
aliasing do slab).

- [x] Nome de campo hostil não escapa da struct tag
- [x] Símbolo de enum hostil não escapa do literal
- [x] Saída malformada não é escrita em arquivo
- [x] `reader.go:302` usa full slice expression
- [x] Testes de regressão cobrindo os casos, incluindo os achados fora do
      escopo original (`.Name`, nome da constante do enum, `avrogen` main.go)
- [x] `make ci` verde
- [x] Saída do gerador inalterada para schemas válidos (verificado byte a
      byte via `git stash` em 3 cenários)

Risco: baixo, mas mexeu em template de geração de código — qualquer erro
apareceria como diferença na saída para schemas válidos, por isso o diff
byte-a-byte foi tratado como critério de aceite obrigatório, não opcional.

---

<a id="fase-5-prevenção"></a>
## Fase 5 — Prevenção

Não corrige achado específico — existe para que a classe de bugs das Fases 1
e 2 não volte sem ser notada. **Dependência:** Fases 1 e 2.

**Motivação**: nenhuma das duas ferramentas automatizadas usadas no
levantamento (Trivy, govulncheck) detectou qualquer um dos 9 achados de
código — ambas só analisam dependências. Para uma biblioteca que decodifica
entrada não confiável, a defesa efetiva é fuzzing e teste de regressão.

**Implementado**:

- `govulncheck` como step em `.github/workflows/test.yml`, rodando em ambos
  os Go da matriz. A política "quebra para `CALLED`, só reporta os demais" é
  o comportamento **padrão** do CLI com `-scan symbol` (default) — confirmado
  lendo o código-fonte do `golang.org/x/vuln` (`internal/scan/text.go`): o
  exit code 3 só é retornado quando há finding `isCalled`. Nenhuma flag extra
  foi necessária.
- 3 targets de fuzzing: `FuzzDecode` e `FuzzParseSchema` (pacote raiz,
  `fuzz_test.go`, novo), `FuzzOCFDecode` (`ocf/fuzz_test.go`, novo). Corpus
  semeado com `testdata/*.avsc`, `testdata/superhero.bin`, todos os `.avro`
  em `ocf/testdata/`, e o payload exato do PoC de SEC-01/SEC-02.
- `.github/workflows/fuzz.yml` (novo): job agendado (diário + `workflow_dispatch`),
  matriz de 3 entradas (uma por target), `-fuzztime=10m` cada, upload do
  corpus de crash como artefato em caso de falha.
- O corpus semeado já roda em todo PR **sem step novo**: `go test ./...`
  (já existente) executa qualquer `FuzzXxx` como teste comum sobre o corpus
  quando chamado sem `-fuzz` — confirmado localmente.

**Nota — investigação de um falso alarme em `FuzzOCFDecode`**: ao rodar com
`-fuzz` de verdade, o contador de execuções parou (`0/sec`) por dezenas de
segundos, reproduzindo mais rápido com `-parallel=2` que com o default.
Investigado a fundo antes de aceitar como normal: nenhuma das entradas
"interesting" persistidas no cache do fuzzer reproduziu lentidão isoladamente
(todas <15ms); nenhum crasher foi gravado em `testdata/fuzz/`; a pausa
correlacionou precisamente com o evento "new interesting" subindo —
consistente com a fase de minimização sequencial do próprio motor de
fuzzing do Go, não com um hang no código sob teste. Não tratado como achado.

- [x] `govulncheck` roda no CI com política de falha definida
- [x] 3 targets de fuzzing com corpus semeado
- [x] Payloads dos PoCs de SEC-01/SEC-02/SEC-03 no corpus
- [x] Fuzzing do corpus semeado roda em todo PR
- [x] Job agendado de fuzzing configurado
- [x] `make ci` verde

Risco: baixo — só adiciona verificação. O risco operacional é um job de
fuzzing que falha com frequência e passa a ser ignorado; se acontecer,
preferir reduzir o escopo a manter um sinal que ninguém olha.

**Fora de escopo**: `/reports` no `.gitignore` — já feito pelo desenvolvedor
antes desta remediação.
