# Plano de remediação de segurança — 30/07/2026

Continuação de [`docs/seguranca-2026-07-29/`](../seguranca-2026-07-29/README.md).
Remediação realizada em **30/07/2026** sobre o commit `294fbec`, cobrindo dois
CVEs publicados em **27/07/2026** — depois do levantamento da sessão anterior.

A numeração `SEC-NN` continua a da sessão de 29/07 (que terminou em `SEC-09`).

## Contexto

Em 27/07/2026 foram publicadas duas advisories contra `github.com/hamba/avro/v2`
como **"all versions, no known fixed version"**:

| OSV | CVE / GHSA | Título |
|---|---|---|
| `GO-2026-5047` | `CVE-2026-46384` / `GHSA-mc57-h6j3-3hmv` | Integer overflow e narrowing no decoder |
| `GO-2026-5048` | `GHSA-mx64-mj3q-7prj` | Exaustão de memória por alocação ilimitada de map |

Ambas foram corrigidas upstream apenas no fork `github.com/iskorotkov/avro/v2`
(v2.33.0). Como a Qive mantém o próprio fork, a correção foi **portada para este
repositório** — não adotamos o `iskorotkov/avro` como upstream.

As advisories recomendam migrar o import path para `iskorotkov/avro/v2`. Isso
**não** se aplica aqui: contrariaria a regra do `AGENTS.md` de não alterar o
module path, e trocaria um fork mantido internamente por um fork de terceiro.

## Por que o govulncheck não acusa isso

Mesmo motivo já registrado em 29/07, agravado pela renomeação do module path:

- As OSVs listam `github.com/hamba/avro/v2`. Depois da renomeação para
  `github.com/arquivei/avro/v2` (commit `294fbec`), o module path **não bate
  mais** — o govulncheck nem carrega as advisories.
- E mesmo se batesse, o govulncheck não reporta vulnerabilidade no próprio main
  module, só nas dependências.

Consequência: **estes dois achados não têm sinal automatizado neste repo**. Foram
encontrados lendo as advisories publicadas e conferindo o código à mão. O
`govulncheck` continua útil só para a stdlib e dependências.

Corolário para consumidores internos: quem ainda aponta para
`github.com/hamba/avro/v2` via `replace` **vai** ver `GO-2026-5047`/`GO-2026-5048`
no próprio govulncheck, ainda que já esteja usando o código corrigido daqui. A
saída é migrar o import path.

## Achados

| ID | Título | Severidade | Estado |
|---|---|---|---|
| [SEC-10](#sec-10) | Narrowing e overflow de valores de 64 bits do wire (`CVE-2026-46384`) | Alta (CVSS 8.7) | ✅ Corrigido |
| [SEC-11](#sec-11) | Crescimento ilimitado de map decodificado (`GO-2026-5048`) | Média | ✅ Corrigido (opt-in) |

## Estado final

Validado com:

- `go build`, `go vet` e `golangci-lint` limpos (`make ci` verde).
- **1460 testes passando** (1436 da sessão anterior + 24 novos em
  `security_overflow_test.go`).
- Sem regressão de alocação: `B/op` e `allocs/op` idênticos à baseline nos 6
  benchmarks do pacote raiz (`go test -bench=. -benchmem -run=^$ .`, `-count=5`,
  comparando mediana antes/depois). Nenhuma variação de tempo acima do ruído.
- Cross-build OK para `386`, `arm`, `arm64`, `ppc64le` e `s390x`.
- Regressões confirmadas por reversão: com `reader.go` revertido, os subtestes de
  `TestSecurity_ReadBlockHeader_RejectsOutOfRangeHeader` falham e
  `TestSecurity_ReadBytes_ExceedsMaxAllocSize` **panica** com
  `runtime error: makeslice: len out of range`.

---

<a id="sec-10"></a>
## SEC-10 — Narrowing e overflow de valores de 64 bits do wire

| | |
|---|---|
| **Severidade** | Alta (CVSS 8.7) |
| **Referências** | `GO-2026-5047`, `CVE-2026-46384`, `GHSA-mc57-h6j3-3hmv` |

Uma família de bugs com a mesma forma: o decoder lê um valor de 64 bits do wire,
**estreita para `int` antes de validar**, e valida o valor estreitado. Em builds
de 32 bits (`386`, `arm` — ambos na matriz do CI) o estreitamento trunca:
`(1<<32)+5` vira `5`. O limite passa a ser conferido contra um valor que o
decoder nunca usa.

Isso é diretamente relevante para este repo por causa da regra do `AGENTS.md`:
**não assumir plataforma 64-bit** — o CI compila para `386` e `arm`.

Nota importante para leitura dos testes: vários destes payloads **já falhavam em
amd64** antes da correção, porque em 64 bits o valor não trunca e cai no limite
normal. O que a correção garante é que a validação aconteça sobre o `int64`, o
que torna o comportamento idêntico em 32 e 64 bits. Os testes que de fato
reprovam o código pré-fix em amd64 estão listados em [Estado final](#estado-final).

### Pontos afetados

| Arquivo | Função | Sub-issue |
|---|---|---|
| `reader.go` | `Reader.ReadBlockHeader` | header estreitado antes de validar; `-math.MinInt64` devolve `math.MinInt64` |
| `reader.go` | `Reader.readBytes` (via `ReadBytes`/`ReadString`) | length estreitado antes de conferir `MaxByteSliceSize` |
| `reader_skip.go` | `Reader.SkipString`, `Reader.SkipBytes` | length estreitado; skip curto deixa o reader desalinhado |
| `reader_generic.go` | `Reader.ReadNext`, ramo `Union` | índice de union estreitado antes do bounds-check |
| `codec_array.go` | `arrayDecoder.Decode` | soma cumulativa de blocos pode dar wrap antes de bater no limite |
| `ocf/ocf.go` | `Decoder.readBlock`, `skipToEnd` | `size` do bloco chega a `make` / `SkipNBytes` sem caber num `int` |

Não afetado: o decoder de union tipado (`codec_union.go`) usa `Reader.ReadInt`,
que devolve `int32` — não há narrowing.

### Impacto por sub-issue

- **`ReadBlockHeader`** — negar o count é o sinal Avro de "size vem a seguir".
  Com `count == math.MinInt64`, `-count` é `math.MinInt64` de novo (overflow de
  inteiro com sinal em Go dá wrap), então o chamador recebe um "length" negativo
  e trata como bloco válido.
- **`readBytes`** — com `MaxByteSliceSize` desabilitado (negativo), um length
  acima do espaço de heap alocável chega a `make([]byte, size)`: **panic**
  (`makeslice: len out of range`) ou OOM. Este é o único sub-issue com PoC que
  panica em amd64.
- **Índice de union (decode genérico)** — `1<<32` estreita para `0` em 32 bits e
  seleciona `types[0]` silenciosamente. Em union nullable `["null", T]` — a forma
  idiomática — o resultado prático é `nil` onde o produtor codificou payload:
  **corrupção silenciosa de dados**, não só DoS.
- **Skip truncado** — pula menos bytes do que devia e o reader continua lendo do
  meio do bloco, interpretando dados como estrutura.
- **Soma cumulativa em array** — `size += int(l)` pode dar wrap para negativo e
  passar pelo `> limite`.

### Correção implementada

Padrão único, aplicado nos 6 pontos: **ler em `int64`, validar todos os limites
sobre o `int64`, e só então estreitar**.

- `ReadBlockHeader` passou a exigir que count e size caibam em `int32` — nenhum
  bloco legítimo declara mais que `math.MaxInt32` elementos ou bytes, e aceitar
  mais largo é exatamente o que permite o truncamento. `math.MinInt64` é
  rejeitado antes da negação. Em erro devolve `(0, 0)`, que todos os chamadores
  já tratam como "fim dos blocos" seguido de checagem de `r.Error`.
- `readBytes` compara o length contra `MaxByteSliceSize` **e** contra
  `maxAllocSize` (este último cobre o caso do limite desabilitado) antes de
  estreitar. O cálculo de `fnName` continua dentro dos ramos de erro — trazê-lo
  para fora alocaria no hot path.
- Novo `Reader.SkipNBytesInt64(int64)` (API pública), usado por `SkipString`,
  `SkipBytes` e `ocf.skipToEnd`. Delega ao `SkipNBytes` existente em fatias de
  até `math.MaxInt32`, preservando o caminho rápido. `SkipNBytes(int)` fica
  inalterado.
- `arrayDecoder` compara `int64(size) + chunk > maxSize` em `int64`, **antes** de
  aplicar a soma ao acumulador `int`. O lookup de `getMaxSliceAllocSize()` saiu
  de dentro do loop.
- `ocf.readBlock` rejeita `size` que não caiba num `int` da plataforma (`maxInt`,
  nova constante) — alcançável quando `WithMaxBlockSize` desabilita o limite.
  `ocf.skipToEnd` passou a rejeitar `size` negativo e a pular via
  `SkipNBytesInt64`.

### Compatibilidade

Não quebra a API pública: só adiciona `Reader.SkipNBytesInt64`. `ReadBlockHeader`
mantém a assinatura `(int64, int64)`; passa a reportar erro em headers que antes
devolvia silenciosamente — todos fora da faixa que um encoder Avro legítimo
produz. `TestSecurity_ReadBlockHeader_AcceptsInt32Bounds` fixa o limite exato
(`math.MaxInt32` ainda é aceito) para que ele não seja apertado por acidente.

---

<a id="sec-11"></a>
## SEC-11 — Crescimento ilimitado de map decodificado

| | |
|---|---|
| **Severidade** | Média |
| **Referências** | `GO-2026-5048`, `GHSA-mx64-mj3q-7prj` |

`mapDecoder.Decode` e `mapDecoderUnmarshaler.Decode` aceitam o count de cada
bloco vindo do wire e crescem o map de destino sem limite superior. Um produtor
hostil declara um map arbitrariamente grande — num bloco só, ou fatiado em muitos
blocos individualmente pequenos — até o OOM killer agir.

Não havia limite equivalente ao `MaxSliceAllocSize` dos arrays.

### Nota sobre a severidade real neste repo

Diferente do que a advisory descreve para o upstream, aqui os decoders de map
**não pré-alocam** a partir do count: `UnsafeMakeMap(0)` e crescimento por
inserção. Cada entrada exige ler uma chave e um valor de verdade, e o loop para
no primeiro erro do `Reader` (correção de SEC-01). Ou seja: não existe o vetor
"um bloco declara `2^31` entradas e o processo aloca na hora".

O que sobra é amplificação — uma entrada de map custa mais memória que os bytes
que ela ocupa no wire — e é isso que `MaxMapAllocSize` limita. Real, mas
bem menos grave que o descrito na advisory.

### Correção implementada

Novo `Config.MaxMapAllocSize`, espelhando `MaxSliceAllocSize`:

- Acumulado **entre blocos**, então não dá para burlar fatiando as entradas em
  vários blocos abaixo do limite. Esse era o vetor mais interessante.
- Acumulador em `int64`, e ambos os operandos já estão limitados por
  `ReadBlockHeader` (SEC-10) — a soma não pode dar wrap.
- Aplicado nos dois decoders (`mapDecoder` e `mapDecoderUnmarshaler`).

### Default: opt-in, deliberadamente

**Só subir a versão não protege.** O default (`0`) resolve para `maxAllocSize` —
efetivamente ilimitado. Consumidores de entrada não confiável precisam setar
`MaxMapAllocSize` explicitamente:

```go
cfg := avro.Config{MaxMapAllocSize: 10_000}.Freeze()
dec := cfg.NewDecoder(schema, r)
```

Três razões para não ligar por default, apesar da convenção "seguro por default"
que SEC-03/SEC-04 seguiram:

1. `MaxSliceAllocSize` — o limite análogo, para arrays — já é opt-in com
   exatamente essa convenção (`size <= 0` → `maxAllocSize`). Um default diferente
   para maps seria inconsistente.
2. Qualquer valor default quebraria silenciosamente quem hoje decodifica maps
   grandes e legítimos. É um limite sobre **contagem de entradas**, sem valor
   "obviamente alto o bastante" — diferente de `MaxBlockSize` (100 MiB) ou
   `MaxByteSliceSize` (1 MiB), que são em bytes.
3. É o que a advisory do upstream especifica, o que mantém a semântica portável
   entre os forks.

`TestSecurity_MapDecoder_DefaultIsUnbounded` documenta essa escolha como teste,
para que ela seja uma decisão visível e não um esquecimento.

**Isto é uma pendência para os consumidores**, não para a lib: os serviços da
Qive que decodificam Avro de Kafka ou de upload de terceiro devem setar
`MaxMapAllocSize` (e `MaxSliceAllocSize`) nas próprias configs.

---

## Cobertura de regressão

Tudo em `security_overflow_test.go` (novo, 24 testes), seguindo o padrão de
`security_dos_test.go` da sessão anterior. Helpers: `craftLongs` (monta payload
de longs Avro crus, para produzir headers que o `WriteBlockHeader` nunca geraria)
e `craftMap` (monta map válido fatiado em blocos).

| Teste | Cobre |
|---|---|
| `TestSecurity_ReadBlockHeader_RejectsOutOfRangeHeader` | 5 casos: count `math.MinInt64`, count negado > `MaxInt32`, count > `MaxInt32`, size > `MaxInt32`, size negativo |
| `TestSecurity_ReadBlockHeader_AcceptsInt32Bounds` | guarda o limite exato contra aperto acidental |
| `TestSecurity_ArrayDecoder_MinInt64BlockCount`, `..._MapDecoder_...` | end-to-end do count `math.MinInt64` |
| `TestSecurity_ReadBytes_ExceedsMaxAllocSize` | `bytes` e `string` com `MaxByteSliceSize` desabilitado |
| `TestSecurity_GenericUnionIndex_OutOfRange` | índice de union fora da faixa não vira `types[0]` |
| `TestSecurity_SkipBytes_LargeLength` | `SkipBytes` e `SkipString` com length além dos dados |
| `TestSecurity_MapDecoder_ExceedMaxMapAllocSize` | SEC-11 em bloco único **e** fatiado |
| `TestSecurity_MapDecoderUnmarshaler_ExceedMaxMapAllocSize` | idem, no decoder com chave `TextUnmarshaler` |
| `TestSecurity_MapDecoder_WithinMaxMapAllocSize` | guarda de correção: total exatamente no limite ainda decodifica |
| `TestSecurity_MapDecoder_DefaultIsUnbounded` | documenta o default opt-in |

### Limitação conhecida da suíte

Os testes do pacote raiz **não compilam sob `GOARCH=386`** — três arquivos de
teste pré-existentes (`decoder_native_test.go:103`, `encoder_native_test.go:279`,
`encoder_union_test.go:690`) usam constantes que estouram `int` em 32 bits. Isso
é anterior a esta sessão. Os outros 9 pacotes rodam e passam em `386`.

Efeito prático: os sub-issues de SEC-10 que **só** se manifestam em 32 bits não
têm teste que reprove o código pré-fix em CI. A cobertura acima valida que a
checagem acontece sobre o `int64`, que é o que torna as duas plataformas
equivalentes — mas a verificação de ponta a ponta em 32 bits depende de arrumar
aqueles três arquivos. Candidato a follow-up.
