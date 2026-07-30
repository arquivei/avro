# Contexto do Projeto

## O que é este serviço

`avro` é um **codec Avro para Go de alta performance** — é uma biblioteca, não um serviço.
Implementa encode/decode conforme a especificação Apache Avro, com foco em baixa alocação.

Este repositório é o fork **`arquivei/avro`** do projeto `hamba/avro`, cujo upstream foi
**descontinuado** pelo autor original. A Qive assumiu a **manutenção interna ativa**:
correções, novas features e bumps de dependência passam a ser feitos aqui.

O module path continua sendo `github.com/hamba/avro/v2` — os consumidores internos apontam
para este fork via `replace` no `go.mod`.

Capacidades principais:

- Encode/decode Avro binário (`avro.Marshal` / `avro.Unmarshal`)
- OCF — Object Container Files (`ocf/`)
- SOE — Single Object Encoding (`soe/`)
- Cliente do Confluent Schema Registry (`registry/`)
- Geração de structs Go a partir de schemas (`gen/` + CLI `avrogen`)
- Validação de schemas em pipelines CI/CD (CLI `avrosv`)

## Comandos

```bash
make test    # go test -cover -race ./...
make lint    # golangci-lint run ./...
make fmt     # golangci-lint fmt ./...
make tidy    # go mod tidy
make ci      # lint + test

# Teste específico
go test -run TestDecoder_Record ./...

# Benchmarks — guarda contra regressão de alocação
go test -bench=. -benchmem -run=^$ .

# CLIs
go run ./cmd/avrogen -pkg avro -o out.go in.avsc   # gera structs Go do schema
go run ./cmd/avrosv in.avsc                        # valida schema (exit != 0 se inválido)
```

Ferramentas via `mise.toml` na raiz. O CI usa golangci-lint **v2.12.2**.

## Arquitetura

Biblioteca Go com o pacote principal na raiz e subpacotes por formato/funcionalidade.

```
.                    # package avro — núcleo do codec
├── cmd/avrogen/     # CLI: gera structs Go a partir de .avsc
├── cmd/avrosv/      # CLI: valida schemas .avsc
├── docs/seguranca-2026-07-29/  # achados de segurança e plano de remediação (29/07/2026)
├── gen/             # lib de geração de código usada pelo avrogen
├── ocf/             # Object Container Files (codecs null/deflate/snappy/zstandard)
├── soe/             # Single Object Encoding (magic C3 01 + fingerprint CRC64-LE)
│   └── resolvers/   # MemorySchemaStore — resolve schema por fingerprint
├── registry/        # cliente HTTP do Confluent Schema Registry
├── pkg/crc64/       # checksum CRC-64-AVRO (fingerprint de schema)
├── internal/bytesx/ # ResetReader — leitura sobre []byte reaproveitável
└── testdata/        # schemas .avsc e payloads .bin dos testes
```

Núcleo (raiz):

| Arquivo | Responsabilidade |
|---|---|
| `schema.go`, `schema_parse.go` | modelo e parsing de schemas Avro |
| `schema_compatibility.go` | regras de compatibilidade entre schemas |
| `codec_*.go` | um arquivo por tipo Avro (record, union, map, array, enum, fixed, native…) |
| `reader.go` / `writer.go` | I/O binário de baixo nível |
| `encoder.go` / `decoder.go` | API de streaming |
| `config.go` + `config_{386,arm,x64}.go` | configuração e ajustes por arquitetura |
| `typeconverter.go`, `converter.go` | conversores de tipo customizados |
| `resolver.go` | registro nome ↔ tipo Go para unions |
| `noescape.go` / `noescape.s` | unsafe + assembly para evitar escape para heap |

Performance é requisito de primeira classe: o codec usa `modern-go/reflect2` para evitar
reflection cara, e o alvo é **zero-alloc** no caminho de decode.

## Convenções

- **Testes black-box por padrão**: `package avro_test`. Use `package avro` só quando o teste
  precisar de internals — e nomeie o arquivo `*_internal_test.go`
  (`converter_test.go` é a exceção histórica).
- **Teardown de config global**: testes que mexem em `avro.DefaultConfig` ou registram tipos
  devem chamar `defer ConfigTeardown()` (helper em `avro_test.go`).
- **Um arquivo por tipo Avro**: `codec_<tipo>.go` + `encoder_<tipo>_test.go` + `decoder_<tipo>_test.go`.
- **Tags de struct**: o mapeamento campo ↔ schema usa a tag `avro:"nome_do_campo"`.
- **Linter não roda em testes** (`run.tests: false`), mas roda com `default: all` no código de
  produção — padrão é linter rígido com exclusões explícitas no `.golangci.yml`.
- **Formatação**: `gofumpt` com `extra-rules`, mais `gci` e `goimports`. Sempre rode `make fmt`.
- **Tabela de conversão Avro ↔ Go**: a fonte da verdade é o README (seção "Types Conversions").
  Mudança de mapeamento exige atualizar o README junto.
- **Commits**: histórico segue Conventional Commits (`feat:`, `fix:`, `chore:`).

## Dependências relevantes

| Dependência | Uso |
|---|---|
| `modern-go/reflect2` | reflection de baixo custo — base da performance do codec |
| `json-iterator/go` | parsing/serialização JSON de schemas |
| `klauspost/compress` | compressão zstd no OCF |
| `golang/snappy` | compressão snappy no OCF |
| `go-viper/mapstructure/v2` | decode de schemas e protocolos (`schema_parse.go`, `protocol.go`) |
| `ettle/strcase` | conversão de nomes no gerador de código (`gen/gen.go`) |
| `golang.org/x/tools` | `imports` — formata o código gerado pelo `avrogen` |
| `stretchr/testify` | asserts nos testes |

Serviço externo: o pacote `registry/` fala HTTP com um **Confluent Schema Registry**.

## O que NÃO fazer

- **Não alterar o module path** `github.com/hamba/avro/v2`. Consumidores internos dependem dele
  via `replace`; renomear quebra todos de uma vez.
- **Não quebrar a API pública.** É uma lib v2 com consumidores externos conhecidos (Apache Arrow
  for Go, confluent-kafka-go, pulsar-client-go). Mudança incompatível exige decisão humana.
- **Não assumir plataforma 64-bit.** Existem `config_386.go` / `config_arm.go` / `config_x64.go`
  e o CI compila para `386`, `arm`, `arm64`, `ppc64le` e `s390x`. Decodificar Avro `long` em
  `int` só é válido em 64 bits.
- **Não introduzir alocações no hot path.** Valide com `go test -bench=. -benchmem` antes e
  depois; `noescape.go`/`noescape.s` existem exatamente para evitar escape para heap.
- **Não subir a versão mínima do Go sem necessidade.** A política é suportar as duas últimas
  versões (matriz do CI: 1.25 e 1.26; `go.mod` mantido em 1.24.0).

## Informações Extras

- **Segurança**: [`docs/seguranca-2026-07-29/`](docs/seguranca-2026-07-29/) —
  catálogo de achados e plano de remediação em 5 fases. Todos os achados
  corrigíveis (incluindo `CVE-2026-46385`) foram corrigidos na sessão de
  29/07/2026 — ver o documento para o único achado deixado deliberadamente
  sem correção (SEC-09) e para o histórico completo antes de mexer nos
  decoders (`codec_*.go`, `reader_generic.go`) ou no pacote `ocf/`.
- Especificação Avro: https://avro.apache.org/docs/current/
- Single Object Encoding: https://avro.apache.org/docs/1.10.2/spec.html#single_object_encoding
- Fingerprints de schema: https://avro.apache.org/docs/current/spec.html#schema_fingerprints
- Regras de nomes Avro: https://avro.apache.org/docs/1.11.1/specification/#names
- API do Confluent Schema Registry: https://docs.confluent.io/current/schema-registry/docs/api.html
- Godoc (mesma API): https://pkg.go.dev/github.com/hamba/avro/v2
- Upstream original (descontinuado): https://github.com/hamba/avro
- Benchmarks comparativos: https://github.com/nrwiersma/avro-benchmarks
- CI: `.github/workflows/test.yml` — lint + testes (Go 1.24/1.25) + build cross-platform dos CLIs
