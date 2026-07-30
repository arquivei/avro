package gen_test

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/arquivei/avro/v2"
	"github.com/arquivei/avro/v2/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests are regression coverage for docs/seguranca-2026-07-29/README.md SEC-05:
// a field name or enum symbol only reachable via avro.SkipNameValidation must
// not be able to escape the generated Go source, even though normal schema
// validation would never allow the characters involved.
//
// assertNoInjectedDecl parses generated Go source and fails if it declares an
// "init" function or a type named "dummy" - the shape of declaration a
// successful escape from a struct tag or string literal would produce.
func assertNoInjectedDecl(t *testing.T, src []byte) *ast.File {
	t.Helper()

	fset := token.NewFileSet()
	astFile, err := parser.ParseFile(fset, "", src, 0)
	require.NoError(t, err, "generated code must remain syntactically valid Go:\n%s", src)

	for _, decl := range astFile.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			assert.NotEqual(t, "init", d.Name.Name, "hostile input must not inject a function declaration")
		case *ast.GenDecl:
			if d.Tok != token.TYPE {
				continue
			}
			for _, spec := range d.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if ok {
					assert.NotEqual(t, "dummy", ts.Name.Name, "hostile input must not inject a type declaration")
				}
			}
		}
	}
	return astFile
}

func TestStruct_HostileFieldNameCannotEscapeStructTag(t *testing.T) {
	avro.SkipNameValidation = true
	defer func() { avro.SkipNameValidation = false }()

	hostile := "a` + \"`\" + `\nfunc init() { println(\"pwned\") }\ntype dummy struct{ x string `x:\""
	schemaJSON := fmt.Sprintf(`{"type":"record","name":"Test","fields":[{"name":%q,"type":"string"}]}`, hostile)

	buf := &bytes.Buffer{}
	err := gen.Struct(schemaJSON, buf, gen.Config{PackageName: "something"})
	require.NoError(t, err)

	assertNoInjectedDecl(t, buf.Bytes())
}

// Enum generation (-enums) is only reachable through the lower-level
// Generator API (gen.WithEnums), not through gen.Config/gen.Struct, so this
// test drives NewGenerator directly instead of gen.Struct.
func TestStruct_HostileEnumSymbolCannotEscapeStringLiteral(t *testing.T) {
	avro.SkipNameValidation = true
	defer func() { avro.SkipNameValidation = false }()

	hostile := `A"; func init(){println("pwned")}; type dummy struct{}; const _ = "`
	schemaJSON := fmt.Sprintf(`{
		"type": "record",
		"name": "Test",
		"fields": [
			{"name": "status", "type": {"type": "enum", "name": "Status", "symbols": [%q]}}
		]
	}`, hostile)

	schema, err := avro.Parse(schemaJSON)
	require.NoError(t, err)
	rec, ok := schema.(*avro.RecordSchema)
	require.True(t, ok)

	g := gen.NewGenerator("something", nil, gen.WithEnums(true))
	g.Parse(rec)

	buf := &bytes.Buffer{}
	require.NoError(t, g.Write(buf))

	assertNoInjectedDecl(t, buf.Bytes())
}
