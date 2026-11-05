//go:build windows

package main

// Regression guard for the REAL rebuilt public Centro, not a mock entrypoint.
// An admin pressing --uninstall must not remove any browser policy, hosts
// state or catalog. Emergency DNS restoration remains deliberately callable.
import (
    "go/ast"
    "go/parser"
    "go/token"
    "path/filepath"
    "runtime"
    "strconv"
    "strings"
    "testing"
)

func TestPublicCentroUninstallerNeverDispatched(t *testing.T) {
    _, file, _, ok := runtime.Caller(0)
    if !ok { t.Fatal("could not locate source under test") }
    f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(filepath.Dir(file), "main_windows.go"), nil, 0)
    if err != nil { t.Fatal(err) }
    var mainFn *ast.FuncDecl
    for _, decl := range f.Decls {
        if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "main" {
            mainFn=fn;break
        }
    }
    if mainFn==nil { t.Fatal("public Centro main entrypoint missing") }
    foundEmergencyRestore:=false
    foundInstall:=false
    ast.Inspect(mainFn.Body, func(n ast.Node) bool {
        switch v:=n.(type) {
        case *ast.CallExpr:
            if id,ok:=v.Fun.(*ast.Ident);ok && id.Name=="uninstall" {
                t.Error("public Centro main still calls uninstaller")
            }
        case *ast.BasicLit:
            if v.Kind!=token.STRING {break}
            literal,err:=strconv.Unquote(v.Value);if err!=nil{t.Error(err);break}
            if strings.Contains(literal,"--uninstall") || strings.Contains(literal,"--uninstall-ui") {
                t.Error("public Centro entrypoint still advertises/references removal flag")
            }
            if strings.Contains(literal,"--dns-restore") {foundEmergencyRestore=true}
            if literal=="--install" {foundInstall=true}
        }
        return true
    })
    if !foundEmergencyRestore {t.Error("emergency DNS restoration was removed") }
    if !foundInstall {t.Error("existing installation branch was removed") }
}
