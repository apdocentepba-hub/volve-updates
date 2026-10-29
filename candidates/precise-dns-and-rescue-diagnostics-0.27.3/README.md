# VOLVÉ 0.27.3 — diagnóstico preciso (29/10/2026)

Beta de diagnóstico: no reemplaza el motor residente 0.27.0 ni modifica DNS, ACL o tareas.

Captura 0.27.2: el motor bloquea y resuelve bien IPv4/IPv6, pero el adaptador devuelve respuesta no reconocida y el rescate independiente no es verificable. El catálogo Full tenía 1,7 horas desde su última modificación.

Cambios 0.27.3: stdout/stderr PowerShell separados, marcador de comprobación estricto con validación de UTF-8/UTF-16 y timeout; motivos acotados de discrepancias en tareas SYSTEM, sin hacer cambios ni declarar verificado algo no comprobado.

Tests: go test ./... y go test -race ./... OK, go vet Windows x64 OK, compilación Windows x64 GUI PE32+ OK; ZIP comprobado.

SHA-256 EXE: e27221c9c01cc5f1a118b50e40b1ddc261169c7bf70ce1a5ff7d0ee31ef7cc42

EXE: https://drive.google.com/file/d/1Bx10GD7jiJLPj8hRhPdWUe4nTBGcB3Fz/view
ZIP: https://drive.google.com/file/d/1rIO6GQBtTd6m1K6kMMYTti5iP3b8R32n/view

No probado aún en el Windows del usuario. No se demostró rescate real ante falla ni se debe activar stable.