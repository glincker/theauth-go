module github.com/glincker/theauth-go/examples/mcp-server

go 1.25.0

require (
	github.com/glincker/theauth-go/mcpresource v0.0.0
	github.com/go-chi/chi/v5 v5.3.1
)

replace github.com/glincker/theauth-go/mcpresource => ../../mcpresource
