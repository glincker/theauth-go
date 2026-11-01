# Renders .github/demo/mcp-auth.gif. Run from integration/mcp-interop:
#   vhs ../../.github/demo/mcp-auth.tape
Output ../../.github/demo/mcp-auth.gif
Set Shell "bash"
Set FontSize 15
Set Width 1180
Set Height 360
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set WindowBar Colorful

# Warm the build cache off camera so the visible go run starts at once.
Hide
Type "export PS1='$ ' && GOWORK=off go build -o /dev/null ./cmd/demo && clear" Enter
Sleep 10s
Show

Type "# Official Go MCP SDK client vs a theauth-go authorization server" Enter
Sleep 1s
Type "GOWORK=off go run ./cmd/demo" Sleep 600ms Enter
Sleep 10s
