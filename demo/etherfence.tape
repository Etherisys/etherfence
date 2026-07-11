# Output controlled by run-demo.sh --output flag

Set Shell "bash"
Set Width 1280
Set Height 760
Set FontSize 26
Set FontFamily "DejaVu Sans Mono"
Set Framerate 10
Set Theme "Builtin Dark"
Set TypingSpeed 30ms

# Scene 1 — EtherFence identity splash
Hide
Type "etherfence"
Enter
Show
Sleep 2s
Ctrl+L
Sleep 300ms

# Scene 2 — Broad posture scan
Type "cd demo/workspace"
Enter 1
Sleep 200ms
Type "etherfence scan --root ."
Enter 1
Sleep 5s

# Scene 3 — MCP setup assessment
Ctrl+L
Sleep 300ms
Type "etherfence setup detect --root ."
Enter 1
Sleep 7s

# Scene 4 — Runtime policy enforcement
Ctrl+L
Sleep 300ms
Type "etherfence mcp-policy check --policy project-readonly.toml --request request.json"
Enter 1
Sleep 5s
