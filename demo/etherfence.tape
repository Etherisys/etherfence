# Output controlled by run-demo.sh --output flag

Set Shell "bash"
Set Width 1280
Set Height 760
Set FontSize 26
Set FontFamily "DejaVu Sans Mono"
Set Framerate 10
Set Theme "Builtin Dark"
Set TypingSpeed 30ms

# Scene 1 — Identity + posture scan
# etherfence scan is a human-output command that naturally prints the real
# colored splash before the scan report. No separate "splash-only" scene.
Sleep 500ms
Type "cd demo/workspace"
Enter 1
Sleep 200ms
Type "etherfence scan --root ."
Enter 1
Sleep 6s

# Scene 2 — MCP setup assessment
Ctrl+L
Sleep 300ms
Type "etherfence setup detect --root ."
Enter 1
Sleep 7s

# Scene 3 — Runtime policy decision preview (multiline command)
Ctrl+L
Sleep 300ms
Type "etherfence mcp-policy check \"
Enter 1
Type "  --policy project-readonly.toml \"
Enter 1
Type "  --request request.json"
Enter 1
Sleep 5s
