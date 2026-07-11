Output docs/assets/etherfence-demo.gif

Set Shell "bash"
Set Width 1280
Set Height 760
Set FontSize 26
Set FontFamily "DejaVu Sans Mono"
Set Framerate 10
Set Theme "Builtin Dark"
Set TypingSpeed 30ms

# Scene 1 — posture discovery
Sleep 500ms
Type "cd demo/workspace"
Enter 1
Sleep 300ms
Type "etherfence setup detect --root ."
Enter 1
Sleep 7s

# Clear and scene 2 — policy enforcement
Ctrl+L
Sleep 300ms
Type "etherfence mcp-policy check --policy project-readonly.toml --request request.json"
Enter 1
Sleep 5s
