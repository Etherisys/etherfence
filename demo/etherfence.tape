Output docs/assets/etherfence-demo.gif

Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 16
Set FontFamily "JetBrains Mono"
Set Framerate 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Sleep 700ms
Type "etherfence setup detect --root demo/workspace"
Enter
Sleep 4200ms
Type "etherfence mcp-policy check --policy demo/workspace/project-readonly.toml --request demo/workspace/request.json"
Enter
Sleep 4200ms
