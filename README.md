# LuaGuard v5

Roblox-focused static security scanner.

V5 raises the maximum size of each executable remote Lua source to **10 MB**, with a **25 MB total executable-chain limit** to protect the public server from oversized/malicious payloads.

It follows executable `loadstring/load + game:HttpGet` chains, while ordinary non-executed `HttpGet` references do not make the scan incomplete. JSON API errors, HTML responses, failed executable fetches, and chain/depth-limit failures remain unverified rather than falsely green.

LuaGuard downloads code as text for static inspection and never executes it.

## Deploy
Replace the existing GitHub repo files with these V5 files and commit to `main`. Render should automatically redeploy.
