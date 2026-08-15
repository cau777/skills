# Unified proxy web UI prototype

Throwaway prototype for three variants of the Credentials, Rules, VMs, and
Logs UI, switchable via `?variant=`, on a standalone prototype route.

Run it from the repository root:

```bash
python3 -m http.server 4173 --directory prototypes/web-ui
```

Then open <http://localhost:4173/?variant=A>. Use the floating switcher (or
the left/right arrow keys) to compare:

- `A` — Entity console
- `B` — Policy workspace
- `C` — Activity debugger

Everything is mock data held in browser memory. Reloading resets it.

