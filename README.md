# Claude Code Kitty Keyboard Patch

Binary patch for Claude Code that fixes shifted punctuation characters (like `@`, `!`, `?`, `#`, etc.) not working in WezTerm and other terminals using the kitty keyboard protocol.

Supports **Windows** (PE), **Linux** (ELF), and **macOS** (Mach-O) binaries.

## The Bug

Since Claude Code 2.1.247, pressing Shift+key combinations that produce punctuation (Shift+2 → `@`, Shift+/ → `?`, etc.) inserts the **unshifted** character instead when the terminal uses kitty keyboard protocol with alternate key reporting.

**Affected terminals**: WezTerm (with `enable_kitty_keyboard = true`)

**Upstream issue**: https://github.com/anthropics/claude-code/issues/90067

## Root Cause

Claude Code requests kitty keyboard flags `5` (which includes flag 4 = report alternate keys). The terminal then sends the physical key codepoint and the shifted key codepoint as a sub-parameter:

```
ESC [ 47:63;130u
       ^  ^  ^
       |  |  modifier (shift + numlock)
       |  shifted key ('?')
       physical key ('/')
```

The decoder regex captures both values, but the code only reads the physical key (group 1) and ignores the shifted key (group 2).

## The Fix

The patch changes the kitty keyboard flags from `5` to `1` in the Bun bytecode string table (and JS source text). Flag `1` = progressive enhancement only (no alternate keys), which makes WezTerm send the actual shifted character directly instead of the physical key + alternate key sub-parameter.

Two locations are patched:
1. **Bytecode string constant** — the NUL-terminated `">5u"` → `">1u"` in the compiled string table
2. **JS source text** — `_mr=Mf(">5u")` → `_mr=Mf(">1u")`

Previous versions of this patch tried to modify the CSI-u parser JS code, but that didn't work because Bun standalone executables use bytecode compilation (`@bun @bytecode`), so text-level JS patches are inert.

## Usage

```
python patch.py
```

This finds the Claude binary at `~/.local/bin/claude`, kills any running Claude processes, creates a backup (`.bak`), and patches the binary in place.

### Revert

Kill Claude processes first, then restore the backup:

```powershell
# Windows
Get-Process -Name "claude*" | Stop-Process -Force
copy "$env:USERPROFILE\.local\bin\claude.exe.bak" "$env:USERPROFILE\.local\bin\claude.exe"
```

```bash
# Linux / macOS
pkill -f claude || true
cp ~/.local/bin/claude.bak ~/.local/bin/claude
```

## Re-patching after updates

Claude Code auto-updates overwrite the binary. Re-run `python patch.py` after each update.
