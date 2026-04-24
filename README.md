# block

Prevent accidental edits. Watch files, block writes, restore on exit.

## Usage

```bash
# Start protecting files listed in config.toml
./block

# Use custom config
./block -c protect.toml
```

Press `Ctrl+C` to stop. All permissions restored automatically.

## Configuration

Create `config.toml`:

```toml
[blocked]
files = [
    "src/main.rs",
    "README.md",
    "secrets/",
]
```

- Files become read-only (444)
- Directories stay accessible (555) — readable, traversable, but protected

## How it Works

Uses **kernel-level immutable bit** (`chattr +i`) — files become completely unchangeable, even to root (without removing the bit first).

1. **Startup** — sets immutable bit on all blocked paths
2. **Runtime** — detects and blocks symlink attacks, re-applies protection if bypassed
3. **Shutdown** — removes immutable bit, restores normal access

### Bypass Protection

The immutable bit prevents all these attacks:
- ❌ `chmod +w && echo … > file` — blocked at kernel level
- ❌ Write temp + `mv` — immutable files cannot be replaced
- ❌ Symlink swap — detected and removed immediately
- ❌ Even root cannot modify without removing the bit first

> [!IMPORTANT]
> **Requires root privileges.** The immutable bit can only be set by root (or with `CAP_LINUX_IMMUTABLE`). Run with `sudo`:
> ```bash
> sudo ./block
> ```

> [!CAUTION]
> **Never block system paths** like `/`, `/usr`, `/bin`, `/etc`.
>
> This app recursively modifies permissions. Blocking `/` would make your entire system unchangeable and require a live USB to recover. Always test with a specific project directory first.

## Build

```bash
cargo build --release
```

Binary at `target/release/block`.

## License

MIT
