# block

Prevent accidental edits. Uses **kernel-level immutable bit** (`chattr +i`) — unbypassable protection that even root can't defeat without removing the bit first.

> [!CAUTION]
> **Never block system paths** like `/`, `/usr`, `/bin`, `/etc`.
>
> Blocking `/` would make your entire system unchangeable and require a live USB to recover. Always test with a specific project directory first.

## Usage

> [!IMPORTANT]
> **Requires root.** The immutable bit can only be set by root:
> ```bash
> sudo ./block
> ```

```bash
# Start protecting files listed in config.toml
sudo ./block

# Use custom config
sudo ./block -c protect.toml
```

> [!NOTE]
> Press `Ctrl+C` to stop. All files restored automatically.

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

## How it Works

1. **Startup** — sets immutable bit on all blocked paths
2. **Runtime** — detects and blocks symlink attacks, re-applies protection if bypassed  
3. **Shutdown** — removes immutable bit, restores full access

### Attack Prevention

The immutable bit blocks **all** bypass attempts:
- ❌ `chmod +w && write` — kernel blocks at lowest level
- ❌ Write temp + `mv` — cannot replace immutable files
- ❌ Symlink attacks — detected and removed instantly
- ❌ Hardlink bypasses — blocked by kernel
- ❌ Root without `CAP_LINUX_IMMUTABLE` — blocked
- ❌ Even `chattr -i` fails without root

## Build

```bash
cargo build --release
```

Binary at `target/release/block`.

## License

MIT
