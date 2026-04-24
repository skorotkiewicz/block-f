# block-f

Prevent accidental edits. Works **with or without root**:

- **As root**: Uses kernel-level immutable bit (`chattr +i`) — unbypassable protection
- **As regular user**: Uses read-only permissions — blocks most edits, race-condition vulnerable

> [!CAUTION]
> **Never block system paths** like `/`, `/usr`, `/bin`, `/etc`.
>
> Blocking `/` as root would make your entire system unchangeable. Always test with a specific project directory first.

## Usage

```bash
# Run as user (read-only mode) - basic protection
./block-f

# Run as root (immutable mode) - strongest protection
sudo ./block-f

# Use custom config
./block-f -c protect.toml
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

## Protection Modes

### Root Mode (Immutable Bit)
Uses `chattr +i` — kernel-level protection that blocks:
- All writes (even by root)
- File deletion and renaming
- Permission changes
- Symlink/hardlink attacks
- Atomic replacement attacks

**Recovery**: Only root can remove the immutable bit.

### User Mode (Read-Only)
Uses `chmod 444/555` — user-level protection that:
- Sets files read-only
- Allows reading and directory traversal
- **Vulnerable** to: race conditions, temp+move, symlink swaps

**Recovery**: Original permissions restored on exit.

## Build

```bash
cargo build --release
```

Binary at `target/release/block-f`.

## License

MIT
