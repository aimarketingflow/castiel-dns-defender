# Mac A Setup — Castiel Installation

Run these directly on Mac A (not via remote SSH from Mac B). Copy/paste each
block into Terminal on Mac A in order.

Current Mac A network info (as of Aug 6, 2026):
- Hostname: `hanas-MacBook-Pro.local`
- macOS: 26.4.1 (M1)
- WiFi IP: `192.168.5.95` (Thunderbolt bridge not yet connected — connect the
  cable before Phase 1 of the actual test, not needed for this setup step)

---

## Step 1: Install Homebrew

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Follow the on-screen instructions at the end to add brew to your PATH
(usually involves adding a line to `~/.zprofile` and running `eval` — the
installer will print the exact commands for your shell).

Verify:
```bash
brew --version
```

---

## Step 2: Install Go

```bash
brew install go
```

Verify:
```bash
go version
```

---

## Step 3: Get Castiel source

**Option A — copy from Mac B via SCP** (run this from Mac B, not Mac A):
```bash
scp -r /Users/meep/Documents/DNSAttackDefender akidob0t@192.168.5.95:/tmp/castiel-src
```

**Option B — clone from GitHub** (run this on Mac A):
```bash
git clone https://github.com/aimarketingflow/castiel-dns-defender.git /tmp/castiel-src
```

---

## Step 4: Build Castiel

```bash
cd /tmp/castiel-src
go build -o castiel .
```

---

## Step 5: Install as launch daemon

```bash
sudo make install
launchctl list | grep castiel   # should show it running
```

If there's no `make install` target, check the README in `/tmp/castiel-src`
for the correct install command — flag this back if `make install` fails so
we can adjust.

---

## Step 6: Verify Castiel is working

```bash
# Check PF redirect is active
sudo pfctl -a castiel -s rules 2>/dev/null

# Check DNS resolution still works
dig ocsp.apple.com

# Check Castiel metrics endpoint
curl -s http://127.0.0.1:9090/metrics | head -20

# Check alert log exists
ls -la /tmp/castiel-src/logs/castiel_alerts.jsonl

# Run built-in test suite
cd /tmp/castiel-src
./test-castiel.sh --quick
```

---

## Step 7: Verify Gatekeeper baseline (pre-test sanity check)

```bash
spctl -a -vv /Applications/SomeApp.app
```

Should show normal enforcement (accepted for valid apps, rejected for any
revoked-cert test app) — confirms no lingering cache/state issues from
earlier campaigns before we start Phase 1.

---

## Step 8: Pre-test sysdiagnose

```bash
sudo sysdiagnose -u -A castiel_vs_gatebreaker_pre
```

---

## When done

Report back here (or just tell me in chat) with the output of:
```bash
launchctl list | grep castiel
go version
brew --version
```

so I can confirm everything's ready before we move to Phase 1 (which needs
the Thunderbolt bridge connected — plug that in when you're ready to
actually start the attack test, not before).
