# Mac A Debug — LuLu / Network Filtering Investigation

Context: Castiel vs Gatebreaker test campaign (Aug 6, 2026). Gatebreaker's
ARP spoof + DNS poison attack is timing out on Mac A even after fixing a
stale Gateway IP config bug (was `192.168.2.1`, corrected to the real WiFi
gateway `192.168.5.94`). Suspect LuLu's Network Extension may still be
filtering traffic on Mac A independent of the ARP/DNS attack path.

Run these directly on Mac A.

---

## Step 1: Check if LuLu is running

```bash
ps aux | grep -i lulu | grep -v grep
launchctl list | grep -i lulu
systemextensionsctl list | grep -i lulu
```

Look specifically at the `systemextensionsctl list` output — if LuLu's
Network Extension shows `[activated enabled]`, it is actively filtering
traffic regardless of whether the LuLu menu bar app is running or quit.

---

## Step 2: Check current ARP table state (before any LuLu changes)

```bash
arp -a | grep 192.168.5.94
```

Compare this MAC address against Mac B's real MAC (run on Mac B):
```bash
ifconfig en0 | grep ether
```

- If Mac A's ARP entry for `192.168.5.94` matches Mac B's MAC → ARP spoof
  landed correctly, and LuLu (or something else) is the remaining blocker.
- If it shows a different MAC → ARP spoof still isn't landing even with the
  corrected gateway IP; this needs further investigation before touching LuLu.

---

## Step 3: Disable LuLu's Network Extension

Quitting the LuLu app is NOT sufficient — the Network Extension persists
system-wide even with the app closed.

1. Open **System Settings → General → Login Items & Extensions → Network
   Extensions**
2. Find **LuLu**, toggle it **off**
3. Confirm via terminal:
   ```bash
   systemextensionsctl list | grep -i lulu
   ```
   Should no longer show `[activated enabled]` after disabling.

If you want it fully removed (not just disabled) rather than just toggled
off, use LuLu's official uninstaller instead of manually deleting files:
```bash
sudo /Library/LuLu/uninstall.sh 2>/dev/null || echo "check actual install path"
```
(Path may vary — check `/Applications/LuLu.app/Contents/Resources/` if the
above path doesn't exist.)

---

## Step 4: Force-quit the app itself (optional, cosmetic only)

```bash
sudo pkill -9 LuLu
```

This stops the UI/alert prompts but does NOT remove the Network Extension
filtering — Step 3 is the one that actually matters for this test.

---

## Step 5: Re-test after disabling

Once LuLu's Network Extension is confirmed disabled:

```bash
# Clear OCSP cache for a clean state
sudo rm -f /private/var/db/TrustData/valid.sqlite3*

# Test DNS resolution baseline (before restarting Gatebreaker)
dig +timeout=3 ocsp.apple.com
```

Then restart Gatebreaker on Mac B (with the corrected Gateway IP already
in place) and re-check:

```bash
dig +timeout=3 ocsp.apple.com
```

**Expected if LuLu was the blocker**: DNS now resolves to the poisoned IP
(`192.168.0.0`) instead of timing out.

**If it still times out after disabling LuLu**: the issue is not LuLu —
go back to the ARP table check in Step 2 and verify the spoof is actually
landing on Mac A's side.

---

## Report back

Please share:
1. Output of `systemextensionsctl list | grep -i lulu` (before and after Step 3)
2. Output of `arp -a | grep 192.168.5.94` (before and after)
3. Result of the `dig` test after Gatebreaker restart
