# Mac A Diagnostic Report — Phase 1 DNS Debug

**Date**: Aug 6, 2026 15:44 EDT  
**Run on**: Mac A (`hanas-MacBook-Pro.local`, macOS 26.4.1, M1)  
**Thunderbolt IP**: `192.168.2.2` on `bridge0`  
**Gateway (Mac B)**: `192.168.2.1`

---

## Summary

Mac A is correctly sending DNS queries through the Thunderbolt bridge to Mac B (`192.168.2.1:53`), but Mac B is returning **real Apple IPs** instead of poisoned ones (`192.168.0.0`). The issue appears to be on Mac B's side — Gatebreaker's PF redirect or dnsmasq is not intercepting the queries.

---

## LuLu Status

| Check | Result |
|-------|--------|
| LuLu process | Not running |
| `launchctl list` | No LuLu entries |
| `systemextensionsctl list` | `com.objective-see.lulu.extension (4.3.2/4.3.2) [activated disabled]` |

**Conclusion**: LuLu Network Extension is **disabled** — not filtering traffic. ✅

---

## ARP Table

```
? (192.168.2.1) at 36:f5:9:5c:43:40 on bridge0 ifscope [bridge]
```

**Note**: Need Mac B's `ifconfig en0 | grep ether` (or `ifconfig bridge0 | grep ether`) to confirm whether this MAC matches Mac B. If Gatebreaker is ARP spoofing, this should show Mac B's spoofed MAC.

---

## Network Interfaces

```
lo0:   inet 127.0.0.1 netmask 0xff000000
bridge0: inet 192.168.2.2 netmask 0xffffff00 broadcast 192.168.2.255
en0:   (no IP — WiFi is OFF)
```

- WiFi (`en0`) is **off** — all traffic forced through Thunderbolt ✅
- Only active path is `bridge0` → `192.168.2.1` ✅

---

## DNS Configuration

```
resolver #1
  nameserver[0] : 192.168.2.1
  flags    : Request A records
  reach    : 0x00020002 (Reachable, Directly Reachable Address)
```

- System DNS is set to `192.168.2.1` (Thunderbolt gateway / Mac B) ✅
- No WiFi DNS servers configured ✅

---

## Default Route

```
default  192.168.2.1  UGScg  bridge0
```

- Single default route via `bridge0` → `192.168.2.1` ✅
- No competing WiFi route ✅

---

## DNS Test Results

### Test 1: `dig +timeout=5 ocsp.apple.com`
```
;; ANSWER SECTION:
ocsp.apple.com.         606     IN      CNAME   ocsp-a.g.aaplimg.com.
ocsp-a.g.aaplimg.com.   9       IN      A       17.253.27.152
ocsp-a.g.aaplimg.com.   9       IN      A       17.253.27.144

;; SERVER: 192.168.2.1#53(192.168.2.1)
;; Query time: 5 msec
```

**Result**: Resolved to **real Apple IPs** (not poisoned).  
**Expected**: `192.168.0.0` (poisoned by Gatebreaker's dnsmasq).  
**DNS server**: `192.168.2.1` (correct — going through Thunderbolt to Mac B).

### Test 2: `dig +trace ocsp.apple.com`
```
.  4502  IN  NS  a.root-servers.net.
...
;; Received 239 bytes from 192.168.2.1#53(192.168.2.1) in 41 ms
;; Received 468 bytes from 198.41.0.4#53(a.root-servers.net) in 28 ms
```

**Result**: Trace shows queries going to `192.168.2.1` first, then resolving normally via root servers. Gatebreaker is not intercepting.

---

## Castiel / PF Cleanup

All Castiel components were stopped and cleaned before testing:

| Component | Status |
|-----------|--------|
| Castiel daemon | Stopped (kill switch `stop` command) |
| Socat forwarder (port 53→5300) | Stopped |
| Castiel PF anchor | Removed |
| PF firewall | Disabled |
| System DNS | Restored (set to `192.168.2.1` via Thunderbolt) |

---

## Diagnosis

**Mac A side is clean and correctly configured:**
- ✅ WiFi off — only Thunderbolt path active
- ✅ DNS pointing to `192.168.2.1` (Mac B)
- ✅ LuLu Network Extension disabled
- ✅ Castiel/socat/PF all stopped
- ✅ Default route via `bridge0` only

**The problem is on Mac B's side.** Mac A is sending DNS queries to `192.168.2.1:53` as expected, but Mac B is resolving them normally instead of returning poisoned responses. Possible causes:

1. **Gatebreaker's PF redirect on `bridge0` is not active or misconfigured** — the `rdr pass on bridge0` rule may not be loaded or the interface name may differ
2. **dnsmasq is not running or not listening on port 5553** — the redirect target may be unreachable
3. **Mac B's PF is not enabled** — `pfctl -s info` should show "Enabled"
4. **The PF redirect rule source IP doesn't match** — rule specifies `from 192.168.2.2` but Mac A's IP may have changed

### Recommended checks on Mac B:

```bash
# Check PF status
sudo pfctl -s info

# Check PF redirect rules on bridge0
sudo pfctl -a gatebreaker -s nat 2>/dev/null || sudo pfctl -s nat 2>/dev/null

# Check dnsmasq is running
ps aux | grep dnsmasq

# Check dnsmasq is listening on 5553
sudo lsof -i :5553

# Check bridge0 interface and IP
ifconfig bridge0

# Check Mac B's MAC address for ARP comparison
ifconfig bridge0 | grep ether
```

---

## Report Back From Mac B

Please share:
1. Output of `sudo pfctl -s info` (is PF enabled?)
2. Output of `sudo pfctl -s nat` or `sudo pfctl -a gatebreaker -s nat` (redirect rules)
3. Output of `ps aux | grep dnsmasq` (is dnsmasq running?)
4. Output of `sudo lsof -i :5553` (is anything listening on the redirect port?)
5. Output of `ifconfig bridge0` (interface IP and MAC)
