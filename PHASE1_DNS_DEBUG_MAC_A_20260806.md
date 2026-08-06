# Phase 1 Debug — DNS Poison Not Reaching Mac A

Context: Gatebreaker running on Mac B over Thunderbolt (`bridge0`), PF
redirect rule is correct (`rdr pass on bridge0 inet proto udp from
192.168.2.2 to any port = 53 -> 127.0.0.1 port 5553`), PF is enabled,
dnsmasq poisoning confirmed. But Mac A still resolves `ocsp.apple.com`
to real Apple IP (`17.253.27.154`) instead of poisoned `192.168.0.0`.

Suspected cause: Mac A's DNS queries are going over WiFi (`en0`) instead
of Thunderbolt (`bridge0`), bypassing the PF redirect entirely.

Run these on **Mac A** to diagnose.

---

## Step 1: Check which DNS server Mac A is using

```bash
scutil --dns | head -20
```

Look at the `nameserver` entries — if they point to a WiFi router DNS
(e.g. `192.168.4.1` or `192.168.5.94`) instead of the Thunderbolt
gateway (`192.168.2.1`), DNS is going over WiFi, not Thunderbolt.

---

## Step 2: Check which interfaces are active

```bash
ifconfig | grep "inet "
```

If both `en0` (WiFi) and `bridge0` (Thunderbolt) have IPs, Mac A has
two active paths to the internet. macOS may prefer WiFi for DNS.

---

## Step 3: Check default route priority

```bash
netstat -rn | grep default
```

If there are two default routes (one via `en0` to WiFi gateway, one via
`bridge0` to `192.168.2.1`), macOS picks the one with lower metric.
WiFi often wins.

---

## Step 4: Trace the actual DNS query path

```bash
dig +trace ocsp.apple.com 2>&1 | head -20
```

This shows which server is actually answering DNS queries.

---

## Step 5: Fix — disable WiFi on Mac A to force all traffic through Thunderbolt

```bash
# Turn off WiFi (DNS will be forced through Thunderbolt bridge)
networksetup -setairportpower en0 off

# Verify only Thunderbolt is active
ifconfig | grep "inet "

# Verify DNS now goes through Thunderbolt gateway
scutil --dns | head -20

# Test — should now show poisoned IP
dig +timeout=5 ocsp.apple.com
```

Expected after disabling WiFi: `dig ocsp.apple.com` returns
`192.168.0.0` (poisoned by Gatebreaker's dnsmasq via PF redirect on
`bridge0`).

---

## Step 6: Re-enable WiFi after testing

```bash
networksetup -setairportpower en0 on
```

---

## Report back

Please share:
1. Output of `scutil --dns | head -20` (before and after Step 5)
2. Output of `ifconfig | grep "inet "` (before and after)
3. Output of `netstat -rn | grep default`
4. Result of `dig +timeout=5 ocsp.apple.com` after disabling WiFi
