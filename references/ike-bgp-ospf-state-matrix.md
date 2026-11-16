# IKEv2, BGP, and OSPF Multi-Vendor State Transition & MTU Reference Matrix

This reference provides exact protocol state machines, RFC error notifications, overhead calculations, and multi-vendor CLI translation patterns for **Cisco IOS-XE/ASA**, **Fortinet FortiGate**, and **MikroTik RouterOS v7**.

---

## 1. IKEv2 RFC 7296 Notify Message Error Codes

| Notify Code | Hex | RFC Name | Common Operational Root Cause | Multi-Vendor Resolution |
| :---: | :---: | :--- | :--- | :--- |
| `14` | `0x000E` | `NO_PROPOSAL_CHOSEN` | Phase 1 or Phase 2 encryption, integrity, PRF, DH group, or PFS mismatch. | Align exact proposals. Note: In IKEv2, `AES-GCM` includes built-in integrity/AEAD—do **not** configure a separate SHA hash alongside `PRF-SHA256`. |
| `17` | `0x0011` | `INVALID_KE_PAYLOAD` | Initiator guessed the wrong Diffie-Hellman (DH) group in `IKE_SA_INIT`. | Set a single matching DH group (e.g., `Group 14` 2048-bit MODP or `Group 19/20` ECP) at the top of the proposal list on both peers. |
| `24` | `0x0018` | `AUTHENTICATION_FAILED` | Pre-Shared Key (PSK) mismatch, or `Local/Remote ID` mismatch when one peer is behind NAT (sending RFC1918 IP as ID while remote expects public WAN IP). | Explicitly set `Local ID` / `Peer ID` to FQDN or match the NAT-translated vs. internal IP explicitly on the responder. |
| `34` | `0x0022` | `CHILD_SA_NOT_FOUND` | Out-of-sync SPI tables during simultaneous Phase 2 rekeying. | Disable kilobyte (`lifesize`) rekeying; use time-based rekeying only (e.g., `28800s` Phase 1, `3600s` Phase 2). |
| `38` | `0x0026` | `TS_UNACCEPTABLE` | Traffic Selector (Proxy-ID) mismatch in `IKE_AUTH` or `CREATE_CHILD_SA`. | Convert to Route-Based VTI (`0.0.0.0/0` to `0.0.0.0/0`) or ensure identical subnet masks on both ends. |

---

## 2. IPsec Encapsulation Overhead & Safe MTU / TCP MSS Values

When running BGP or OSPF inside an IPsec tunnel (VTI, GRE-over-IPsec, or XFRM interface), outer ESP/UDP headers reduce the maximum payload size before fragmentation occurs:

| Encapsulation Mode | Cipher Suite | NAT-T (UDP 4500) | Total Header Overhead | Max Safe Tunnel IP MTU (1500 WAN) | Max Safe TCP MSS (`MTU - 40`) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Native IPsec VTI (Tunnel Mode)** | `AES-256-GCM` (16B ICV) | No (ESP 50) | `54–62 bytes` | **`1400 bytes`** | **`1360 bytes`** |
| **Native IPsec VTI + NAT-T** | `AES-256-GCM` (16B ICV) | Yes (`+8B UDP`) | `62–70 bytes` | **`1400 bytes`** | **`1360 bytes`** |
| **Native IPsec VTI + NAT-T** | `AES-256-CBC + SHA256` | Yes (`+8B UDP`) | `78–94 bytes` | **`1380 bytes`** | **`1340 bytes`** |
| **GRE over IPsec + NAT-T** | `AES-256-CBC + SHA256` | Yes (`+24B GRE`) | `102–118 bytes` | **`1360 bytes`** | **`1320 bytes`** |
| **PPPoE WAN (`1492` Base MTU) + GRE/IPsec** | `AES-256-CBC + SHA256` | Yes (`-8B PPPoE`) | `110–126 bytes` | **`1340 bytes`** | **`1300 bytes`** |

> **Golden Rule for Enterprise VPNs:** Standardize all IPsec VTI / Tunnel interfaces across Cisco, FortiGate, and MikroTik to **`MTU = 1400`** and **`TCP MSS = 1360`** (or **`MTU = 1360` / `MSS = 1320`** if GRE or PPPoE is in the path).

---

## 3. OSPF Neighbor State Machine Failure Diagnosis

| Stuck State | Symptom in Logs | Root Cause | Fix (Cisco / FortiGate / MikroTik) |
| :--- | :--- | :--- | :--- |
| **`DOWN` / `ATTEMPT`** | Zero OSPF Hellos received from remote peer. | Multicast `224.0.0.5` blocked across point-to-point/NBMA tunnel, or Phase 2 SA only permits unicast traffic. | Configure OSPF interface network type to `point-to-point` on both peers and ensure tunnel interface is in the OSPF network statement. |
| **`INIT` (One-Way)** | Peer A sees Peer B in `INIT`, Peer B sees nothing. | Asymmetric IPsec SA (inbound SPI active, outbound SPI dead) or local firewall input chain blocking IP Protocol `89` (OSPF). | Allow IP protocol `89` (`ospf`) on the tunnel interface input firewall rule (especially on MikroTik `/ip firewall filter` chain=`input`). |
| **`2-WAY` (Dropping on PtP)** | Adjacency never progresses to `EXSTART`. | Both routers set to `priority 0` on a Broadcast network type segment. | Change OSPF network type from `broadcast` to `point-to-point` on VPN tunnel interfaces (`ip ospf network point-to-point`). |
| **`EXSTART` / `EXCHANGE`** | `OSPF-4-EXTER_MTU` or `NBRCHG: ExStart -> Down: Too many retransmissions`. | Interface IP MTU mismatch encoded in the OSPF Database Description (DBD) header, OR large DBD packets (>1400 bytes) dropped silently by IPsec DF-bit blackhole. | Set identical `MTU = 1400` on both tunnel interfaces (`ip mtu 1400` on Cisco, `set mtu 1400` on FortiGate, `mtu=1400` on MikroTik). |

---

## 4. BGP Finite State Machine (FSM) Notification Error Codes (RFC 4271)

| Error Code | Subcode | Name | Typical Cause Over IPsec VPN |
| :---: | :---: | :--- | :--- |
| **`1`** | `1–3` | `Message Header Error` | Corrupt packet or bad synchronization over lossy WAN link. |
| **`2`** | `2` | `OPEN Message: Bad Peer AS` | Local router configured `remote-as 65001`, but remote router sent `My AS: 65002`. |
| **`2`** | `3` | `OPEN Message: Bad BGP Identifier` | Duplicate Router-ID (`0.0.0.0` or identical loopback IP configured on both routers). |
| **`4`** | `0` | **`Hold Timer Expired`** | Keepalive/Update packets failed to arrive within Hold Time (`180s` default). Almost always caused by: **(1)** IPsec Phase 2 SA rekey drop, **(2)** Full BGP table `UPDATE` packet exceeding tunnel Path MTU (1500B DF-bit dropped while 60B Keepalives pass), or **(3)** Recursive route flap (`%TUN-5-RECURDOWN`). |
| **`6`** | `2 / 4` | `Cease: Administratively Reset` | Peer manual reset (`clear ip bgp`) or BGP Max-Prefix limit exceeded. |

---

## 5. Multi-Vendor CLI Equivalents for Tunnel MTU, MSS & Routing Safety

### Cisco IOS-XE (Route-Based VTI)
```ios
interface Tunnel10
 ip address 169.254.10.1 255.255.255.252
 ip mtu 1400
 ip tcp adjust-mss 1360
 ip ospf network point-to-point
 tunnel mode ipsec ipv4
! Prevent Recursive Routing Loop:
ip route <REMOTE_PEER_PUBLIC_WAN_IP> 255.255.255.255 <LOCAL_ISP_GATEWAY_IP>
```

### Fortinet FortiGate (FortiOS 7.x)
```fortios
config system interface
    edit "vpn-to-branch"
        set ip 169.254.10.1 255.255.255.255
        set remote-ip 169.254.10.2 255.255.255.252
        set mtu-override enable
        set mtu 1400
        set tcp-mss 1360
    next
end
config router ospf
    config ospf-interface
        edit "vpn-ospf"
            set interface "vpn-to-branch"
            set network-type point-to-point
            set mtu-ignore disable
        next
    end
end
```

### MikroTik RouterOS v7
```routeros
# Clamp TCP MSS across the IPsec tunnel
/ip firewall mangle
add chain=forward ipsec-policy=out,ipsec protocol=tcp tcp-flags=syn action=change-mss new-mss=1360 passthrough=yes
add chain=forward ipsec-policy=in,ipsec protocol=tcp tcp-flags=syn action=change-mss new-mss=1360 passthrough=yes

# Pin remote VPN peer public IP to physical WAN gateway to prevent BGP/OSPF recursive collapse
/ip route
add dst-address=<REMOTE_PEER_PUBLIC_WAN_IP>/32 gateway=<LOCAL_ISP_GATEWAY_IP> distance=1 comment="Pin VPN Peer Underlay"
```

---

## 6. BGP Cease Subcodes (RFC 4486)

A Cease notification (code `6`) is never a transport failure. Something decided to end the session.
The subcode names what.

| Subcode | Name | What it actually means over a VPN |
| :---: | :--- | :--- |
| `1` | Maximum Number of Prefixes Reached | A configured limit fired. It will fire again on every reconnect until the limit or the advertisement changes. Raising the limit without asking why the peer's table grew means you now carry that growth. |
| `2` | Administrative Shutdown | Someone issued a shutdown. Correlate the timestamp against change records before blaming the network. |
| `3` | Peer De-configured | The neighbour statement was removed at the far end. |
| `4` | Administrative Reset | A `clear ip bgp` or equivalent. Often a script, often on a schedule - check periodicity. |
| `5` | Connection Rejected | The far end refused the inbound TCP connection, usually a filter or an ACL. |
| `6` | Other Configuration Change | A policy or capability change forced a reset. |
| `7` | Connection Collision Resolution | Both ends opened simultaneously and one was dropped by the collision rule. Normal once; repeated means both ends are retrying in lockstep. |
| `8` | Out of Resources | The device is under memory or CPU pressure. Fix the device, not the session. |

RFC 8203 and RFC 9003 add an operator-supplied shutdown message to subcodes `2` and `4`. If the
peer sends one, it is the most useful line in the entire log - read it before anything else.

---

## 7. Liveness Timer Coordination (DPD, Hold Time, Dead Interval, BFD)

Failover is only deterministic when the layers detect loss in a known order. When IPsec DPD is
slower than the routing protocol's hold timer, the routing protocol tears down a session whose
tunnel is still nominally up, and the route withdraws before the tunnel reconverges.

| Layer | Mechanism | Typical default | Suggested coordinated value |
| :--- | :--- | :---: | :---: |
| Forwarding | BFD (RFC 5880) | 300 ms x 3 | `300 ms x 3` - fastest, detects first |
| IPsec | DPD / liveness (RFC 3706, RFC 7296 s.10) | 30 s, 5 retries | `10 s x 3` |
| BGP | Hold time (RFC 4271) | 180 s | `30 s` (keepalive `10 s`) |
| OSPF | Dead interval (RFC 2328) | 40 s | `40 s` (hello `10 s`) |

Two rules:

1. **Detection must get slower as you go up the stack**, so the lower layer reports the loss and
   the upper layer reacts to the report rather than racing it.
2. **Shortening a timer does not repair a path.** It makes the flap detectable sooner. If the
   underlying loss is not fixed, shorter timers simply produce a faster flap and a noisier log.

---

## 8. On the "SA lifetime mismatch causes drops" claim

This is repeated widely and is not straightforwardly true, so the correlator reports it as a
hypothesis to test rather than a finding.

What the standards say: RFC 7296 section 2.8 makes rekeying unilateral. Each peer rekeys on its own
schedule, and there is no requirement that the two lifetimes agree. A peer that receives traffic on
an SA it did not initiate the rekey for is expected to handle it.

What breaks in practice, and why it is usually misattributed:

- **Kilobyte-based (`lifesize` / `lifebytes`) rekeying.** Two peers almost never count the same
  bytes, so volume rekeys fire at unpredictable, drifting times. This is the single most common
  real cause of a "lifetime mismatch" flap, and disabling it is uncontroversial.
- **Simultaneous rekey collisions.** When both peers rekey within the same window, older stacks
  could delete both SAs. RFC 7296 defines the resolution; implementations vary in how well they
  follow it. `CHILD_SA_NOT_FOUND` and invalid-SPI messages are the fingerprint.
- **Policy-based peers with multiple child SAs.** Narrow traffic selectors multiply the number of
  SAs, and so the number of rekey events, and so the chance of a collision.

The discriminating test is in the report: change one peer's lifetime to a clearly different value
and see whether the drop moves to the new interval. If it stays where it was, the lifetime was
never the cause.
