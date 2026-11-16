# Multi-Vendor IPsec VPN & BGP/OSPF Flap Root Cause Analysis Report

**Incident / Ticket ID:** `{{INCIDENT_ID}}`
**Date & Time Analyzed:** `{{ANALYSIS_TIMESTAMP}}`
**Peer A (HQ / Hub):** `{{PEER_A_HOSTNAME}}` (`{{PEER_A_VENDOR}}` — Public IP: `{{PEER_A_WAN_IP}}`)
**Peer B (Branch / Spoke):** `{{PEER_B_HOSTNAME}}` (`{{PEER_B_VENDOR}}` — Public IP: `{{PEER_B_WAN_IP}}`)

---

## 1. Executive Root Cause Verdict

* **Primary Failure Layer:** `{{FAILURE_LAYER}}` *(e.g., IKEv2 Phase 2 Rekey / Tunnel Path MTU / OSPF ExStart / BGP Recursive Loop)*
* **Root Cause Summary:** `{{ROOT_CAUSE_SUMMARY}}`
* **Clock Offset (`Delta_T`) Between Peers:** `{{CLOCK_OFFSET}}` *(e.g., Peer B NTP is trailing Peer A by +3.4 seconds)*

---

## 2. Synchronized Cross-Peer Event Timeline

| Normalized UTC Time | Peer | Layer | Event / Notify Code | Sanitized Log Evidence | Diagnostic Interpretation |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `{{TIME_1}}` | Peer A | `{{LAYER_1}}` | `{{CODE_1}}` | `{{LOG_1}}` | `{{INTERP_1}}` |
| `{{TIME_2}}` | Peer B | `{{LAYER_2}}` | `{{CODE_2}}` | `{{LOG_2}}` | `{{INTERP_2}}` |
| `{{TIME_3}}` | Peer A | `{{LAYER_3}}` | `{{CODE_3}}` | `{{LOG_3}}` | `{{INTERP_3}}` |
| `{{TIME_4}}` | Peer B | `{{LAYER_4}}` | `{{CODE_4}}` | `{{LOG_4}}` | `{{INTERP_4}}` |

---

## 3. Side-by-Side Peer Parameter Audit Matrix

| Parameter | Peer A (`{{PEER_A_VENDOR}}`) Current | Peer B (`{{PEER_B_VENDOR}}`) Current | Conflict Status | Target Aligned Standard |
| :--- | :--- | :--- | :---: | :--- |
| **IKE Version & Mode** | `{{PA_IKE_VER}}` | `{{PB_IKE_VER}}` | `{{STATUS_IKE}}` | `IKEv2` |
| **Phase 1 Proposal (Enc/PRF/DH)** | `{{PA_P1_PROP}}` | `{{PB_P1_PROP}}` | `{{STATUS_P1}}` | `AES-256-GCM / PRF-SHA256 / DH14` |
| **Phase 1 Lifetime / DPD** | `{{PA_P1_LIFE}}` | `{{PB_P1_LIFE}}` | `{{STATUS_DPD}}` | `28800s / DPD On-Demand 10sx3` |
| **Phase 2 Proposal & PFS** | `{{PA_P2_PROP}}` | `{{PB_P2_PROP}}` | `{{STATUS_P2}}` | `AES-256-GCM / PFS Group 14` |
| **Phase 2 Lifetime (Sec / KB)** | `{{PA_P2_LIFE}}` | `{{PB_P2_LIFE}}` | `{{STATUS_P2_LIFE}}` | `3600s / Lifesize KB Disabled` |
| **Traffic Selectors (Proxy-ID)** | `{{PA_TS}}` | `{{PB_TS}}` | `{{STATUS_TS}}` | `0.0.0.0/0 <-> 0.0.0.0/0 (VTI)` |
| **Tunnel IP MTU / TCP MSS** | `{{PA_MTU}}` | `{{PB_MTU}}` | `{{STATUS_MTU}}` | `MTU 1400 / TCP MSS 1360` |
| **BGP / OSPF Timers & Network** | `{{PA_ROUTING}}` | `{{PB_ROUTING}}` | `{{STATUS_ROUTING}}` | `PtP / Keepalive 10s, Hold 30s` |

---

## 4. Matched Vendor CLI Remediation Plan

> [!IMPORTANT]
> **Remote Lockout Protection:** Before applying the commands below on the remote branch appliance (`{{PEER_B_HOSTNAME}}`), enable auto-rollback / Safe Mode (`configure terminal revert timer 10` on Cisco, `cfg-save revert` on FortiGate, or `Ctrl+X` Safe Mode on MikroTik).

### Peer A (`{{PEER_A_HOSTNAME}}` — `{{PEER_A_VENDOR}}`)
```text
{{PEER_A_REMEDIATION_CLI}}
```

### Peer B (`{{PEER_B_HOSTNAME}}` — `{{PEER_B_VENDOR}}`)
```text
{{PEER_B_REMEDIATION_CLI}}
```

---

## 5. Post-Change Verification & Rollback Commands

### Verification Checklist
1. **Confirm Phase 1 & Phase 2 SAs are Installed with Zero Rekey Drops:**
   ```text
   {{VERIFY_IPSEC_CMD}}
   ```
2. **Verify Path MTU with Unfragmented (`DF-bit`) 1372-byte ICMP Payload (`1372 + 28 = 1400 MTU`):**
   ```text
   {{VERIFY_MTU_PING_CMD}}
   ```
3. **Verify BGP `Established` or OSPF `FULL` State:**
   ```text
   {{VERIFY_ROUTING_CMD}}
   ```

### Emergency Rollback Commands
```text
# Peer A Rollback:
{{PEER_A_ROLLBACK_CLI}}

# Peer B Rollback:
{{PEER_B_ROLLBACK_CLI}}
```
