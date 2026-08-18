# Detection Rules

Elastic SIEM detection rules developed and validated in a home SOC lab.

Every rule here has been tested against real telemetry — the trigger 
was reproduced deliberately and the alert confirmed to fire.

## Environment

| Component | Detail |
|-----------|--------|
| SIEM | Elasticsearch + Kibana 9.5 |
| Collection | Elastic Agent (Fleet-managed) |
| Endpoint telemetry | Sysmon (SwiftOnSecurity config) |
| Endpoints | Windows 11 clients, Windows Server 2022 DC/ADC |

## Rules

| # | Rule | MITRE | Severity | Status |
|---|------|-------|----------|--------|
| 1 | Execution from User-Writable Directory | T1204 | Medium | ✅ Validated |

---

## Rule 1 — Execution from User-Writable Directory

**MITRE:** T1204 — User Execution
**Severity:** Medium (47)
**Interval:** 5m, look-back 1m
**Index:** `logs-*`

### Query
event.code : "1" and
process.executable : (\AppData\ or \Temp\ or \Downloads\) and
not (
process.executable : (\Microsoft\OneDrive\ or \Microsoft\EdgeWebView\ or \WindowsApps\)
and winlog.event_data.Company : "Microsoft Corporation"
)


### Rationale

Malware favours AppData, Temp and Downloads because these paths are 
writable without elevation and are frequently excluded from restrictive 
application-control policies.

### Tuning

The initial query returned three hits, all Microsoft OneDrive components. 
OneDrive installs into AppData by design, so these are expected. They were 
verified legitimate against two independent signals — publisher 
(`Microsoft Corporation`) and parent process (`explorer.exe` and 
`svchost.exe -k netsvcs -p -s Schedule`).

The exclusion requires **both** a known-good path **and** a matching 
publisher. Excluding on path alone would let a payload dropped into the 
OneDrive folder bypass the rule.

### Validation

`notepad.exe` was copied to `Downloads` as `test.exe` and executed. 
The alert fired within one rule interval.

One detail worth noting from the alert: `process.name` showed `test.exe` 
while `process.pe.original_file_name` retained `NOTEPAD.EXE`. The rename 
was visible in telemetry — the same signal that exposes malware 
masquerading under a system process name.

### Known false positives

Portable applications and software updaters may match. Verify publisher, 
parent process and command line before escalating.

---

## About

Cybersecurity undergraduate and SOC analyst candidate, currently in 
Blue Team incident response training.

**Basel Mostafa Ibrahim** · [LinkedIn](https://linkedin.com/in/baselmostafa)
