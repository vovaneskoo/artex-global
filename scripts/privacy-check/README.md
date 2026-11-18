# Read-only network privacy snapshot

Exit code 0 means the report was generated; it does not mean privacy checks passed. This standard-library CLI reports sanitized Mullvad and Lima metadata for one explicitly named VM. It never starts or stops a VM, changes VPN/firewall settings, reads process environments, or prints raw configuration or credentials. It does not establish that the host or VM is leak-free.

```sh
python3 scripts/privacy-check/privacy_check.py --vm <running-lima-instance>
python3 scripts/privacy-check/privacy_check.py --vm <running-lima-instance> --probe-exit
python3 -m unittest discover -s tests -p 'test_network_privacy.py' -v
go test -count=1 -v ./scripts/privacy-check/fallback
```

The optional probe makes one fixed HTTPS request to `https://am.i.mullvad.net/json` from the selected running VM. It emits an ephemeral keyed digest of the observed address and the endpoint's Mullvad-exit boolean, never the address itself. Resolver configuration is metadata only. IPv6 labels describe the VM snapshot: `absent` means no global address and no default route were observed. Firewall rule and counter summaries are metadata only and never establish that traffic is blocked. The overall leak-free conclusion remains `unproven` in every case.

## Provider-routing integration

The Go tests use real ARTEX/Norma HTTP providers with local httptest endpoints and a synthetic key. They verify primary 402 -> backup delivery, primary success without backup requests, and explicit profile-proxy routing. No database, production profile, or external provider is used. This proves the local provider/pool integration, not the destination of a historical or live ARTEX task.

Runtime profile selection and network routing are separate: an empty per-profile proxy currently means direct transport (HTTP_PROXY/HTTPS_PROXY are ignored by agent/provider.go), while an empty provider BaseURL may select the provider's public default. A relay log records only relay connections. The bench hostname api.venice.ai resolves to guest loopback; a refused bare :443 connection therefore is not a test of direct public Venice egress.

## Snapshot limits

The collector does not modify mission state, VPN, firewall or provider configuration. Optional exit probing makes one explicit benign network request. Missing collectors are reported as incomplete/unavailable. DNS configuration does not attribute the host forwarder or final resolver; IPv6 absence in one snapshot does not prove behavior under future global IPv6 connectivity. Agent tools, goals, budgets and autonomy are unchanged.

Exit probing rejects HTTP redirects instead of following another destination. Firewall fields named listed_packet_counter_sum/listed_byte_counter_sum sum the displayed policy and rule counters; they are not unique traffic totals. A usable exit-probe response can report Mullvad false or unknown; status ok is not a VPN/privacy pass.
