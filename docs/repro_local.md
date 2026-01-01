# Local repro

## Setup

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1

pip install -e D:\DEV\projects\dbl-ingress
pip install -e D:\DEV\projects\dbl-policy
pip install -e D:\DEV\projects\dbl-main
pip install -e D:\DEV\projects\kl-kernel-logic-dev
pip install -e D:\DEV\projects\dbl-reference
pip install -e .
```

## Run gateway

```powershell
$env:DBL_GATEWAY_DB=".\data\trail.sqlite"
$env:DBL_GATEWAY_POLICY_MODULE="policy_stub"
$env:DBL_GATEWAY_POLICY_OBJECT="policy"

dbl-gateway serve --db $env:DBL_GATEWAY_DB --host 127.0.0.1 --port 8010
```

## Probe

```powershell
Invoke-WebRequest http://127.0.0.1:8010/healthz
Invoke-WebRequest http://127.0.0.1:8010/capabilities
```

## Append INTENT

```powershell
Invoke-WebRequest http://127.0.0.1:8010/ingress/intent -Method Post -ContentType "application/json" -Body @'
{
  "interface_version": 1,
  "correlation_id": "c-1",
  "payload": {
    "stream_id": "default",
    "lane": "user_chat",
    "actor": "user",
    "intent_type": "chat.message",
    "payload": { "message": "hello" }
  }
}
'@
```

## Tail

```powershell
Invoke-WebRequest "http://127.0.0.1:8010/tail?stream_id=default&since=0"
```
