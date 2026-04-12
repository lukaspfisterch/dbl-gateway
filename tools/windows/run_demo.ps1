docker compose up -d --build

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Start-Sleep -Seconds 2
Start-Process "http://localhost:8010/ui/"
