param(
  [string]$ProjectId = "project-b2fcff48-a0ca-4867-995",
  [switch]$PopulateFromEnv
)

$ErrorActionPreference = "Stop"

$Secrets = @(
  "JWT_SECRET",
  "CONTA_AZUL_CLIENT_SECRET",
  "CONTA_AZUL_ACCESS_TOKEN",
  "CONTA_AZUL_REFRESH_TOKEN",
  "DATABASE_URL",
  "SIGNATURE_SECRET",
  "EVENT_WEBHOOK_SECRET",
  "REDIS_URL",
  "COBLI_API_TOKEN"
)

Write-Host "Configurando projeto: $ProjectId"
gcloud config set project $ProjectId | Out-Null

foreach ($Secret in $Secrets) {
  $exists = $false
  try {
    gcloud secrets describe $Secret --project=$ProjectId | Out-Null
    $exists = $true
  } catch {
    $exists = $false
  }

  if (-not $exists) {
    Write-Host "Criando secret: $Secret"
    gcloud secrets create $Secret --replication-policy=automatic --project=$ProjectId | Out-Null
  } else {
    Write-Host "Secret ja existe: $Secret"
  }
}

$ProjectNumber = gcloud projects describe $ProjectId --format="value(projectNumber)"
$ServiceAccounts = @(
  "${ProjectId}@appspot.gserviceaccount.com",
  "${ProjectNumber}-compute@developer.gserviceaccount.com"
)

foreach ($Secret in $Secrets) {
  foreach ($ServiceAccount in $ServiceAccounts) {
    Write-Host "Aplicando acesso secretAccessor em $Secret para $ServiceAccount"
    gcloud secrets add-iam-policy-binding $Secret `
      --project=$ProjectId `
      --member="serviceAccount:$ServiceAccount" `
      --role="roles/secretmanager.secretAccessor" | Out-Null
  }
}

if ($PopulateFromEnv) {
  foreach ($Secret in $Secrets) {
    $value = [Environment]::GetEnvironmentVariable($Secret)
    if ([string]::IsNullOrWhiteSpace($value)) {
      Write-Host "Sem valor no env para $Secret (skip)."
      continue
    }
    Write-Host "Adicionando nova versao para $Secret a partir do env."
    $value | gcloud secrets versions add $Secret --project=$ProjectId --data-file=- | Out-Null
  }
}

Write-Host "Setup concluido. Agora adicione as versoes dos segredos com:"
Write-Host "gcloud secrets versions add <SECRET_NAME> --data-file=-"
