param(
  [string]$ProjectId = "project-b2fcff48-a0ca-4867-995",
  [string]$ServiceName = "default",
  [string]$NotificationChannel = ""
)

$ErrorActionPreference = "Stop"

function Ensure-Project {
  gcloud config set project $ProjectId | Out-Null
}

function Ensure-LogMetric {
  param(
    [string]$MetricName,
    [string]$Description,
    [string]$Filter
  )
  $exists = $false
  try {
    gcloud logging metrics describe $MetricName --project=$ProjectId | Out-Null
    $exists = $true
  } catch {
    $exists = $false
  }
  if (-not $exists) {
    Write-Host "Criando log-based metric: $MetricName"
    gcloud logging metrics create $MetricName `
      --project=$ProjectId `
      --description="$Description" `
      --log-filter="$Filter" | Out-Null
  } else {
    Write-Host "Log-based metric ja existe: $MetricName"
  }
}

function Upsert-Policy {
  param(
    [string]$PolicyFile
  )
  $displayName = (Get-Content $PolicyFile | ConvertFrom-Json).displayName
  $existing = gcloud alpha monitoring policies list --project=$ProjectId --format="value(name,displayName)" `
    | Where-Object { $_ -match [regex]::Escape($displayName) } `
    | Select-Object -First 1

  if ($existing) {
    $name = ($existing -split '\s+')[0]
    Write-Host "Atualizando policy: $displayName"
    gcloud alpha monitoring policies update $name --project=$ProjectId --policy-from-file=$PolicyFile | Out-Null
  } else {
    Write-Host "Criando policy: $displayName"
    gcloud alpha monitoring policies create --project=$ProjectId --policy-from-file=$PolicyFile | Out-Null
  }
}

Ensure-Project

# 1) Log-based metrics for critical runtime warnings.
Ensure-LogMetric `
  -MetricName "dmf_redis_unavailable_count" `
  -Description "Conta warnings de Redis indisponivel no runtime." `
  -Filter "resource.type=`"gae_app`" AND resource.labels.module_id=`"$ServiceName`" AND textPayload:`"Redis is unavailable`""

Ensure-LogMetric `
  -MetricName "dmf_sse_pubsub_init_fail_count" `
  -Description "Conta falhas de inicializacao de SSE Pub/Sub." `
  -Filter "resource.type=`"gae_app`" AND resource.labels.module_id=`"$ServiceName`" AND textPayload:`"Failed to initialize Pub/Sub SSE subscription`""

Ensure-LogMetric `
  -MetricName "dmf_http_5xx_alert_count" `
  -Description "Conta logs ALERT_HTTP_5XX emitidos pelo backend." `
  -Filter "resource.type=`"gae_app`" AND resource.labels.module_id=`"$ServiceName`" AND textPayload:`"ALERT_HTTP_5XX`""

$policyDir = Join-Path $PSScriptRoot "monitoring-policies"
New-Item -ItemType Directory -Force -Path $policyDir | Out-Null

$notifJson = "[]"
if ($NotificationChannel) {
  $notifJson = "[`"$NotificationChannel`"]"
}

$policy5xx = @"
{
  "displayName": "DMF AppEngine 5xx Spike",
  "combiner": "OR",
  "conditions": [
    {
      "displayName": "5xx > 10 em 5m",
      "conditionThreshold": {
        "filter": "resource.type=\"gae_app\" AND resource.label.\"module_id\"=\"$ServiceName\" AND metric.type=\"logging.googleapis.com/user/dmf_http_5xx_alert_count\"",
        "comparison": "COMPARISON_GT",
        "thresholdValue": 10,
        "duration": "300s",
        "aggregations": [
          {
            "alignmentPeriod": "60s",
            "perSeriesAligner": "ALIGN_RATE"
          }
        ],
        "trigger": { "count": 1 }
      }
    }
  ],
  "alertStrategy": { "autoClose": "1800s" },
  "notificationChannels": $notifJson,
  "enabled": true
}
"@

$policyRedis = @"
{
  "displayName": "DMF Redis Runtime Warning",
  "combiner": "OR",
  "conditions": [
    {
      "displayName": "Redis indisponivel > 0 em 5m",
      "conditionThreshold": {
        "filter": "resource.type=\"gae_app\" AND resource.label.\"module_id\"=\"$ServiceName\" AND metric.type=\"logging.googleapis.com/user/dmf_redis_unavailable_count\"",
        "comparison": "COMPARISON_GT",
        "thresholdValue": 0,
        "duration": "300s",
        "aggregations": [
          {
            "alignmentPeriod": "60s",
            "perSeriesAligner": "ALIGN_RATE"
          }
        ],
        "trigger": { "count": 1 }
      }
    }
  ],
  "alertStrategy": { "autoClose": "1800s" },
  "notificationChannels": $notifJson,
  "enabled": true
}
"@

$policySse = @"
{
  "displayName": "DMF SSE PubSub Init Failure",
  "combiner": "OR",
  "conditions": [
    {
      "displayName": "Falha init SSE PubSub > 0 em 5m",
      "conditionThreshold": {
        "filter": "resource.type=\"gae_app\" AND resource.label.\"module_id\"=\"$ServiceName\" AND metric.type=\"logging.googleapis.com/user/dmf_sse_pubsub_init_fail_count\"",
        "comparison": "COMPARISON_GT",
        "thresholdValue": 0,
        "duration": "300s",
        "aggregations": [
          {
            "alignmentPeriod": "60s",
            "perSeriesAligner": "ALIGN_RATE"
          }
        ],
        "trigger": { "count": 1 }
      }
    }
  ],
  "alertStrategy": { "autoClose": "1800s" },
  "notificationChannels": $notifJson,
  "enabled": true
}
"@

$p1 = Join-Path $policyDir "policy-5xx.json"
$p2 = Join-Path $policyDir "policy-redis.json"
$p3 = Join-Path $policyDir "policy-sse.json"

$policy5xx | Set-Content -Path $p1 -Encoding UTF8
$policyRedis | Set-Content -Path $p2 -Encoding UTF8
$policySse | Set-Content -Path $p3 -Encoding UTF8

Upsert-Policy -PolicyFile $p1
Upsert-Policy -PolicyFile $p2
Upsert-Policy -PolicyFile $p3

Write-Host "Alertas configurados com sucesso."
Write-Host "Project: $ProjectId"
Write-Host "Service: $ServiceName"
if ($NotificationChannel) {
  Write-Host "Notification channel: $NotificationChannel"
} else {
  Write-Host "Notification channel: nao configurado (adicione depois no Cloud Monitoring)."
}
