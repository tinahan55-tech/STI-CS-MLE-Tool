<#
.SYNOPSIS
    從 CSV 大量匯入 CrowdStrike Falcon 的 Machine Learning Exclusions（ML 放行清單），支援讀取 .cfg 設定檔。

.DESCRIPTION
    透過 CrowdStrike OAuth2 API 逐筆建立 ML exclusion：
      POST /policy/entities/ml-exclusions/v1

    支援傳入 -ConfigPath 指定單一 .cfg 設定檔或設定檔資料夾，自動掃描並載入參數執行。

.EXAMPLE
    .\Import-FalconMLExclusionsV5.ps1 -ConfigPath .\config.cfg
    .\Import-FalconMLExclusionsV5.ps1 -ConfigPath .\configs\
#>
[CmdletBinding()]
param(
    # 可傳入單一 .cfg 檔案路徑，或包含 .cfg 的資料夾路徑（預設為當前執行目錄）
    [string]$ConfigPath = '.\',

    # 手動指定單一 CSV 時使用（若 Config 內有指定 InputFolder，則會優先掃描 InputFolder 內的 CSV）
    [string]$CsvPath,

    [string]$ClientId,
    [string]$ClientSecret,
    [string]$BaseUrl = 'https://api.us-2.crowdstrike.com',
    [string]$MemberCid,
    [string[]]$Groups = @('all'),
    [ValidateSet('blocking', 'extraction')]
    [string[]]$ExcludedFrom = @('blocking'),
    [string]$DefaultComment,
    [string]$Encoding = 'big5',
    [switch]$DryRun,
    [switch]$SkipExistingCheck
)

$ErrorActionPreference = 'Stop'

# ---------- 1. 解析並載入 Config 檔案 ----------
$configFiles = @()
if (Test-Path $ConfigPath) {
    if ((Get-Item $ConfigPath).PSIsContainer) {
        $configFiles = Get-ChildItem -Path $ConfigPath -Filter "*.cfg" -File
    } else {
        $configFiles = @(Get-Item $ConfigPath)
    }
}

if ($configFiles.Count -eq 0 -and -not $ClientId) {
    throw "未找到任何 .cfg 配置文件，且未提供 -ClientId 參數。"
}

# 輔助函式：解析 .cfg 檔案內容為 Hashtable
function Parse-ConfigFile {
    param([string]$FilePath)
    $cfg = @{}
    Get-Content -Path $FilePath -Encoding UTF8 | Where-Object { $_ -and -not $_.Trim().StartsWith('#') } | ForEach-Object {
        $parts = $_.Split('=', 2)
        if ($parts.Count -eq 2) {
            $key = $parts[0].Trim()
            $val = $parts[1].Trim()
            if ($key) { $cfg[$key] = $val }
        }
    }
    return $cfg
}

# 若找到 config 檔，逐個處理；若無，則封裝目前命令列參數為一個單一任務
$tasks = @()
if ($configFiles.Count -gt 0) {
    foreach ($cfgFile in $configFiles) {
        Write-Host "已載入配置文件: $($cfgFile.FullName)" -ForegroundColor Cyan
        $c = Parse-ConfigFile -FilePath $cfgFile.FullName
        
        # 處理有多個 MemberCid (以逗號或分號分隔)
        $cids = if ($c['MemberCid']) { $c['MemberCid'] -split '[;,]' | Where-Object { $_.Trim() } } else { @('') }

        foreach ($cid in $cids) {
            $tasks += [pscustomobject]@{
                ConfigFile        = $cfgFile.Name
                ClientId          = if ($c['ClientId']) { $c['ClientId'] } else { $ClientId }
                ClientSecret      = if ($c['ClientSecret']) { $c['ClientSecret'] } else { $ClientSecret }
                BaseUrl           = if ($c['BaseUrl']) { $c['BaseUrl'] } else { $BaseUrl }
                MemberCid         = $cid.Trim()
                InputFolder       = $c['InputFolder']
                LogFolder         = $c['LogFolder']
                Groups            = if ($c['Groups']) { $c['Groups'] -split '[;,]' } else { $Groups }
                ExcludedFrom      = if ($c['ExcludedFrom']) { $c['ExcludedFrom'] -split '[;,]' } else { $ExcludedFrom }
                DefaultComment    = if ($c['DefaultComment']) { $c['DefaultComment'] } else { $DefaultComment }
                Encoding          = if ($c['Encoding']) { $c['Encoding'] } else { $Encoding }
                DryRun            = if ($c['DryRun']) { [bool]::Parse($c['DryRun']) } else { $DryRun.IsPresent }
                SkipExistingCheck = if ($c['SkipExistingCheck']) { [bool]::Parse($c['SkipExistingCheck']) } else { $SkipExistingCheck.IsPresent }
            }
        }
    }
} else {
    $tasks += [pscustomobject]@{
        ConfigFile        = 'N/A'
        ClientId          = $ClientId
        ClientSecret      = $ClientSecret
        BaseUrl           = $BaseUrl
        MemberCid         = $MemberCid
        InputFolder       = $null
        LogFolder         = $null
        Groups            = $Groups
        ExcludedFrom      = $ExcludedFrom
        DefaultComment    = if ($DefaultComment) { $DefaultComment } else { "Bulk import via API $(Get-Date -Format 'yyyy-MM-dd')" }
        Encoding          = $Encoding
        DryRun            = $DryRun.IsPresent
        SkipExistingCheck = $SkipExistingCheck.IsPresent
    }
}

# ---------- API 核心函式定義 ----------
$script:tokenExpires = [datetime]::MinValue
function Get-FalconToken {
    param($Task)
    $body = @{ client_id = $Task.ClientId; client_secret = $Task.ClientSecret }
    if ($Task.MemberCid) { $body.member_cid = $Task.MemberCid }
    $resp = Invoke-RestMethod -Method Post -Uri "$($Task.BaseUrl)/oauth2/token" -Body $body
    $script:token = $resp.access_token
    $script:tokenExpires = (Get-Date).AddSeconds($resp.expires_in - 120)
}

function Invoke-Falcon {
    param([string]$Method, [string]$Path, [string]$JsonBody, $Task)
    if ((Get-Date) -ge $script:tokenExpires) { Get-FalconToken -Task $Task }
    $params = @{
        Method  = $Method
        Uri     = "$($Task.BaseUrl)$Path"
        Headers = @{ Authorization = "Bearer $script:token"; Accept = 'application/json' }
    }
    if ($JsonBody) {
        $params.Body        = [System.Text.Encoding]::UTF8.GetBytes($JsonBody)
        $params.ContentType = 'application/json; charset=utf-8'
    }
    for ($try = 1; $try -le 3; $try++) {
        try { return Invoke-RestMethod @params }
        catch {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -eq 429 -and $try -lt 3) {
                Write-Host "  觸發 rate limit，等待 5 秒後重試..." -ForegroundColor Yellow
                Start-Sleep -Seconds 5
                continue
            }
            throw
        }
    }
}

# ---------- 2. 執行所有任務 ----------
foreach ($task in $tasks) {
    Write-Host "`n==================================================" -ForegroundColor Header
    Write-Host "開始處理任務 [Config: $($task.ConfigFile)] [CID: $(if($task.MemberCid){$task.MemberCid}else{'Self'})]" -ForegroundColor Header
    Write-Host "==================================================" -ForegroundColor Header

    if (-not $task.ClientId -or -not $task.ClientSecret) {
        Write-Host "缺少 ClientId 或 ClientSecret，跳過此任務。" -ForegroundColor Red
        continue
    }

    # 收集待處理的 CSV 檔案
    $targetCsvs = @()
    if ($task.InputFolder -and (Test-Path $task.InputFolder)) {
        $targetCsvs += Get-ChildItem -Path $task.InputFolder -Filter "*.csv" | Select-Object -ExpandProperty FullName
    } elseif ($CsvPath -and (Test-Path $CsvPath)) {
        $targetCsvs += (Resolve-Path $CsvPath).Path
    }

    if ($targetCsvs.Count -eq 0) {
        Write-Host "未找到任何待處理的 CSV 檔案，跳過此任務。" -ForegroundColor Yellow
        continue
    }

    foreach ($csvFile in $targetCsvs) {
        Write-Host "`n正在讀取 CSV: $csvFile" -ForegroundColor Cyan

        # 讀取與解析 CSV
        $enc = switch ($task.Encoding.ToLower()) {
            'utf8'    { [System.Text.UTF8Encoding]::new($false) }
            'utf8bom' { [System.Text.UTF8Encoding]::new($true) }
            'default' { [System.Text.Encoding]::Default }
            'big5'    {
                try { [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance) } catch {}
                [System.Text.Encoding]::GetEncoding(950)
            }
            default   { [System.Text.Encoding]::GetEncoding($task.Encoding) }
        }

        $rawText = [System.IO.File]::ReadAllText($csvFile, $enc)
        $text = $rawText.TrimStart([char]0xFEFF)
        $firstLine = ($text -split "\r?\n" | Where-Object { $_.Trim() } | Select-Object -First 1)

        $valueHeaders   = @('value', 'path', 'pattern', 'exclusion', 'primary_executable_filepath', '路徑', '放行路徑', '排除路徑', '檔案路徑')
        $commentHeaders = @('comment', '備註', '說明', '原因', 'reason', 'note')

        $firstCols = $firstLine.Split(',') | ForEach-Object { $_.Trim().Trim('"').TrimStart([char]0xFEFF) }
        $valueCol   = $firstCols | Where-Object { $valueHeaders -contains $_.ToLower() -or $valueHeaders -contains $_ } | Select-Object -First 1
        $commentCol = $firstCols | Where-Object { $commentHeaders -contains $_.ToLower() -or $commentHeaders -contains $_ } | Select-Object -First 1

        if ($valueCol) {
            $rows = $text | ConvertFrom-Csv
        } else {
            Write-Host "未偵測到標題列，將第一欄視為路徑、第二欄視為備註。" -ForegroundColor Yellow
            $rows = $text | ConvertFrom-Csv -Header 'value', 'comment'
            $valueCol = 'value'; $commentCol = 'comment'
        }

        $entries = foreach ($row in $rows) {
            $v = "$($row.$valueCol)".Trim().Trim('"').TrimStart([char]0xFEFF)
            if (-not $v) { continue }
            $c = if ($commentCol) { "$($row.$commentCol)".Trim() } else { '' }
            [pscustomobject]@{ value = $v; comment = if ($c) { $c } else { $task.DefaultComment } }
        }

        $entries = $entries | Group-Object { $_.value.ToLower() } | ForEach-Object { $_.Group[0] }
        if (-not $entries) {
            Write-Host "CSV 中無有效路徑，跳過此檔案。" -ForegroundColor Yellow
            continue
        }

        # 認證與檢查既有 Exclusions
        if (-not $task.DryRun) { Get-FalconToken -Task $task }

        $existingValues = @{}
        if (-not $task.SkipExistingCheck -and -not $task.DryRun) {
            Write-Host '查詢既有的 ML exclusions...'
            $ids = @(); $offset = 0
            do {
                $r = Invoke-Falcon -Method Get -Path "/policy/queries/ml-exclusions/v1?limit=500&offset=$offset" -Task $task
                $ids += @($r.resources)
                $total = $r.meta.pagination.total
                $offset += 500
            } while ($ids.Count -lt $total)

            for ($i = 0; $i -lt $ids.Count; $i += 100) {
                $chunk = $ids[$i..([Math]::Min($i + 99, $ids.Count - 1))]
                $qs = ($chunk | ForEach-Object { "ids=$([uri]::EscapeDataString($_))" }) -join '&'
                $detail = Invoke-Falcon -Method Get -Path "/policy/entities/ml-exclusions/v1?$qs" -Task $task
                foreach ($e in $detail.resources) { $existingValues[$e.value.ToLower()] = $true }
            }
        }

        # 執行匯入
        $created = @(); $skipped = @(); $failed = @()
        $i = 0
        foreach ($entry in $entries) {
            $i++
            $prefix = "[$i/$(@($entries).Count)]"

            if ($existingValues.ContainsKey($entry.value.ToLower())) {
                Write-Host "$prefix 已存在，略過：$($entry.value)" -ForegroundColor DarkGray
                $skipped += $entry
                continue
            }

            $payload = @{
                value         = $entry.value
                comment       = $entry.comment
                groups        = $task.Groups
                excluded_from = $task.ExcludedFrom
            } | ConvertTo-Json -Depth 3

            if ($task.DryRun) {
                Write-Host "$prefix [DryRun] 將建立：" -ForegroundColor Cyan
                Write-Host $payload
                continue
            }

            try {
                $null = Invoke-Falcon -Method Post -Path '/policy/entities/ml-exclusions/v1' -JsonBody $payload -Task $task
                Write-Host "$prefix 建立成功：$($entry.value)" -ForegroundColor Green
                $created += $entry
            } catch {
                $errMsg = $_.ErrorDetails.Message
                if (-not $errMsg) { $errMsg = $_.Exception.Message }
                Write-Host "$prefix 建立失敗：$($entry.value)" -ForegroundColor Red
                Write-Host "  $errMsg" -ForegroundColor Red
                $failed += [pscustomobject]@{ value = $entry.value; comment = $entry.comment; error = $errMsg }
            }
            Start-Sleep -Milliseconds 100
        }

        # 輸出失敗 Log
        if ($failed -and $task.LogFolder) {
            if (-not (Test-Path $task.LogFolder)) { New-Item -ItemType Directory -Path $task.LogFolder | Out-Null }
            $failCsv = Join-Path $task.LogFolder ("import-failed-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
            $failed | Export-Csv -Path $failCsv -NoTypeInformation -Encoding UTF8
            Write-Host "失敗清單已輸出至 Log 目錄：$failCsv" -ForegroundColor Yellow
        }
    }
}