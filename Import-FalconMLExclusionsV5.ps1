<#
.SYNOPSIS
    從 CSV 大量匯入 CrowdStrike Falcon 的 Machine Learning Exclusions（ML 放行清單）。

.DESCRIPTION
    透過 CrowdStrike OAuth2 API 逐筆建立 ML exclusion：
      POST /policy/entities/ml-exclusions/v1

    CSV 格式（有無標題列皆可，完整支援 UTF-8 / UTF-8 BOM 繁簡體中文）：
      - 有標題列：路徑欄位名稱可為 value / path / pattern / primary_executable_filepath / 路徑 / 放行路徑 / 排除路徑 / 檔案路徑
                  備註欄位可為 comment / 備註 / 說明 / 原因（可省略）
      - 無標題列：第一欄視為路徑，第二欄（若有）視為備註

.EXAMPLE
    .\Import-FalconMLExclusions.ps1 -CsvPath .\import-filepath2.csv -ClientId xxx -ClientSecret yyy -DryRun
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$CsvPath,

    [string]$ClientId = $env:FALCON_CLIENT_ID,
    [string]$ClientSecret = $env:FALCON_CLIENT_SECRET,

    # 依所在雲別調整：
    #   US-1: https://api.crowdstrike.com
    #   US-2: https://api.us-2.crowdstrike.com
    #   EU-1: https://api.eu-1.crowdstrike.com
    [string]$BaseUrl = 'https://api.us-2.crowdstrike.com',

    # MSSP / Flight Control 母 CID 對子 CID 操作時填子 CID
    [string]$MemberCid,

    # 套用的 host group ID；'all' = 全部主機
    [string[]]$Groups = @('all'),

    # blocking = ML 偵測/防止；extraction = 檔案上傳分析
    [ValidateSet('blocking', 'extraction')]
    [string[]]$ExcludedFrom = @('blocking'),

    # CSV 該列沒有備註時使用的預設備註
    [string]$DefaultComment = "Bulk import via API(TH0708) $(Get-Date -Format 'yyyy-MM-dd')",

    # CSV 檔案編碼：utf8 / utf8bom / default(ANSI) / big5
    [string]$Encoding = 'utf8',

    # 只預覽將建立的內容，不實際呼叫 API
    [switch]$DryRun,

    # 跳過「查詢既有 exclusion 避免重複」的步驟
    [switch]$SkipExistingCheck
)

$ErrorActionPreference = 'Stop'

if (-not $ClientId -or -not $ClientSecret) {
    throw '缺少 API 憑證：請用 -ClientId / -ClientSecret 參數，或設定環境變數 FALCON_CLIENT_ID / FALCON_CLIENT_SECRET。'
}

# ---------- 讀取 CSV (徹底消除 UTF-8 BOM 與字元相容問題) ----------
$resolvedPath = (Resolve-Path $CsvPath).Path

# 1. 依據 -Encoding 選擇正確的 Encoding 物件
$enc = switch ($Encoding.ToLower()) {
    'utf8'    { [System.Text.UTF8Encoding]::new($false) }
    'utf8bom' { [System.Text.UTF8Encoding]::new($true) }
    'default' { [System.Text.Encoding]::Default }
    'big5'    {
        try { [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance) } catch {}
        [System.Text.Encoding]::GetEncoding(950)
    }
    default   { [System.Text.Encoding]::GetEncoding($Encoding) }
}

# 2. 讀取全文並消除開頭 UTF-8 BOM 字元 (0xFEFF)
$rawText = [System.IO.File]::ReadAllText($resolvedPath, $enc)
$text = $rawText.TrimStart([char]0xFEFF)

# 3. 取得第一行標題列
$firstLine = ($text -split "\r?\n" | Where-Object { $_.Trim() } | Select-Object -First 1)

# 支援各種常見標題列名稱（包含 primary_executable_filepath）
$valueHeaders   = @('value', 'path', 'pattern', 'exclusion', 'primary_executable_filepath', '路徑', '放行路徑', '排除路徑', '檔案路徑')
$commentHeaders = @('comment', '備註', '說明', '原因', 'reason', 'note')

$firstCols = $firstLine.Split(',') | ForEach-Object { $_.Trim().Trim('"').TrimStart([char]0xFEFF) }
$valueCol   = $firstCols | Where-Object { $valueHeaders -contains $_.ToLower() -or $valueHeaders -contains $_ } | Select-Object -First 1
$commentCol = $firstCols | Where-Object { $commentHeaders -contains $_.ToLower() -or $commentHeaders -contains $_ } | Select-Object -First 1

# 4. 解析 CSV 內容
if ($valueCol) {
    $rows = $text | ConvertFrom-Csv
}
else {
    Write-Host "未偵測到標題列，將第一欄視為路徑、第二欄視為備註。" -ForegroundColor Yellow
    $rows = $text | ConvertFrom-Csv -Header 'value', 'comment'
    $valueCol = 'value'; $commentCol = 'comment'
}

$entries = foreach ($row in $rows) {
    # .Trim() 會自動清除路徑開頭與結尾的空格
    $v = "$($row.$valueCol)".Trim().Trim('"').TrimStart([char]0xFEFF)
    if (-not $v) { continue }
    $c = if ($commentCol) { "$($row.$commentCol)".Trim() } else { '' }
    [pscustomobject]@{ value = $v; comment = if ($c) { $c } else { $DefaultComment } }
}

# CSV 內部去重（不分大小寫）
$entries = $entries | Group-Object { $_.value.ToLower() } | ForEach-Object { $_.Group[0] }
if (-not $entries) { throw "CSV 中找不到任何路徑：$resolvedPath" }
Write-Host "CSV 解析完成：$(@($entries).Count) 筆不重複路徑（已相容繁簡體中文與 UTF-8 BOM）。" -ForegroundColor Green

# ---------- 取得 OAuth2 Token ----------
$script:tokenExpires = [datetime]::MinValue
function Get-FalconToken {
    $body = @{ client_id = $ClientId; client_secret = $ClientSecret }
    if ($MemberCid) { $body.member_cid = $MemberCid }
    $resp = Invoke-RestMethod -Method Post -Uri "$BaseUrl/oauth2/token" -Body $body
    $script:token = $resp.access_token
    $script:tokenExpires = (Get-Date).AddSeconds($resp.expires_in - 120)
}

function Invoke-Falcon {
    param([string]$Method, [string]$Path, [string]$JsonBody)
    if ((Get-Date) -ge $script:tokenExpires) { Get-FalconToken }
    $params = @{
        Method  = $Method
        Uri     = "$BaseUrl$Path"
        Headers = @{ Authorization = "Bearer $script:token"; Accept = 'application/json' }
    }
    if ($JsonBody) {
        # 強制轉為 UTF-8 Byte 陣列，確保繁簡體中文字元傳輸至 CrowdStrike 時不變亂碼
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

if (-not $DryRun) {
    Get-FalconToken
    Write-Host "OAuth2 認證成功（$BaseUrl$(if ($MemberCid) { "，member CID: $MemberCid" })）。" -ForegroundColor Green
}

# ---------- 查詢既有 exclusion，避免重複建立 ----------
$existingValues = @{}
if (-not $SkipExistingCheck -and -not $DryRun) {
    Write-Host '查詢既有的 ML exclusions...'
    $ids = @(); $offset = 0
    do {
        $r = Invoke-Falcon -Method Get -Path "/policy/queries/ml-exclusions/v1?limit=500&offset=$offset"
        $ids += @($r.resources)
        $total = $r.meta.pagination.total
        $offset += 500
    } while ($ids.Count -lt $total)

    for ($i = 0; $i -lt $ids.Count; $i += 100) {
        $chunk = $ids[$i..([Math]::Min($i + 99, $ids.Count - 1))]
        $qs = ($chunk | ForEach-Object { "ids=$([uri]::EscapeDataString($_))" }) -join '&'
        $detail = Invoke-Falcon -Method Get -Path "/policy/entities/ml-exclusions/v1?$qs"
        foreach ($e in $detail.resources) { $existingValues[$e.value.ToLower()] = $true }
    }
    Write-Host "既有 exclusion 共 $($existingValues.Count) 筆。"
}

# ---------- 逐筆建立 ----------
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
        groups        = $Groups
        excluded_from = $ExcludedFrom
    } | ConvertTo-Json -Depth 3

    if ($DryRun) {
        Write-Host "$prefix [DryRun] 將建立：" -ForegroundColor Cyan
        Write-Host $payload
        continue
    }

    try {
        $null = Invoke-Falcon -Method Post -Path '/policy/entities/ml-exclusions/v1' -JsonBody $payload
        Write-Host "$prefix 建立成功：$($entry.value)" -ForegroundColor Green
        $created += $entry
    }
    catch {
        $errMsg = $_.ErrorDetails.Message
        if (-not $errMsg) { $errMsg = $_.Exception.Message }
        Write-Host "$prefix 建立失敗：$($entry.value)" -ForegroundColor Red
        Write-Host "  $errMsg" -ForegroundColor Red
        $failed += [pscustomobject]@{ value = $entry.value; comment = $entry.comment; error = $errMsg }
    }
    Start-Sleep -Milliseconds 100
}

# ---------- 結果摘要 ----------
Write-Host ''
Write-Host ('=' * 50)
if ($DryRun) {
    Write-Host "DryRun 完成，共 $(@($entries).Count) 筆待建立（未呼叫 API）。" -ForegroundColor Cyan
}
else {
    Write-Host "完成 — 成功 $(@($created).Count) 筆、略過(已存在) $(@($skipped).Count) 筆、失敗 $(@($failed).Count) 筆。"
    if ($failed) {
        $failCsv = Join-Path (Split-Path $resolvedPath) ("import-failed-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $failed | Export-Csv -Path $failCsv -NoTypeInformation -Encoding UTF8
        Write-Host "失敗清單已輸出：$failCsv" -ForegroundColor Yellow
    }
}