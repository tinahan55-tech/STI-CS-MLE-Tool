<#
.SYNOPSIS
    CrowdStrike Falcon Machine Learning Exclusions 導出工具 (支援 Multi-CID / Strict Token 隔離 / 完整錯誤 Log)

.DESCRIPTION
    1. 取得 ML Exclusion 完整詳細資訊（保留 Raw 原始路徑，不進行跨平台正規化）。
    2. 每個 CID 擁有完全獨立的 Token 空間，絕不跨 CID 共享 Token。
    3. Token 有效期為 30 分鐘，若單一 CID 處理超過 28 分鐘會自動針對該 CID 更新 Token。
    4. 完整抓取並解析 CrowdStrike API 回傳的 Error Response (JSON) 登入/呼叫失敗細節。

.EXAMPLE
    # 測試模式：僅在螢幕顯示，不儲存 CSV
    .\Get-FalconMLExclusions.ps1 -TestMode

.EXAMPLE
    # 僅取前 10 筆並匯出至 CSV
    .\Get-FalconMLExclusions.ps1 -MaxRecords 10
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][string]$ConfigFile = ".\config.cfg",
    [Parameter(Mandatory = $false)][string]$OutputFolder = ".\output",
    [Parameter(Mandatory = $false)][int]$MaxRecords = 0,         # 0 代表全取，>0 代表指定筆數
    [Parameter(Mandatory = $false)][switch]$TestMode            # 模擬測試模式
)

$ErrorActionPreference = 'Stop'

function Initialize-ConfigFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { throw "找不到設定檔 $Path" }
    $config = @{}
    Get-Content -Path $Path -Encoding UTF8 | Where-Object { $_ -match '^\s*([^#=]+)\s*=\s*(.*)' } | ForEach-Object {
        $config[$matches[1].Trim()] = $matches[2].Trim()
    }
    return $config
}

# 輔助函式：解析 CrowdStrike API 拋出的詳細 Error Response (JSON Stream)
function Get-FalconErrorDetail {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    
    try {
        if ($ErrorRecord.Exception.Response) {
            $response = $ErrorRecord.Exception.Response
            $statusCode = [int]$response.StatusCode
            
            # 讀取 Response Body
            $stream = $response.GetResponseStream()
            if ($stream) {
                $reader = [System.IO.StreamReader]::new($stream)
                $rawBody = $reader.ReadToEnd()
                
                # 釋放 Stream 資源
                $reader.Dispose()
                $stream.Dispose()
                
                # 試圖轉換 JSON
                if ($rawBody) {
                    $jsonObj = $rawBody | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($jsonObj.errors) {
                        $errMsgs = ($jsonObj.errors | ForEach-Object { "[$($_.code)] $($_.message)" }) -join " | "
                        return "HTTP $statusCode - $errMsgs"
                    }
                    return "HTTP $statusCode - $rawBody"
                }
            }
            return "HTTP $statusCode - $($response.StatusDescription)"
        }
    } catch {
        # 解析失敗時降級回傳原生的 Exception Message
    }
    return $ErrorRecord.Exception.Message
}

# 為特定 CID 取得全新/有效之專屬 Token (不跨 CID 共享，包含登入錯誤抓取)
function Get-CidSpecificToken {
    param(
        [hashtable]$Config, 
        [string]$TargetCid,
        [ref]$CidCache
    )

    # 如果當前 CID 的 Token 存在且未接近 30 分鐘過期時間 (預留 120 秒)，直接回傳
    if ($CidCache.Value -and (Get-Date) -lt $CidCache.Value.Expires) {
        return $CidCache.Value.Token
    }

    # 否則重新為此 CID 申請新 Token
    $body = @{ 
        client_id     = $Config['ClientId']
        client_secret = $Config['ClientSecret'] 
    }
    if ($TargetCid) { 
        $body['member_cid'] = $TargetCid 
    }

    try {
        $resp = Invoke-RestMethod -Method Post -Uri "$($Config['BaseUrl'])/oauth2/token" -Body $body
        
        # 記錄 Token 及 30 分鐘過期時間 (預留 2 分鐘彈性)
        $CidCache.Value = @{
            Token   = $resp.access_token
            Expires = (Get-Date).AddSeconds($resp.expires_in - 120)
        }

        return $CidCache.Value.Token
    }
    catch {
        $errDetail = Get-FalconErrorDetail -ErrorRecord $_
        $targetMsg = if ($TargetCid) { "Child CID [$TargetCid]" } else { "Parent CID" }
        throw "對 $targetMsg 進行 OAuth2 登入失敗: $errDetail"
    }
}

# 呼叫 API (內部自動維持該 CID Token 效期與錯誤細節擷取)
function Invoke-FalconApi {
    param(
        [hashtable]$Config, 
        [string]$Method, 
        [string]$Path, 
        [string]$TargetCid,
        [ref]$CidCache
    )
    
    $token = Get-CidSpecificToken -Config $Config -TargetCid $TargetCid -CidCache $CidCache
    $headers = @{ 
        Authorization = "Bearer $token"
        Accept        = 'application/json' 
    }
    $uri = "$($Config['BaseUrl'])$Path"

    for ($try = 1; $try -le 3; $try++) {
        try {
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
        } catch {
            $status = 0
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -eq 429 -and $try -lt 3) { Start-Sleep -Seconds 5; continue }
            
            $errDetail = Get-FalconErrorDetail -ErrorRecord $_
            throw "呼叫 API [$Path] 失敗: $errDetail"
        }
    }
}

try {
    $config = Initialize-ConfigFile -Path $ConfigFile
    $outputDir = [System.IO.Path]::GetFullPath($OutputFolder)
    if (-not (Test-Path $outputDir) -and -not $TestMode) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }

    # 解析設定檔中的 MemberCid，若未提供則預設執行 Parent CID 自身
    $cidList = if ($config['MemberCid']) { $config['MemberCid'] -split '[;,]' | Where-Object { $_.Trim() } } else { @("") }
    $allExclusions = [System.Collections.Generic.List[PSObject]]::new()

    Write-Host "=== 開始查詢 Falcon ML Exclusions (Multi-CID Strictly Isolated Mode) ===" -ForegroundColor Cyan
    if ($TestMode) { Write-Host "[TEST MODE] 啟用模擬測試：資料將不會寫入檔案。" -ForegroundColor Yellow }
    if ($MaxRecords -gt 0) { Write-Host "筆數限制: 取前 $MaxRecords 筆記錄" -ForegroundColor Yellow } else { Write-Host "筆數限制: 取得全部記錄" -ForegroundColor Green }

    foreach ($currentCid in $cidList) {
        if ($MaxRecords -gt 0 -and $allExclusions.Count -ge $MaxRecords) { break }

        $cidDisplay = if ($currentCid) { "Child CID [$currentCid]" } else { "預設 Parent CID" }
        Write-Host "`n>>> 正在初始化 $cidDisplay 的專屬 Token..." -ForegroundColor Yellow

        # 核心隔離機制：每一個 CID 進入時重新宣告全新的 Token 快取容器
        $cidTokenCache = @{ Token = ""; Expires = [datetime]::MinValue }

        $ids = [System.Collections.Generic.List[string]]::new()
        $offset = 0
        $limit = 100

        try {
            # 先試取得一次 Token 確定認證正常並顯示提示
            $null = Get-CidSpecificToken -Config $config -TargetCid $currentCid -CidCache ([ref]$cidTokenCache)
            Write-Host "  └─ 專屬 Token 取得成功 (效期 30 分鐘，不跨 CID 共享)。" -ForegroundColor Green

            # Step 1: 查詢 IDs
            do {
                $queryPath = "/policy/queries/ml-exclusions/v1?limit=$limit&offset=$offset"
                $r = Invoke-FalconApi -Config $config -Method Get -Path $queryPath -TargetCid $currentCid -CidCache ([ref]$cidTokenCache)
                if ($r.resources) { $ids.AddRange([string[]]$r.resources) }
                $total = if ($r.meta.pagination.total) { $r.meta.pagination.total } else { 0 }
                $offset += $limit
                
                # 若已有筆數限制，達到數量即可提早結束 Query 循環
                if ($MaxRecords -gt 0 -and ($allExclusions.Count + $ids.Count) -ge $MaxRecords) { break }
            } while ($ids.Count -lt $total -and $r.resources.Count -gt 0)

            if ($ids.Count -eq 0) {
                Write-Host "  └─ [提示] 此 CID 目前無任何 ML Exclusion。" -ForegroundColor Gray
                continue
            }

            # 裁剪需要的 ID 數量
            $targetIds = $ids
            if ($MaxRecords -gt 0) {
                $remainingNeeded = $MaxRecords - $allExclusions.Count
                if ($targetIds.Count -gt $remainingNeeded) {
                    $targetIds = $targetIds.GetRange(0, $remainingNeeded)
                }
            }

            # Step 2: 批次取得實體細節
            $chunkSize = 100
            for ($i = 0; $i -lt $targetIds.Count; $i += $chunkSize) {
                $currentChunkSize = [Math]::Min($chunkSize, $targetIds.Count - $i)
                $chunk = $targetIds.GetRange($i, $currentChunkSize)
                $qs = ($chunk | ForEach-Object { "ids=$([uri]::EscapeDataString($_))" }) -join '&'
                
                $detailResp = Invoke-FalconApi -Config $config -Method Get -Path "/policy/entities/ml-exclusions/v1?$qs" -TargetCid $currentCid -CidCache ([ref]$cidTokenCache)

                foreach ($item in $detailResp.resources) {
                    $groupList = if ($item.groups) { ($item.groups | ForEach-Object { if ($_.name) { $_.name } else { $_.id } }) -join ';' } else { "" }
                    
                    $obj = [PSCustomObject]@{
                        CID                = if ($currentCid) { $currentCid } else { "Parent/Default" }
                        id                 = $item.id
                        value              = $item.value                 # Raw 原始放行字串
                        groups             = $groupList
                        modified_by        = $item.modified_by
                        created_by         = $item.created_by
                        created_timestamp  = $item.created_timestamp
                        modified_timestamp = $item.modified_timestamp
                        comment            = $item.comment
                    }
                    [void]$allExclusions.Add($obj)
                }
            }
        }
        catch {
            # 正確印出丟出的字串錯誤（修正 $_.Exception.Message 抓不到 String 的 Bug）
            Write-Host "  └─ [Error] 處理 $cidDisplay 時發生錯誤: $_" -ForegroundColor Red
        }
        finally {
            # 當前 CID 處理結束，徹底銷毀該 CID 的 Token 空間
            $cidTokenCache = $null
        }
    }

    Write-Host "`n==================================================" -ForegroundColor Green
    Write-Host "共順利取得 $($allExclusions.Count) 筆記錄。" -ForegroundColor Green

    if ($allExclusions.Count -gt 0) {
        if (-not $TestMode) {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $exportCsvPath = Join-Path $outputDir "Falcon_ML_Exclusions_$timestamp.csv"
            $allExclusions | Export-Csv -Path $exportCsvPath -NoTypeInformation -Encoding UTF8
            Write-Host "CSV 檔案已寫入: $exportCsvPath" -ForegroundColor Green
        } else {
            Write-Host "[TEST MODE] 測試完畢，未寫入檔案。" -ForegroundColor Yellow
        }

        Write-Host "`n--- 資料預覽 ---" -ForegroundColor Yellow
        $allExclusions | Format-Table -AutoSize CID, id, value, modified_by
    }

} catch {
    Write-Host "[Fatal Error] 執行失敗: $_" -ForegroundColor Red
    exit 1
}