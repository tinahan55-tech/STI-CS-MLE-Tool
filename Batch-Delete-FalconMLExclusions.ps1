<#
.SYNOPSIS
    CrowdStrike Falcon Machine Learning Exclusions 批次刪除工具
	支援powershell 5.1 以上版本

.DESCRIPTION
    可以直接讀取 Get-FalconMLExclusions.ps1 導出的 CSV 檔案。
    優先以 id 欄位調用 API 直接進行刪除（精準度與效率最高）。
    支援 -WhatIf (測試模擬模式) 與 -MaxRecords (限制刪除筆數)。

.EXAMPLE
    # 測試模式：模擬刪除匯出檔的前 5 筆資料 (不實際執行刪除)
    .\Batch-Delete-FalconMLExclusions.ps1 -InputCsv .\output\Falcon_ML_Exclusions_20260410.csv -MaxRecords 5 -WhatIf

.EXAMPLE
    # 正式執行：全數刪除 CSV 檔中的記錄
    .\Batch-Delete-FalconMLExclusions.ps1 -InputCsv .\output\Falcon_ML_Exclusions_20260410.csv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InputCsv,
    [Parameter(Mandatory = $false)][string]$ConfigFile = ".\config.cfg",
    [Parameter(Mandatory = $false)][int]$MaxRecords = 0,         # 0 代表刪除全數，>0 代表最多刪除指定筆數
    [Parameter(Mandatory = $false)][switch]$WhatIf              # 模擬測試模式
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

$script:authCache = @{ Token = ""; Expires = [datetime]::MinValue }

function Get-FalconAuthToken {
    param([hashtable]$Config)
    if ((Get-Date) -lt $script:authCache.Expires) { return $script:authCache.Token }
    $body = @{ client_id = $Config['ClientId']; client_secret = $Config['ClientSecret'] }
    $resp = Invoke-RestMethod -Method Post -Uri "$($Config['BaseUrl'])/oauth2/token" -Body $body
    $script:authCache.Token = $resp.access_token
    $script:authCache.Expires = (Get-Date).AddSeconds($resp.expires_in - 120)
    return $script:authCache.Token
}

function Invoke-FalconApi {
    param([hashtable]$Config, [string]$Method, [string]$Path, [string]$TargetCid = "")
    $token = Get-FalconAuthToken -Config $Config
    $headers = @{ Authorization = "Bearer $token"; Accept = 'application/json' }
    if ($TargetCid -and $TargetCid -ne "Default") { $headers['X-Falcon-Tenant-CID'] = $TargetCid }
    $uri = "$($Config['BaseUrl'])$Path"

    for ($try = 1; $try -le 3; $try++) {
        try {
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
        } catch {
            $status = 0
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -eq 429 -and $try -lt 3) { Start-Sleep -Seconds 5; continue }
            throw
        }
    }
}

try {
    $config = Initialize-ConfigFile -Path $ConfigFile
    
    if (-not (Test-Path $InputCsv)) { throw "找不到輸入的 CSV 檔案: $InputCsv" }
    $rawCsv = Import-Csv -Path $InputCsv -Encoding UTF8

    if ($rawCsv.Count -eq 0) {
        Write-Host "CSV 檔案中無任何記錄。" -ForegroundColor Yellow
        exit 0
    }

    # 套用 MaxRecords 數量限制
    $deleteQueue = $rawCsv
    if ($MaxRecords -gt 0 -and $deleteQueue.Count -gt $MaxRecords) {
        $deleteQueue = $deleteQueue[0..($MaxRecords - 1)]
    }

    Write-Host "=== 準備進行 Falcon ML Exclusions 批次刪除 ===" -ForegroundColor Cyan
    Write-Host "CSV 檔案總筆數 : $($rawCsv.Count)" -ForegroundColor Gray
    Write-Host "預計處理筆數   : $($deleteQueue.Count)" -ForegroundColor Yellow
    if ($WhatIf) { Write-Host "[WHAT-IF MODE] 模擬測試模式開啟，將不會對雲端進行實際刪除。" -ForegroundColor Red }

    # 按 CID 分組處理以利 API 批次操作
    $groupedByCid = $deleteQueue | Group-Object -Property CID

    $successCount = 0
    $failCount = 0

    foreach ($group in $groupedByCid) {
        $targetCid = $group.Name
        $items = $group.Group
        Write-Host "`n>>> 正在處理 CID [$targetCid] (共 $($items.Count) 筆)..." -ForegroundColor Yellow

        # 整理出刪除所需 ID 陣列
        $idsToDelete = @($items | Where-Object { $_.id } | Select-Object -ExpandProperty id)

        if ($idsToDelete.Count -eq 0) {
            Write-Host "  └─ [警告] 本批次項目均缺少 'id' 欄位，無法直接進行 ID 刪除。" -ForegroundColor Red
            continue
        }

        # 批次刪除 (Chunking = 100/次)
        $chunkSize = 20
        for ($i = 0; $i -lt $idsToDelete.Count; $i += $chunkSize) {
            $currentChunkSize = [Math]::Min($chunkSize, $idsToDelete.Count - $i)
            # 強制轉換為陣列類型，防止單筆資料時退化成單一物件
            $chunk = @($idsToDelete[$i..($i + $currentChunkSize - 1)])
            
            $qs = ($chunk | ForEach-Object { "ids=$([uri]::EscapeDataString($_))" }) -join '&'
            $deletePath = "/policy/entities/ml-exclusions/v1?$qs"

            if ($WhatIf) {
                Write-Host "  └─ [What-If 模擬] 將執行 DELETE $deletePath (包含 $($chunk.Count) 筆 IDs)" -ForegroundColor Gray
                $successCount += $chunk.Count
            } else {
                try {
                    $resp = Invoke-FalconApi -Config $config -Method Delete -Path $deletePath -TargetCid $targetCid
                    Write-Host "  └─ [成功] 批次刪除 $($chunk.Count) 筆記錄。" -ForegroundColor Green
                    $successCount += $chunk.Count
                } catch {
                    Write-Host "  └─ [失敗] 刪除失敗: $($_.Exception.Message)" -ForegroundColor Red
                    $failCount += $chunk.Count
                }
            }
        }
    }

    Write-Host "`n==================================================" -ForegroundColor Cyan
    Write-Host "處理完成！" -ForegroundColor Cyan
    Write-Host "成功預定/完成: $successCount 筆" -ForegroundColor Green
    
    # 修正點：使用跨版本相容的 $(if ... else ...) 語法
    Write-Host "失敗筆數      : $failCount 筆" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Gray" })

} catch {
    Write-Host "[Fatal Error] 執行發生例外: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
