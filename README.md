# STI-CS-MLE-Tool
Import file path list into MLE List by CS API
## 1. 簡介與架構說明
1. Import-FalconMLExclusionsV5.ps1：批次匯入排除規則，支援跨平台（Windows / Linux）路徑自動辨識與多 CID 處理。
2. Get-FalconMLExclusions.ps1：查詢並導出 Exclusion 詳細清單，保留 API 原始（Raw）字串，支援記錄筆數限制與測試模式。
3. Batch-Delete-FalconMLExclusions.ps1：精準刪除工具，可直接讀取 `Get-FalconMLExclusions.ps1` 所導出的 CSV 檔案並以 `id` 進行 Chunking 高速刪除。

## 2. 系統環境準備與設定檔 (config.cfg)

所有腳本皆共用目錄下的 `config.cfg` 設定檔。執行前請確認 API 權限（需具備 **ML Exclusions: Read/Write** 權限）與端點設定正確。

### 2.2 設定檔範例 (`config.cfg`)
```ini
# API Client 憑證
ClientId=your_falcon_client_id
ClientSecret=your_falcon_client_secret

# CrowdStrike 雲端區域端點
BaseUrl=https://api.us-2.crowdstrike.com

# 多 CID 設定 (MSSP/Flight Control，以分號分隔；單一租戶請留空)
不支援Multi CID

# 路徑與編碼設定
InputFolder=.\csv_input
LogFolder=.\output
Encoding=utf8 or big5 支援簡中, 繁中, 英文字串

# 全域 DryRun 設定 (true: 模擬不寫入 | false: 正式異動)
DryRun=true
