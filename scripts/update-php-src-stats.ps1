param(
  [string]$PhpSrcPath = "C:\Users\admin\Desktop\php-src",
  [switch]$Fetch,
  [switch]$CreateCommit,
  [switch]$Push
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()

$SiteRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$StatsPath = Join-Path $SiteRoot "php-src-stats.json"

if (-not (Test-Path $PhpSrcPath)) {
  throw "php-src path not found: $PhpSrcPath"
}

git -C $PhpSrcPath rev-parse --is-inside-work-tree | Out-Null

if ($Fetch) {
  git -C $PhpSrcPath fetch --all --prune
}

$authorPatterns = @(
  "LamentXU123",
  "Weilin Du",
  "lamentxu",
  "weilindu@php.net",
  "108666168+LamentXU123@users.noreply.github.com",
  "1372449351@qq.com"
)

$commits = [System.Collections.Generic.HashSet[string]]::new()

foreach ($pattern in $authorPatterns) {
  git -C $PhpSrcPath log --all --author=$pattern --format="%H" |
    ForEach-Object {
      if ($_ -and $_.Trim()) {
        [void]$commits.Add($_.Trim())
      }
    }
}

$additions = [int64]0
$deletions = [int64]0

foreach ($commitHash in $commits) {
  git -C $PhpSrcPath show --format="" --numstat $commitHash |
    ForEach-Object {
      $parts = $_ -split "`t"
      if ($parts.Length -ge 2 -and $parts[0] -match "^\d+$" -and $parts[1] -match "^\d+$") {
        $script:additions += [int64]$parts[0]
        $script:deletions += [int64]$parts[1]
      }
    }
}

$stats = [ordered]@{
  owner = "php"
  repo = "php-src"
  author = "LamentXU123"
  additions = $additions
  deletions = $deletions
  prs = $commits.Count
  label = (-join @([char]25552, [char]20132))
  source = "local git author commit numstat"
  phpSrcPath = (Resolve-Path $PhpSrcPath).Path
  updatedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

$json = $stats | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText($StatsPath, "$json`n", [System.Text.UTF8Encoding]::new($false))

Write-Host "Updated $StatsPath"
Write-Host "additions=$additions deletions=$deletions commits=$($commits.Count)"

if ($CreateCommit) {
  git -C $SiteRoot add php-src-stats.json
  $status = git -C $SiteRoot status --short php-src-stats.json
  if ($status) {
    git -C $SiteRoot commit -m "Update php-src contribution stats"
  } else {
    Write-Host "No stats changes to commit."
  }
}

if ($Push) {
  git -C $SiteRoot push
}
