<#
.SYNOPSIS
  构建 NovaWAF Windows 发行包（1.1.2-rc.1）。
.DESCRIPTION
  1) 构建 admin-web/dist
  2) 构建 admin-server jar（自动内嵌前端到 BOOT-INF/classes/static）
  3) 组装 dist-windows\ 目录：jar + WinSW + 安装脚本 + 配置模板
  4) 可选：调用 Inno Setup 生成 .exe 安装包（若 iscc 可用）
  用法: .\build-windows.ps1 [-SkipFrontend] [-SkipInstaller]
#>
param(
    [switch]$SkipFrontend,
    [switch]$SkipInstaller
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = (Resolve-Path (Join-Path $root "..")).Path
$dist = Join-Path $root "dist-windows"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
Remove-Item -Recurse -Force (Join-Path $dist "*") -ErrorAction SilentlyContinue

function Step($m){ Write-Host "[build] $m" -ForegroundColor Cyan }

# 1) 前端
if (-not $SkipFrontend) {
    Step "构建前端 ..."
    Push-Location (Join-Path $root "admin-web")
    & npm run build
    Pop-Location
}

# 2) 管理端 jar（内嵌前端）
Step "构建管理端 jar（内嵌前端）..."
$mvn = "C:\project\nac\tools\apache-maven-3.9.9\bin\mvn.cmd"
if (-not (Test-Path $mvn)) { $mvn = "mvn.cmd" }
Push-Location (Join-Path $root "admin-server")
& $mvn -q -DskipTests package
Pop-Location
$jar = Join-Path $root "admin-server\target\novawaf-admin.jar"
if (-not (Test-Path $jar)) { throw "jar 未生成: $jar" }
Copy-Item $jar (Join-Path $dist "novawaf-admin.jar") -Force
Step "jar: $((Get-Item $jar).Length/1MB) MB"

# 3) 拷贝安装脚本与模板
$win = Join-Path $root "windows"
Copy-Item (Join-Path $win "install.ps1") $dist -Force
Copy-Item (Join-Path $win "novawaf-admin.xml") $dist -Force
Copy-Item (Join-Path $win "application.yml") $dist -Force
Copy-Item (Join-Path $win "start.bat") $dist -Force
Copy-Item (Join-Path $win "stop.bat") $dist -Force
Copy-Item (Join-Path $win "setup.iss") $dist -Force

# 4) WinSW（尝试下载，失败则提示手动放置）
$winsw = Join-Path $dist "winsw.exe"
if (-not (Test-Path $winsw)) {
    Step "下载 WinSW ..."
    $urls = @(
        "https://github.com/winsw/winsw/releases/download/v3.0.0/WinSW-x64.exe",
        "https://ghproxy.com/https://github.com/winsw/winsw/releases/download/v3.0.0/WinSW-x64.exe"
    )
    foreach ($u in $urls) { try { Invoke-WebRequest -Uri $u -OutFile $winsw -UseBasicParsing -TimeoutSec 120; break } catch {} }
}
if (Test-Path $winsw) { Step "WinSW 就绪" } else { Write-Host "  WARN: winsw.exe 缺失，请到 https://github.com/winsw/winsw/releases 下载放入 $dist" -ForegroundColor Yellow }

# 5) 可选：Inno Setup 打包
if (-not $SkipInstaller) {
    $iscc = Get-Command iscc.exe -ErrorAction SilentlyContinue
    if ($iscc) {
        Step "生成 .exe 安装包 ..."
        Push-Location $dist
        & $iscc.Source setup.iss 2>&1 | Out-Null
        Pop-Location
        $out = Get-ChildItem (Join-Path $dist "Output\NovaWAF-Admin-Setup-*.exe") -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($out) { Step "安装包: $($out.FullName) ($([math]::Round($out.Length/1MB,1)) MB)" }
    } else {
        Write-Host "  未检测到 Inno Setup，跳过 .exe 打包。可直接运行 dist-windows\install.ps1 安装。" -ForegroundColor Yellow
    }
}

Step "完成 -> $dist"
Get-ChildItem $dist | Select-Object Name, @{N="MB";E={[math]::Round($_.Length/1MB,2)}}


