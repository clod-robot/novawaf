<#
.SYNOPSIS
  NovaWAF 管理端 Windows 安装器（1.1.2-rc.1）。
.DESCRIPTION
  将内嵌前端的 novawaf-admin.jar 安装为 Windows 服务，开箱即用：
    - 安装目录：C:\Program Files\NovaWAF\Admin（可自定义）
    - 配置文件：<install>\config\application.yml（首次安装由模板生成）
    - Windows 服务：NovaWAF-Admin（基于 WinSW）
    - 防火墙：自动放行服务端口
  前置条件：
    - Windows 10/11 / Server 2016+，PowerShell 5.1+
    - 已安装 JDK 21（java 在 PATH 中，或通过 -JavaHome 指定）
    - 已准备可访问的 MySQL 8+ 与 Redis 6+（本地或远程均可）
  用法（管理员 PowerShell）：
    .\install.ps1 -InstallDir "D:\NovaWAF\Admin"
    .\install.ps1 -Uninstall          # 卸载服务与文件
    .\install.ps1 -DownloadOnly        # 仅下载 WinSW 到当前目录（离线场景）
#>
param(
    [string]$InstallDir = "C:\Program Files\NovaWAF\Admin",
    [string]$JavaHome = "",
    [string]$ServiceName = "NovaWAF-Admin",
    [int]$Port = 18081,
    [string]$MysqlHost = "127.0.0.1",
    [int]$MysqlPort = 3306,
    [string]$MysqlDb = "novawaf_admin",
    [string]$MysqlUser = "novawaf",
    [string]$MysqlPassword = "",
    [string]$RedisHost = "127.0.0.1",
    [int]$RedisPort = 6379,
    [string]$RedisPassword = "",
    [string]$JwtSecret = "",
    [switch]$Uninstall,
    [switch]$DownloadOnly
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProgressPreference = "SilentlyContinue"

function Write-Step($msg) { Write-Host "[NovaWAF] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "  OK  $msg" -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "  FAIL $msg" -ForegroundColor Red }

# 管理员权限校验
if (-not $Uninstall -and -not $DownloadOnly) {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "请以「管理员身份」运行 PowerShell 后再执行安装。"
    }
}

# 仅下载 WinSW（离线部署预下载）
if ($DownloadOnly) {
    $winsw = Join-Path $scriptDir "winsw.exe"
    if (Test-Path $winsw) { Write-Ok "winsw.exe 已存在"; exit 0 }
    Write-Step "下载 WinSW-x64.exe ..."
    $urls = @(
        "https://github.com/winsw/winsw/releases/download/v3.0.0/WinSW-x64.exe",
        "https://ghproxy.com/https://github.com/winsw/winsw/releases/download/v3.0.0/WinSW-x64.exe"
    )
    foreach ($u in $urls) {
        try { Invoke-WebRequest -Uri $u -OutFile $winsw -UseBasicParsing -TimeoutSec 120; break } catch { }
    }
    if (Test-Path $winsw) { Write-Ok "已下载 winsw.exe ($((Get-Item $winsw).Length) 字节)" }
    else { Write-Fail "下载失败，请手动放置 winsw.exe 到 $scriptDir" }
    exit 0
}

# ---------- 卸载 ----------
if ($Uninstall) {
    Write-Step "卸载服务 $ServiceName ..."
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        & (Join-Path $InstallDir "winsw.exe") stop $ServiceName 2>$null
        & (Join-Path $InstallDir "winsw.exe") uninstall $ServiceName 2>$null
        Start-Sleep -Seconds 2
        Write-Ok "服务已卸载"
    }
    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
        Write-Ok "安装目录已删除: $InstallDir"
    }
    Write-Step "卸载完成"
    exit 0
}

# ---------- 安装 ----------
Write-Step "NovaWAF 管理端 v1.1.2-rc.1 安装"

# 1) Java 检查（支持 JAVA_HOME、javapath、PATH 三种形态）
$javaCandidates = @()
if ($JavaHome) {
    $javaCandidates += (Join-Path $JavaHome "bin\java.exe")
    $javaCandidates += (Join-Path $JavaHome "java.exe")
} else {
    if ($env:JAVA_HOME) {
        $javaCandidates += (Join-Path $env:JAVA_HOME "bin\java.exe")
    }
    $javaCandidates += "java"
}
$java = $null
$oldEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
foreach ($c in $javaCandidates) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    $javaExe = $cmd.Source
    try {
        $v = (& $javaExe -version 2>&1 | Out-String)
        if ($v -match 'version') {
            $java = $javaExe
            $firstLine = ($v -split "`r?`n")[0].Trim()
            Write-Ok "Java: $firstLine"
            break
        }
    } catch { }
}
$ErrorActionPreference = $oldEap
if (-not $java) {
    throw "未找到 java，请安装 JDK 21，或通过 -JavaHome 指定 JDK 根目录（含 bin\java.exe）。"
}

# 2) 查找 jar
$jar = Get-ChildItem -Path $scriptDir -Filter "novawaf-admin*.jar" | Select-Object -First 1
if (-not $jar) { throw "未找到 novawaf-admin*.jar，请将 jar 与本脚本放在同一目录。" }
Write-Ok "安装包: $($jar.Name) ($([math]::Round($jar.Length/1MB,1)) MB)"

# 3) 创建目录
New-Item -ItemType Directory -Force -Path $InstallDir, (Join-Path $InstallDir "config"), `
    (Join-Path $InstallDir "logs") | Out-Null
Write-Ok "安装目录: $InstallDir"

# 4) 复制 jar + WinSW
Copy-Item $jar.FullName (Join-Path $InstallDir "novawaf-admin.jar") -Force
$winswSrc = Join-Path $scriptDir "winsw.exe"
if (-not (Test-Path $winswSrc)) {
    Write-Step "下载 WinSW ..."
    $urls = @(
        "https://github.com/winsw/winsw/releases/download/v3.0.0/WinSW-x64.exe",
        "https://ghproxy.com/https://github.com/winsw/winsw/releases/download/v3.0.0/WinSW-x64.exe"
    )
    foreach ($u in $urls) { try { Invoke-WebRequest -Uri $u -OutFile $winswSrc -UseBasicParsing -TimeoutSec 120; break } catch {} }
}
if (Test-Path $winswSrc) {
    Copy-Item $winswSrc (Join-Path $InstallDir "winsw.exe") -Force
    Write-Ok "WinSW 就绪"
} else {
    Write-Fail "WinSW 下载失败，服务模式不可用。可使用 start.bat 手动启动。"
}

# 5) 生成 application.yml（若不存在）
$cfgPath = Join-Path $InstallDir "config\application.yml"
if (-not (Test-Path $cfgPath)) {
    if (-not $MysqlPassword) { $MysqlPassword = Read-Host "请输入 MySQL 密码($MysqlUser@$MysqlHost)" -AsSecureString | ForEach-Object { [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($_)) } }
    if (-not $JwtSecret)    { $JwtSecret = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 40 | ForEach-Object { [char]$_ }) }
    $tpl = Get-Content (Join-Path $scriptDir "application.yml") -Raw
    foreach ($k in @{
        "{{MYSQL_HOST}}"=$MysqlHost; "{{MYSQL_PORT}}"=$MysqlPort; "{{MYSQL_DB}}"=$MysqlDb;
        "{{MYSQL_USER}}"=$MysqlUser; "{{MYSQL_PASSWORD}}"=$MysqlPassword;
        "{{REDIS_HOST}}"=$RedisHost; "{{REDIS_PORT}}"=$RedisPort; "{{REDIS_PASSWORD}}"=$RedisPassword;
        "{{JWT_SECRET}}"=$JwtSecret
    }.GetEnumerator()) { $tpl = $tpl.Replace($k.Key, $k.Value) }
    Set-Content -Path $cfgPath -Value $tpl -Encoding UTF8
    Write-Ok "配置已生成: $cfgPath"
} else {
    Write-Ok "保留已有配置: $cfgPath"
}

# 6) WinSW 服务描述符
$xml = Get-Content (Join-Path $scriptDir "novawaf-admin.xml") -Raw
$xml = $xml.Replace("{{INSTALL_DIR}}", $InstallDir).Replace("{{PORT}}", $Port).Replace("{{SERVICE_NAME}}", $ServiceName).Replace("{{JAVA_EXE}}", $java)
Set-Content -Path (Join-Path $InstallDir "novawaf-admin.xml") -Value $xml -Encoding UTF8

# 7) 注册并启动服务
if (Test-Path (Join-Path $InstallDir "winsw.exe")) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        & (Join-Path $InstallDir "winsw.exe") install (Join-Path $InstallDir "novawaf-admin.xml") | Out-Null
        Write-Ok "服务 $ServiceName 已注册"
    }
    & (Join-Path $InstallDir "winsw.exe") start (Join-Path $InstallDir "novawaf-admin.xml") | Out-Null
    Start-Sleep -Seconds 8
    $state = (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status
    Write-Ok "服务状态: $state"
}

# 8) 防火墙放行
try {
    if (-not (Get-NetFirewallRule -DisplayName "NovaWAF-Admin-$Port" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "NovaWAF-Admin-$Port" -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $Port | Out-Null
        Write-Ok "防火墙已放行 TCP $Port"
    }
} catch { Write-Host "  跳过防火墙规则(需管理员)" -ForegroundColor Yellow }

Write-Step "安装完成"
Write-Host "  控制台地址: http://localhost:$Port/"
Write-Host "  初始账号:   admin / Admin@2026"
Write-Host "  服务管理:   Start-Service/Stop-Service $ServiceName"




