# NovaWAF release pipeline: build -> deploy -> tag -> GitHub Release (UTF-8 safe)
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/release.ps1                 # full pipeline
#   ... -NotesOnly                                                             # only fix/create release notes for current VERSION tag
#   ... -SkipBuild -SkipGit                                                    # release from existing staging artifacts
# Required env for build/deploy stages:
#   NOVA_SSH_PASS   server password (user/host via -SshUser/-SshHost)
# GitHub token: env NOVA_GH_TOKEN first, else git credential fill (same creds as git push).
# Note: PS pipe to native stdin breaks under `powershell -File`, so use Start-Process redirection.
param(
    [string]$Version,                          # default: read repo VERSION file
    [string]$SshHost = '192.168.100.2',
    [string]$SshUser = 'mao',
    [switch]$NotesOnly,                        # only publish/update release body + keep assets untouched
    [switch]$SkipBuild,                        # skip server build + artifact pull (reuse staging dir)
    [switch]$SkipGit,                          # skip commit/tag/push
    [switch]$SkipDeploy                        # build artifacts but do not restart services
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$ghRepo = 'clod-robot/novawaf'
$stage = Join-Path $repo 'release-staging'

# ---------- 0. version ----------
if (-not $Version) { $Version = ([IO.File]::ReadAllText((Join-Path $repo 'VERSION'), [Text.Encoding]::UTF8)).Trim() }
$tag = "v$Version"
$isPre = $Version -match '-'
Write-Host "[0] version=$Version tag=$tag prerelease=$isPre"

function Assert-VersionSync {
    $pom = [IO.File]::ReadAllText((Join-Path $repo 'admin-server\pom.xml'), [Text.Encoding]::UTF8)
    $pkg = [IO.File]::ReadAllText((Join-Path $repo 'admin-web\package.json'), [Text.Encoding]::UTF8)
    $eng = [IO.File]::ReadAllText((Join-Path $repo 'engine\src\main.cpp'), [Text.Encoding]::UTF8)
    $q = [char]34
    if (-not $pom.Contains('<version>' + $Version + '</version>'))            { throw "pom.xml version mismatch, expect $Version" }
    if (-not $pkg.Contains($q + 'version' + $q + ': ' + $q + $Version + $q)) { throw "package.json version mismatch, expect $Version" }
    if (-not $eng.Contains('NOVAWAF_VERSION ' + $q + $Version + $q))         { throw "main.cpp NOVAWAF_VERSION mismatch, expect $Version" }
    Write-Host "[0] version sync OK (VERSION/pom/package.json/main.cpp)"
}
Assert-VersionSync

# ---------- 1. GitHub token ----------
$ghToken = $env:NOVA_GH_TOKEN
if (-not $ghToken) {
    $reqFile = Join-Path $env:TEMP 'novawaf_ghcred_req.txt'
    $outFile = Join-Path $env:TEMP 'novawaf_ghcred_out.txt'
    [IO.File]::WriteAllText($reqFile, "protocol=https`nhost=github.com`n`n")
    $null = Start-Process git -ArgumentList 'credential','fill' -RedirectStandardInput $reqFile -RedirectStandardOutput $outFile -NoNewWindow -Wait -PassThru
    $credOut = [IO.File]::ReadAllText($outFile)
    Remove-Item $reqFile,$outFile -Force -ErrorAction SilentlyContinue
    $ghToken = ((($credOut -split "`n") | Where-Object { $_ -like 'password=*' }) -replace '^password=','').Trim()
}
if (-not $ghToken) { throw 'github token not found (set env NOVA_GH_TOKEN or configure git credential helper)' }
$ghHdr = @{ Authorization = "Bearer $ghToken"; 'User-Agent' = 'novawaf-release'; Accept = 'application/vnd.github+json' }
function Invoke-GhJson($method, $url, $obj) {
    $json = $obj | ConvertTo-Json -Depth 6
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)   # UTF-8 body, fixes mojibake
    Invoke-RestMethod -Method $method -Uri $url -Headers $ghHdr -Body $bytes -ContentType 'application/json; charset=utf-8'
}

if (-not $NotesOnly) {

    # ---------- 2. build on server + pull artifacts ----------
    if (-not $SkipBuild) {
        $sshPass = $env:NOVA_SSH_PASS
        if (-not $sshPass) { throw 'env:NOVA_SSH_PASS required for build stage' }
        Import-Module Posh-SSH -ErrorAction Stop
        $cred = New-Object Management.Automation.PSCredential($SshUser, (ConvertTo-SecureString $sshPass -AsPlainText -Force))
        $s  = New-SSHSession  -ComputerName $SshHost -Credential $cred -AcceptKey -ConnectionTimeout 10
        $sf = New-SFTPSession -ComputerName $SshHost -Credential $cred -AcceptKey -ConnectionTimeout 10

        # push sources (engine + admin-server + pom)
        Set-SFTPItem -SessionId $sf.SessionId -Path (Join-Path $repo 'engine\src\main.cpp') -Destination '/home/mao/novawaf/engine/src' -Force
        Set-SFTPItem -SessionId $sf.SessionId -Path (Join-Path $repo 'admin-server\pom.xml') -Destination '/home/mao/novawaf/admin-server' -Force
        Get-ChildItem (Join-Path $repo 'engine\include') -Recurse -Filter *.h | ForEach-Object {
            $rel = $_.FullName.Substring((Join-Path $repo 'engine\include').Length).Replace('\', '/')
            $dst = "/home/mao/novawaf/engine/include$rel"
            $dir = $dst.Substring(0, $dst.LastIndexOf('/'))
            New-SFTPItem -SessionId $sf.SessionId -Path $dir -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
            Set-SFTPItem -SessionId $sf.SessionId -Path $_.FullName -Destination $dir -Force
        }
        Get-ChildItem (Join-Path $repo 'admin-server\src') -Recurse -Filter *.java | ForEach-Object {
            $rel = $_.FullName.Substring((Join-Path $repo 'admin-server\src').Length).Replace('\', '/')
            $dst = "/home/mao/novawaf/admin-server/src$rel"
            $dir = $dst.Substring(0, $dst.LastIndexOf('/'))
            New-SFTPItem -SessionId $sf.SessionId -Path $dir -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
            Set-SFTPItem -SessionId $sf.SessionId -Path $_.FullName -Destination $dir -Force
        }
        Write-Host '[2] sources uploaded'

        $r = Invoke-SSHCommand -SessionId $s.SessionId -TimeOut 600 -Command 'cd /home/mao/novawaf/engine && g++ -std=c++20 -O2 -Wno-unused-parameter -pthread -I include src/main.cpp -o /tmp/novawaf-engine.new -ldl -lyara -lnghttp2 -lngtcp2 -lngtcp2_crypto_ossl -lnghttp3 -lssl -lcrypto -rdynamic 2>&1 | tail -10 && cd /home/mao/novawaf/admin-server && mvn -q package -DskipTests 2>&1 | tail -4 && echo BUILD_OK'
        $r.Output | ForEach-Object { Write-Host $_ }
        if ($r.Output -notcontains 'BUILD_OK') { throw 'server build failed' }
        Write-Host '[2] server build OK (engine + admin jar)'

        if (-not $SkipDeploy) {
            # 版本化零停机部署：ops 脚本/sudoers/systemd 单元就位 → 安装新版本 →
            # 已迁移过(current 符号链接存在)走 activate 滚动切换；首迁走 bootstrap。
            Set-SFTPItem -SessionId $sf.SessionId -Path (Join-Path $repo 'scripts\engine_ops.sh') -Destination '/home/mao' -Force
            Set-SFTPItem -SessionId $sf.SessionId -Path (Join-Path $repo 'deploy\systemd\novawaf-ops.sudoers') -Destination '/home/mao' -Force
            Set-SFTPItem -SessionId $sf.SessionId -Path (Join-Path $repo 'deploy\systemd\novawaf-engine.service') -Destination '/home/mao' -Force
            $deploy = @'
set -e
echo "$SUDOPW" | sudo -S -p '' mkdir -p /opt/novawaf/bin /opt/novawaf/run /opt/novawaf/engine/versions /opt/novawaf/engine/uploads
echo "$SUDOPW" | sudo -S -p '' chown mao:mao /opt/novawaf/engine/uploads
echo "$SUDOPW" | sudo -S -p '' install -m 0755 -o root -g root /home/mao/engine_ops.sh /opt/novawaf/bin/engine_ops.sh
echo "$SUDOPW" | sudo -S -p '' install -m 0440 -o root -g root /home/mao/novawaf-ops.sudoers /etc/sudoers.d/novawaf-ops
cp /tmp/novawaf-engine.new /opt/novawaf/engine/uploads/release.bin
chmod 755 /opt/novawaf/engine/uploads/release.bin
VER=$(/opt/novawaf/engine/uploads/release.bin --version | head -n1)
echo "release version: $VER"
echo "$SUDOPW" | sudo -S -p '' /opt/novawaf/bin/engine_ops.sh install /opt/novawaf/engine/uploads/release.bin
if [ -L /opt/novawaf/engine/current ]; then
  echo "$SUDOPW" | sudo -S -p '' /opt/novawaf/bin/engine_ops.sh activate "$VER"
else
  # 首次迁移：建立 current 符号链接，换装 master/worker 监管单元
  echo "$SUDOPW" | sudo -S -p '' ln -sfn /opt/novawaf/engine/versions/$VER/novawaf-engine /opt/novawaf/engine/current
  echo "$SUDOPW" | sudo -S -p '' install -m 0644 -o root -g root /home/mao/novawaf-engine.service /etc/systemd/system/novawaf-engine.service
  echo "$SUDOPW" | sudo -S -p '' systemctl daemon-reload
  echo "$SUDOPW" | sudo -S -p '' systemctl restart novawaf-engine
  sleep 5
fi
echo "$SUDOPW" | sudo -S -p '' systemctl restart novawaf-admin
sleep 6
systemctl is-active novawaf-engine
systemctl is-active novawaf-admin
echo DEPLOY_OK
'@.Replace('$SUDOPW', $sshPass)
            $d = Invoke-SSHCommand -SessionId $s.SessionId -TimeOut 180 -Command $deploy
            $d.Output | ForEach-Object { Write-Host $_ }
            if ($d.Output -notcontains 'DEPLOY_OK') { throw 'deploy failed' }
            Write-Host '[2] services restarted'
        }

        # artifacts
        New-Item -ItemType Directory -Force -Path $stage | Out-Null
        Get-SFTPItem -SessionId $sf.SessionId -Path '/tmp/novawaf-engine.new' -Destination $stage -Force
        Get-SFTPItem -SessionId $sf.SessionId -Path '/home/mao/novawaf/admin-server/target/novawaf-admin.jar' -Destination $stage -Force
        Remove-SFTPSession -SessionId $sf.SessionId | Out-Null
        Remove-SSHSession  -SessionId $s.SessionId  | Out-Null

        # frontend package (vite build must already exist in admin-web/dist)
        if (-not (Test-Path (Join-Path $repo 'admin-web\dist\index.html'))) {
            Push-Location (Join-Path $repo 'admin-web'); npm run build | Out-Host; Pop-Location
        }
        tar -czf (Join-Path $stage "novawaf-admin-web_$Version.tar.gz") -C (Join-Path $repo 'admin-web') dist
        Move-Item (Join-Path $stage 'novawaf-engine')     (Join-Path $stage "novawaf-engine_$Version`_linux_amd64") -Force
        Move-Item (Join-Path $stage 'novawaf-admin.jar')  (Join-Path $stage "novawaf-admin_$Version.jar")          -Force
        Write-Host "[2] artifacts staged at $stage"
    }

    # ---------- 3. git commit + tag + push ----------
    if (-not $SkipGit) {
        git -C $repo add VERSION admin-server/pom.xml admin-web/package.json engine/src/main.cpp scripts | Out-Null
        $pending = git -C $repo status --porcelain
        if ($pending) {
            git -C $repo commit -m "chore(release): $tag" | Out-Host
        }
        if (-not (git -C $repo tag -l $tag)) {
            git -C $repo tag -a $tag -m "NovaWAF $tag" | Out-Host
        }
        git -C $repo push origin main --follow-tags | Out-Host
        Write-Host '[3] git pushed with tag'
    }
}

# ---------- 4. GitHub release (idempotent: create or update) ----------
$notesTpl = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'release_notes.template.md'), [Text.Encoding]::UTF8)
$preText = if ($isPre) { '预发布版（Release Candidate）。' } else { '正式版。' }
$notes = $notesTpl.Replace('{{VERSION}}', $Version).Replace('{{TAG}}', $tag).Replace('{{PRERELEASE_TEXT}}', $preText)

$existing = $null
try { $existing = Invoke-RestMethod -Uri "https://api.github.com/repos/$ghRepo/releases/tags/$tag" -Headers $ghHdr } catch {}
if ($existing) {
    $rel = Invoke-GhJson 'Patch' "https://api.github.com/repos/$ghRepo/releases/$($existing.id)" @{
        name = "NovaWAF $tag"; body = $notes; prerelease = $isPre
    }
    Write-Host "[4] release updated id=$($rel.id)"
} else {
    $rel = Invoke-GhJson 'Post' "https://api.github.com/repos/$ghRepo/releases" @{
        tag_name = $tag; name = "NovaWAF $tag"; body = $notes; prerelease = $isPre; draft = $false
    }
    Write-Host "[4] release created id=$($rel.id)"
}
Write-Host "    $($rel.html_url)"

# ---------- 5. assets upload (replace same-name) ----------
if (-not $NotesOnly -and (Test-Path $stage)) {
    $uploadBase = $rel.upload_url -replace '\{\?name,label\}', ''
    Get-ChildItem $stage | ForEach-Object {
        $f = $_
        $dup = $rel.assets | Where-Object { $_.name -eq $f.Name }
        if ($dup) {
            Invoke-RestMethod -Method Delete -Uri "https://api.github.com/repos/$ghRepo/releases/assets/$($dup.id)" -Headers $ghHdr | Out-Null
        }
        Invoke-RestMethod -Method Post -Uri "${uploadBase}?name=$($f.Name)" -Headers $ghHdr -InFile $f.FullName -ContentType 'application/octet-stream' | Out-Null
        Write-Host "[5] asset uploaded: $($f.Name)"
    }
}
Write-Host 'RELEASE_DONE'
