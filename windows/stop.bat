@echo off
REM 停止当前目录下由 start.bat 启动的 NovaWAF 管理端进程
for /f "tokens=2" %%a in ('tasklist /FI "WINDOWTITLE eq NovaWAF*" /NH 2^>nul') do taskkill /PID %%a /F >nul 2>&1
REM 兜底：按命令行匹配 novawaf-admin.jar
wmic process where "commandline like '%%novawaf-admin.jar%%'" call terminate >nul 2>&1
echo [NovaWAF] 已发送停止信号
