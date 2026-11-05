@echo off
REM NovaWAF 管理端 - 控制台启动（非服务模式，便于调试）
REM 用法: start.bat [port]   默认端口 18081
setlocal
set PORT=%1
if "%PORT%"=="" set PORT=18081
cd /d "%~dp0"
if not exist "novawaf-admin.jar" (
  echo [ERROR] novawaf-admin.jar 不在当前目录: %cd%
  exit /b 1
)
echo [NovaWAF] 启动管理控制台 v1.1.2-rc.1, 端口 %PORT% ...
echo [NovaWAF] 配置加载顺序: jar 内置 application.yml -^> config\application.yml -^> 环境变量
java -Xms256m -Xmx1024m -jar novawaf-admin.jar --server.port=%PORT% --spring.config.additional-location=file:%cd%\config\
endlocal
