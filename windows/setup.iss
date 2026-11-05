; NovaWAF 管理端 Windows 安装包脚本（Inno Setup 6+）
; 用法: iscc setup.iss  -> 生成 Output\NovaWAF-Admin-Setup-1.1.2-rc.1.exe
; 安装包将内嵌 novawaf-admin.jar、WinSW、配置模板与脚本，GUI 安装并注册 Windows 服务。

#define MyAppName "NovaWAF 管理控制台"
#define MyAppVersion "1.1.2-rc.1"
#define MyAppPublisher "NovaWAF"
#define MyAppExeName "winsw.exe"

[Setup]
AppId={{8C1F2A7B-3D9E-4F1A-9B5C-7E2D1A4B6C8F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\NovaWAF\Admin
DefaultGroupName=NovaWAF
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=NovaWAF-Admin-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "service"; Description: "注册为 Windows 服务并开机自启"; GroupDescription: "服务:"; Flags: checkedonce
Name: "firewall"; Description: "放行管理端口防火墙"; GroupDescription: "网络:"; Flags: checkedonce
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "图标:"

[Files]
Source: "novawaf-admin.jar"; DestDir: "{app}"; Flags: ignoreversion
Source: "winsw.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "novawaf-admin.xml"; DestDir: "{app}"; Flags: ignoreversion
Source: "application.yml"; DestDir: "{app}\config"; Flags: onlyifdoesntexist
Source: "start.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "stop.bat"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\NovaWAF 管理控制台"; Filename: "http://localhost:18081/"; IconFilename: "{app}\novawaf-admin.exe"
Name: "{commondesktop}\NovaWAF 管理控制台"; Filename: "http://localhost:18081/"; Tasks: desktopicon

[Run]
; 安装后注册并启动服务
Filename: "{app}\winsw.exe"; Parameters: "install ""{app}\novawaf-admin.xml"""; StatusMsg: "注册 Windows 服务..."; Tasks: service
Filename: "{app}\winsw.exe"; Parameters: "start ""{app}\novawaf-admin.xml"""; StatusMsg: "启动服务..."; Tasks: service
Filename: "netsh.exe"; Parameters: "advfirewall firewall add rule name=""NovaWAF-Admin-18081"" dir=in action=allow protocol=TCP localport=18081"; StatusMsg: "配置防火墙..."; Tasks: firewall; Flags: runhidden

[UninstallRun]
Filename: "{app}\winsw.exe"; Parameters: "stop ""{app}\novawaf-admin.xml"""; Flags: runhidden
Filename: "{app}\winsw.exe"; Parameters: "uninstall ""{app}\novawaf-admin.xml"""; Flags: runhidden

[Code]
// 安装时把 novawaf-admin.xml 与 application.yml 的路径占位符替换为实际安装目录
procedure ReplaceInFile(const FileName, AFrom, ATo: String);
var S: String; L: TStringList;
begin
  if not FileExists(FileName) then Exit;
  L := TStringList.Create;
  try
    L.LoadFromFile(FileName);
    S := L.Text;
    S := StringReplace(S, AFrom, ATo, [rfReplaceAll]);
    L.Text := S;
    L.SaveToFile(FileName);
  finally
    L.Free;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var Dir: String;
begin
  if CurStep = ssPostInstall then begin
    Dir := ExpandConstant('{app}');
    ReplaceInFile(Dir + '\novawaf-admin.xml', '{{INSTALL_DIR}}', Dir);
    ReplaceInFile(Dir + '\novawaf-admin.xml', '{{PORT}}', '18081');
    ReplaceInFile(Dir + '\novawaf-admin.xml', '{{SERVICE_NAME}}', 'NovaWAF-Admin');
  end;
end;
