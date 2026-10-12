// NovaWAF 自建 YARA 规则库 —— 基础规则集（防御性检测特征）
// 覆盖：可执行文件上传、Office 宏候选、脚本恶意模式、勒索提示、加壳标记等。
// 可随时在本目录新增/修改 *.yar 文件，引擎按 mtime 热加载。

rule Executable_PE {
  meta:
    description = "Windows PE 可执行文件（MZ 头）"
    category = "trojan/file"
  condition:
    uint16(0) == 0x5A4D
}

rule Executable_ELF {
  meta:
    description = "Linux ELF 可执行文件"
    category = "trojan/file"
  condition:
    uint32(0) == 0x464C457F
}

rule Office_Macro_Candidate {
  meta:
    description = "OLE2 Office 文档，含 VBA/宏特征"
    category = "macro"
  strings:
    $m1 = "Attributed" ascii wide
    $m2 = "_VBA_PROJECT" ascii wide
    $m3 = "ThisDocument" ascii wide
    $m4 = "VBA" ascii wide
    $m5 = "Macros" ascii wide
  condition:
    uint32(0) == 0xE011CFD0 and any of them
}

rule Script_Powershell_DownloadCradle {
  meta:
    description = "PowerShell 下载执行木马常见关键字组合"
    category = "trojan/script"
  strings:
    $a = "IEX" nocase
    $b = "DownloadString" nocase
    $c = "Invoke-Expression" nocase
    $d = "FromBase64String" nocase
    $e = "Net.WebClient" nocase
  condition:
    2 of them
}

rule Script_Com_Automation {
  meta:
    description = "脚本中使用 COM 自动化（常见于木马下载者）"
    category = "trojan/script"
  strings:
    $a = "WScript.Shell" nocase
    $b = "Scripting.FileSystemObject" nocase
    $c = "GetObject(" nocase
    $d = "CreateObject(" nocase
    $e = "Shell.Application" nocase
  condition:
    2 of them
}

rule Ransom_Note_Marker {
  meta:
    description = "勒索提示文本特征"
    category = "ransomware"
  strings:
    $a = "your files have been encrypted" nocase
    $b = "decrypt" nocase
    $c = ".onion" nocase
    $d = "bitcoin" nocase
    $e = "pay" nocase
  condition:
    2 of them
}

rule Packer_UPX {
  meta:
    description = "UPX 加壳标记（常见于免杀木马）"
    category = "packer"
  strings:
    $a = "UPX0"
    $b = "UPX1"
    $c = "UPX!"
  condition:
    any of them
}
