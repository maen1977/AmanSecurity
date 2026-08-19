#ifndef AppVersion
#define AppVersion "1.1.9"
#endif
#ifndef SourceDir
#define SourceDir "payload"
#endif
#ifndef OutputDir
#define OutputDir "bin"
#endif

#define AppName "Maen Shield"
#define AppPublisher "Maen Shield Project"
#define AppExeName "MaenShield.Windows.exe"
#define AppId "{B7A0E56F-39F7-4E1D-A8DB-0D4B6D5D91C0}"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL=https://github.com/maen1977/AmanSecurity
AppSupportURL=https://github.com/maen1977/AmanSecurity
DefaultDirName={localappdata}\Programs\Maen Shield
DefaultGroupName={#AppName}
DisableProgramGroupPage=no
DisableDirPage=no
PrivilegesRequired=lowest
MinVersion=6.1sp1
ArchitecturesAllowed=x86 x64
ArchitecturesInstallIn64BitMode=x64
OutputDir={#OutputDir}
OutputBaseFilename=MaenShield-{#AppVersion}-Windows-Setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
SetupIconFile={#SourceDir}\MaenShield.ico
UninstallDisplayIcon={app}\{#AppExeName}
Uninstallable=yes
ChangesAssociations=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "arabic"; MessagesFile: "compiler:Languages\Arabic.isl"

[CustomMessages]
english.AdditionalShortcuts=Additional shortcuts:
english.CreateDesktopIcon=Create a desktop shortcut
english.LaunchProgram=Launch Maen Shield
arabic.AdditionalShortcuts=اختصارات إضافية:
arabic.CreateDesktopIcon=إنشاء اختصار على سطح المكتب
arabic.LaunchProgram=تشغيل Maen Shield

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalShortcuts}"; Flags: checkedonce

[Files]
Source: "{#SourceDir}\MaenShield.Windows.exe"; DestDir: "{app}"; Flags: ignoreversion restartreplace
Source: "{#SourceDir}\MaenShield.Core.dll"; DestDir: "{app}"; Flags: ignoreversion restartreplace
Source: "{#SourceDir}\MaenShield.Infrastructure.dll"; DestDir: "{app}"; Flags: ignoreversion restartreplace
Source: "{#SourceDir}\aman-threat-db-public.pem"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{sys}\schtasks.exe"; Parameters: "/Create /SC DAILY /TN ""Maen Shield\Daily Intelligence Update"" /TR """"{app}\{#AppExeName}"" --update-only"" /ST 03:17 /F /RL LIMITED"; Flags: runhidden waituntilterminated
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram}"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""Maen Shield\Daily Intelligence Update"" /F"; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
