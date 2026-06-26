#define MyAppName "Hasher"
#ifndef MyAppVersion
  #define MyAppVersion "0.2.0"
#endif
#define MyAppPublisher "Hasher"
#define MyAppExeName "hasher.exe"

[Setup]
AppId={{A0932EC9-EAC4-498B-949D-6D47C67526C8}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Hasher
DefaultGroupName=Hasher
OutputDir=..\..\dist\windows
OutputBaseFilename=Hasher-{#MyAppVersion}-setup
SetupIconFile=..\..\assets\hasher-icon.ico
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequiredOverridesAllowed=dialog
WizardStyle=modern

[Files]
Source: "..\..\target\release\hasher.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\target\release\hasher-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\assets\OFL.txt"; DestDir: "{app}"; DestName: "JetBrainsMono-OFL.txt"; Flags: ignoreversion
Source: "..\..\assets\hasher-icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Hasher"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\hasher-icon.ico"
Name: "{autodesktop}\Hasher"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\hasher-icon.ico"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Hasher"; Flags: nowait postinstall skipifsilent
