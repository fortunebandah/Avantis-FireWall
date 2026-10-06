#define MyAppName "Avantis FireWall"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Avantis"
#define MyAppExeName "Avantis FireWall.exe"

[Setup]
AppId={{8D95F74C-80E0-4DAA-BD16-8B8079227DE6}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\Avantis FireWall
DefaultGroupName=Avantis FireWall
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
OutputDir=..\dist\installer
OutputBaseFilename=AvantisFireWall-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\Images\avantis-app.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=yes
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "..\dist\Avantis FireWall\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Avantis FireWall"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Avantis FireWall"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Avantis FireWall"; Flags: postinstall nowait skipifsilent
