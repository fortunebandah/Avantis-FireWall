#define MyAppName "Avantis FireWall"
#define MyAppVersion "1.1.3"
#define MyAppPublisher "Avantis"
#define MyAppExeName "Avantis FireWall.exe"
#define AgentExeName "Agent\Avantis Agent Service.exe"

[Setup]
AppId={{8D95F74C-80E0-4DAA-BD16-8B8079227DE6}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Avantis FireWall
UsePreviousAppDir=no
DefaultGroupName=Avantis FireWall
DisableProgramGroupPage=yes
PrivilegesRequired=admin
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
Source: "..\dist\Avantis Agent Service\*"; DestDir: "{app}\Agent"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Avantis FireWall"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Avantis FireWall"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Avantis FireWall"; Flags: postinstall nowait skipifsilent runasoriginaluser

[Code]
var
  EnrollmentPage: TInputQueryWizardPage;

function HasSavedDeviceCredential: Boolean;
begin
  Result := FileExists(ExpandConstant('{commonappdata}\Avantis FireWall\agent\device-credential.dpapi'));
end;

procedure InitializeWizard;
begin
  EnrollmentPage := CreateInputQueryPage(wpSelectDir,
    'Connect this PC to Avantis Central',
    'Enter a one-time code created by your Avantis Central administrator.',
    'The code is used once to register this PC. It is not saved in the installed application.');
  EnrollmentPage.Add('One-time enrollment code:', True);
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = EnrollmentPage.ID) and HasSavedDeviceCredential;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = EnrollmentPage.ID) and (Trim(EnrollmentPage.Values[0]) = '') then
  begin
    MsgBox('Enter the one-time enrollment code supplied by your Avantis Central administrator.', mbError, MB_OK);
    Result := False;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  AgentExe: String;
  ResultCode: Integer;
  LegacyAgentExe: String;
begin
  Result := '';
  AgentExe := ExpandConstant('{app}\{#AgentExeName}');
  if FileExists(AgentExe) then
  begin
    if not Exec(AgentExe, '--stop-service', ExpandConstant('{app}\Agent'), SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      Result := 'Avantis Central could not be stopped before updating. Restart Windows and run the installer again.'
    else if ResultCode <> 0 then
      Result := 'Avantis Central could not be stopped before updating. Restart Windows and run the installer again.';
  end
  else
  begin
    LegacyAgentExe := ExpandConstant('{app}\Avantis Agent Service.exe');
    if FileExists(LegacyAgentExe) then
    begin
      if not Exec(ExpandConstant('{sys}\sc.exe'), 'stop AvantisCentralAgent', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) then
        Result := 'The existing Avantis Central service could not be stopped before updating.'
      else if (ResultCode <> 0) and (ResultCode <> 1060) and (ResultCode <> 1062) then
        Result := 'The existing Avantis Central service could not be stopped before updating. Restart Windows and try again.';
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  AgentExe: String;
  EnrollmentFile: String;
  Parameters: String;
  ResultCode: Integer;
  Started: Boolean;
begin
  if CurStep = ssPostInstall then
  begin
    AgentExe := ExpandConstant('{app}\{#AgentExeName}');
    Parameters := '--install';
    EnrollmentFile := '';
    if not HasSavedDeviceCredential then
    begin
      EnrollmentFile := ExpandConstant('{tmp}\avantis-enrollment-code.txt');
      if not SaveStringToFile(EnrollmentFile, Trim(EnrollmentPage.Values[0]) + #13#10, False) then
        RaiseException('The temporary enrollment code file could not be created.');
      Parameters := Parameters + ' --enrollment-code-file "' + EnrollmentFile + '"';
    end;
    Started := Exec(AgentExe, Parameters, ExpandConstant('{app}\Agent'), SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if EnrollmentFile <> '' then
      DeleteFile(EnrollmentFile);
    if not Started then
      RaiseException('The Avantis Central service could not be started. Check that this installer is running with administrator approval.');
    if ResultCode <> 0 then
      RaiseException('Avantis could not connect this PC to Central. Confirm the code and internet access, then run the installer again.');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  AgentExe: String;
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    AgentExe := ExpandConstant('{app}\{#AgentExeName}');
    if FileExists(AgentExe) then
    begin
      if not Exec(AgentExe, '--uninstall', ExpandConstant('{app}\Agent'), SW_HIDE, ewWaitUntilTerminated, ResultCode) then
        RaiseException('Avantis Central could not be stopped. The application files were not removed.');
      if ResultCode <> 0 then
        RaiseException('Avantis could not remove its Central service and restore the hosts file. The application files were not removed.');
    end;
  end;
end;
