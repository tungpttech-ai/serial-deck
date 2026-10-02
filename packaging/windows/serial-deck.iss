; Inno Setup script for Serial Deck (per-user install, no admin rights).
; Build:  iscc /DAppVersion=0.2.0 /DSourceDir=..\..\dist\serial-deck [/DSign=1] serial-deck.iss
; With /DSign=1 the `signtool` sign tool must be configured on the iscc command line:
;   iscc "/Ssigntool=signtool.exe sign /f $qcert.pfx$q /p $qPASS$q /fd sha256 /tr http://timestamp.digicert.com /td sha256 $f" ...

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist\serial-deck"
#endif

[Setup]
AppId={{6E3A4C1D-2F7B-4B8E-9C5A-5D1E0F9A7B21}
AppName=Serial Deck
AppVersion={#AppVersion}
AppPublisher=Serial Deck contributors
AppPublisherURL=https://github.com/tungpttech-ai/serial-deck
AppSupportURL=https://github.com/tungpttech-ai/serial-deck/issues
DefaultDirName={localappdata}\Programs\Serial Deck
DefaultGroupName=Serial Deck
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\dist\installer
OutputBaseFilename=SerialDeck-{#AppVersion}-Setup
SetupIconFile=..\icons\serial-deck.ico
UninstallDisplayIcon={app}\serial-deck.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\..\LICENSE
; Running app windows are found by the restart manager; the hub is handled in [Code].
CloseApplications=yes
RestartApplications=no
ChangesEnvironment=yes
#ifdef Sign
SignTool=signtool
SignedUninstaller=yes
#endif

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"
Name: "addtopath"; Description: "Add the serial-deck-cli command to my &PATH"; GroupDescription: "Command line:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Serial Deck"; Filename: "{app}\serial-deck.exe"
Name: "{group}\Uninstall Serial Deck"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Serial Deck"; Filename: "{app}\serial-deck.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; \
  ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\serial-deck.exe"; Description: "Launch Serial Deck"; Flags: nowait postinstall skipifsilent

[Code]
const
  HubNotRunning = 3;
  HubRefused = 4;
  HubTimeout = 5;

function NeedsAddPath(Dir: string): Boolean;
var
  Paths: string;
begin
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', Paths) then
    Paths := '';
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') = 0;
end;

{ Stop this user's shared hub before files are replaced or removed. The hub
  refuses while dashboards are attached or a flash is running; then setup
  stops instead of breaking it. No installed CLI (first install) or no running
  hub means there is nothing to stop. }
function StopHub(const CliPath: string; var Message: string): Boolean;
var
  Code: Integer;
begin
  Result := True;
  if not FileExists(CliPath) then
    exit;
  if not Exec(CliPath, 'hub --shutdown', '', SW_HIDE, ewWaitUntilTerminated, Code) then
  begin
    Message := 'Could not run ' + CliPath + ' to stop the Serial Deck hub.';
    Result := False;
    exit;
  end;
  case Code of
    0, HubNotRunning: Result := True;
    HubRefused:
      begin
        Message := 'Serial Deck is still in use (a dashboard is connected or a flash is running).' + #13#10 +
                   'Close Serial Deck windows, let any flash finish, then try again.';
        Result := False;
      end;
    HubTimeout:
      begin
        Message := 'The Serial Deck hub did not stop in time. Try again in a moment.';
        Result := False;
      end;
  else
    begin
      Message := 'Stopping the Serial Deck hub failed (exit code ' + IntToStr(Code) + ').';
      Result := False;
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Message: string;
begin
  Result := '';
  if not StopHub(ExpandConstant('{app}\serial-deck-cli.exe'), Message) then
    Result := Message;
end;

function InitializeUninstall(): Boolean;
var
  Message: string;
begin
  Result := StopHub(ExpandConstant('{app}\serial-deck-cli.exe'), Message);
  if not Result then
    MsgBox(Message, mbError, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Paths, Dir: string;
  P: Integer;
begin
  if CurUninstallStep <> usPostUninstall then
    exit;
  Dir := ExpandConstant('{app}');
  if RegQueryStringValue(HKCU, 'Environment', 'Path', Paths) then
  begin
    P := Pos(';' + Uppercase(Dir), Uppercase(Paths));
    if P > 0 then
    begin
      Delete(Paths, P, Length(Dir) + 1);
      RegWriteExpandStringValue(HKCU, 'Environment', 'Path', Paths);
    end;
  end;
end;
