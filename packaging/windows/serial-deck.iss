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
; Remember that this installer added the PATH entry, so uninstall removes only that.
Root: HKCU; Subkey: "Software\Serial Deck"; ValueType: dword; ValueName: "AddedToPath"; ValueData: 1; \
  Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}')); Flags: uninsdeletekey

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

{ Any process still running from the install directory: a Serial Deck window, a
  hub on a custom socket, an MCP server. Files cannot be replaced under them. }
function RunningFromApp(const Dir: string; var Names: string): Boolean;
var
  Locator, Service, Items, Item: Variant;
  I: Integer;
  Path: string;
begin
  Result := False;
  Names := '';
  try
    Locator := CreateOleObject('WbemScripting.SWbemLocator');
    Service := Locator.ConnectServer('.', 'root\CIMV2');
    Items := Service.ExecQuery('SELECT ProcessId, ExecutablePath FROM Win32_Process');
    for I := 0 to Items.Count - 1 do
    begin
      Item := Items.ItemIndex(I);
      if VarIsNull(Item.ExecutablePath) then
        continue;
      Path := Item.ExecutablePath;
      if Pos(Uppercase(AddBackslash(Dir)), Uppercase(Path)) = 1 then
      begin
        Result := True;
        Names := Names + #13#10 + '  ' + ExtractFileName(Path) + ' (pid ' + IntToStr(Item.ProcessId) + ')';
      end;
    end;
  except
    { WMI unavailable: fall back to the hub check alone. }
  end;
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

{ Stop the idle default hub, then refuse if anything else still runs from {app}. }
function ReadyToChange(const Dir: string; var Message: string): Boolean;
var
  Names: string;
begin
  Result := StopHub(Dir + '\serial-deck-cli.exe', Message);
  if not Result then
    exit;
  if RunningFromApp(Dir, Names) then
  begin
    Message := 'Close Serial Deck first. These programs are still running from ' + Dir + ':' + Names;
    Result := False;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Message: string;
begin
  Result := '';
  if not ReadyToChange(ExpandConstant('{app}'), Message) then
    Result := Message;
end;

function InitializeUninstall(): Boolean;
var
  Message: string;
begin
  Result := ReadyToChange(ExpandConstant('{app}'), Message);
  if not Result then
    MsgBox(Message, mbError, MB_OK);
end;

{ Remove exactly the PATH entry this installer added: whole ';'-separated
  entries equal to {app}, and only if we recorded adding it. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Paths, Dir, Entry, Kept: string;
  Added: Cardinal;
  P: Integer;
begin
  if CurUninstallStep <> usUninstall then
    exit;
  if not RegQueryDWordValue(HKCU, 'Software\Serial Deck', 'AddedToPath', Added) or (Added <> 1) then
    exit;
  Dir := Uppercase(RemoveBackslash(ExpandConstant('{app}')));
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', Paths) then
    exit;
  Kept := '';
  Paths := Paths + ';';
  repeat
    P := Pos(';', Paths);
    Entry := Copy(Paths, 1, P - 1);
    Delete(Paths, 1, P);
    if (Entry <> '') and (Uppercase(RemoveBackslash(Entry)) <> Dir) then
    begin
      if Kept <> '' then
        Kept := Kept + ';';
      Kept := Kept + Entry;
    end;
  until Paths = '';
  RegWriteExpandStringValue(HKCU, 'Environment', 'Path', Kept);
end;
