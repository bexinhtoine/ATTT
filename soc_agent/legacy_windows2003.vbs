' Lab connector for Windows Server 2003 using WMI and MSXML already installed.
' Run: cscript //nologo legacy_windows2003.vbs http://SOC_IP:5000 TOKEN
' State lives beside this script. Do not copy state between hosts.
Option Explicit
Dim fso, root, svc, shell, host, ip, server, token, key, logPath, channels, ch
Dim osName, item, result, rx, matches, once, n
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(WScript.ScriptFullName)
logPath = root & "\legacy-agent.log"
Set shell = CreateObject("WScript.Shell")
Set svc = GetObject("winmgmts:{impersonationLevel=impersonate,(Security)}!\\.\root\cimv2")
host = shell.ExpandEnvironmentStrings("%COMPUTERNAME%")
server = "http://192.168.1.201:5000"
token = ""
once = False
If WScript.Arguments.Count > 0 Then server = WScript.Arguments(0)
If WScript.Arguments.Count > 1 Then token = WScript.Arguments(1)
If WScript.Arguments.Count > 2 Then once = (WScript.Arguments(2) = "--once")
ip = ""
For Each item In svc.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True")
  If Not IsNull(item.IPAddress) Then
    For Each n In item.IPAddress
      If InStr(n, ":") = 0 Then ip = n
    Next
  End If
Next
osName = "Windows Server 2003"
For Each item In svc.ExecQuery("SELECT Caption FROM Win32_OperatingSystem")
  osName = item.Caption
Next
key = ReadText(root & "\legacy-api-key.txt", "")
If key = "" Then
  If token = "" Then
    Log "ERROR Missing enrollment token"
    WScript.Quit 1
  End If
  result = Post("/api/v1/agents/register", "{""hostname"":" & Q(host) & ",""enrollment_token"":" & Q(token) & ",""os_type"":""windows"",""os_version"":" & Q(osName) & ",""ip_address"":" & Q(ip) & ",""agent_version"":""legacy-lab-1.1"",""collectors"":[{""type"":""wmi"",""name"":""legacy-eventlog""}]}")
  If result = "" Then WScript.Quit 2
  Set rx = New RegExp
  rx.Pattern = """api_key""\s*:\s*""([^""]+)"""
  Set matches = rx.Execute(result)
  If matches.Count = 0 Then
    Log "ERROR Registration failed; inspect HTTP status above"
    WScript.Quit 3
  End If
  key = matches(0).SubMatches(0)
  WriteText root & "\legacy-api-key.txt", key
  Log "REGISTERED host=" & host & " ip=" & ip & " os=" & osName
End If
channels = Array("System", "Application", "Security")
Do
  For Each ch In channels
    CollectChannel ch
  Next
  result = Post("/api/v1/agents/heartbeat", "{""agent_version"":""legacy-lab-1.1"",""ip_address"":" & Q(ip) & ",""metrics"":{""legacy_channel_count"":3},""collectors"":[{""type"":""wmi"",""name"":""legacy-eventlog""}]}")
  If result <> "" Then Log "HEARTBEAT OK"
  If once Then Exit Do
  WScript.Sleep 10000
Loop

Sub CollectChannel(channel)
  Dim cursorFile, cursor, last, records, e, numbers(), entries(), count, i, j, tmp, obj
  Dim dt, ts, action, outcome, severity, category, body, accepted
  Dim countFile, currentCount, priorCount, fileInfo, generationFile, generation
  cursorFile = root & "\legacy-" & channel & ".cursor"
  cursor = CDbl(ReadText(cursorFile, "-1"))
  countFile = root & "\legacy-" & channel & ".count"
  generationFile = root & "\legacy-" & channel & ".generation"
  generation = CLng(ReadText(generationFile, "0"))
  priorCount = CDbl(ReadText(countFile, "-1"))
  currentCount = -1
  On Error Resume Next
  For Each fileInfo In svc.ExecQuery("SELECT NumberOfRecords FROM Win32_NTEventLogFile WHERE LogFileName='" & channel & "'")
    currentCount = CDbl(fileInfo.NumberOfRecords)
  Next
  If Err.Number <> 0 Then
    Log "ERROR WMI log metadata " & channel & ": " & Err.Description
    Err.Clear
    Exit Sub
  End If
  If cursor >= 0 And (priorCount < 0 Or (currentCount >= 0 And currentCount < priorCount)) Then
    last = 0
    For Each e In svc.ExecQuery("SELECT RecordNumber FROM Win32_NTLogEvent WHERE Logfile='" & channel & "'")
      If CDbl(e.RecordNumber) > last Then last = CDbl(e.RecordNumber)
    Next
    If Err.Number <> 0 Then
      Log "ERROR WMI reset check " & channel & ": " & Err.Description
      Err.Clear
      Exit Sub
    End If
    If last < cursor Then
      If channel <> "Security" Then
        body = "{""events"":[{""event_uid"":" & Q(Left(host,40) & ":" & channel & ":reset:" & (generation+1)) & ",""timestamp"":" & Q(UtcNow()) & ",""host"":" & Q(host) & ",""source"":""agent.health"",""event_id"":""wmi_record_reset"",""action"":""log_channel_reset"",""category"":""system"",""outcome"":""unknown"",""severity"":""high"",""message"":" & Q("Observed WMI RecordNumber reset: " & channel & " previous=" & cursor & " newest=" & last) & ",""extra"":{""collector"":""WMI cursor observation"",""Channel"":" & Q(channel) & ",""previous_record"":" & cursor & ",""newest_record"":" & last & ",""derived_observation"":true}}]}"
        result = Post("/api/v1/logs", body)
        If Not Receipted(result) Then Exit Sub
      End If
      generation = generation + 1
      WriteText generationFile, CStr(generation)
      Log "RESET " & channel & " previous=" & cursor & " newest=" & last & " generation=" & generation
      cursor = 0
      WriteText cursorFile, "0"
    End If
  End If
  If cursor < 0 Then
    last = 0
    For Each e In svc.ExecQuery("SELECT RecordNumber FROM Win32_NTLogEvent WHERE Logfile='" & channel & "'")
      If CDbl(e.RecordNumber) > last Then last = CDbl(e.RecordNumber)
    Next
    If Err.Number <> 0 Then
      Log "ERROR WMI " & channel & ": " & Err.Description
      Err.Clear
      Exit Sub
    End If
    cursor = last - 5
    If cursor < 0 Then cursor = 0
    WriteText cursorFile, CStr(cursor)
    Log "BASELINE " & channel & " last=" & last & " importing at most 5 recent records"
  End If
  Set records = svc.ExecQuery("SELECT * FROM Win32_NTLogEvent WHERE Logfile='" & channel & "' AND RecordNumber > " & CStr(cursor))
  count = 0
  ReDim numbers(0)
  ReDim entries(0)
  For Each e In records
    ReDim Preserve numbers(count)
    ReDim Preserve entries(count)
    numbers(count) = CDbl(e.RecordNumber)
    Set entries(count) = e
    count = count + 1
  Next
  If Err.Number <> 0 Then
    Log "ERROR WMI " & channel & ": " & Err.Description
    Err.Clear
    Exit Sub
  End If
  On Error GoTo 0
  For i = 0 To count - 2
    For j = i + 1 To count - 1
      If numbers(j) < numbers(i) Then
        tmp = numbers(i): numbers(i) = numbers(j): numbers(j) = tmp
        Set obj = entries(i): Set entries(i) = entries(j): Set entries(j) = obj
      End If
    Next
  Next
  For i = 0 To count - 1
    If i >= 200 Then Exit For
    Set e = entries(i)
    Set dt = CreateObject("WbemScripting.SWbemDateTime")
    dt.Value = e.TimeGenerated
    ts = dt.GetVarDate(False)
    ts = Year(ts) & "-" & Pad(Month(ts)) & "-" & Pad(Day(ts)) & "T" & Pad(Hour(ts)) & ":" & Pad(Minute(ts)) & ":" & Pad(Second(ts)) & "Z"
    action = "windows_event": outcome = "unknown": severity = "info": category = "other"
    If e.EventType = 1 Then severity = "high"
    If e.EventType = 2 Then severity = "medium"
    If e.EventType = 5 Then outcome = "failure": severity = "medium"
    Select Case CStr(e.EventCode)
      Case "529", "530", "531", "532", "533", "534", "535", "536", "537", "539"
        action = "logon_failed": outcome = "failure": category = "authentication"
      Case "528", "540"
        action = "logon_success": outcome = "success": category = "authentication"
      Case "624"
        action = "user_created": category = "account"
      Case "517"
        action = "audit_log_cleared": severity = "high"
    End Select
    body = "{""events"":[{""event_uid"":" & Q(Left(host,40) & ":" & channel & ":" & generation & ":" & e.RecordNumber & ":" & e.TimeGenerated) & ",""timestamp"":" & Q(ts) & ",""host"":" & Q(host) & ",""source"":" & Q("windows." & LCase(channel)) & ",""event_id"":" & Q(CStr(e.EventCode)) & ",""action"":" & Q(action) & ",""outcome"":" & Q(outcome) & ",""category"":" & Q(category) & ",""severity"":" & Q(severity) & ",""message"":" & Q(e.Message) & ",""raw"":" & Q(e.Message) & ",""process"":" & Q(e.SourceName) & ",""user"":" & Q(e.User) & ",""extra"":{""collector"":""WMI Win32_NTLogEvent"",""record_number"":" & e.RecordNumber & ",""legacy_event_id"":true,""log_generation"":" & generation & ",""insertion_strings"":" & JsonArray(e.InsertionStrings) & "}}]}"
    result = Post("/api/v1/logs", body)
    Set rx = New RegExp
    rx.Pattern = """(accepted|duplicates)""\s*:\s*1"
    If rx.Test(result) Then
      WriteText cursorFile, CStr(e.RecordNumber)
      Log "ACK " & channel & " Record=" & e.RecordNumber & " EventID=" & e.EventCode
    Else
      Log "RETRY " & channel & " Record=" & e.RecordNumber
      Exit For
    End If
  Next
  If currentCount >= 0 Then WriteText countFile, CStr(currentCount)
End Sub

Function Receipted(response)
  Dim pattern
  Set pattern = New RegExp
  pattern.Pattern = """(accepted|duplicates)""\s*:\s*1"
  Receipted = pattern.Test(response)
End Function

Function JsonArray(values)
  Dim value, output, separator
  output = "[": separator = ""
  If IsArray(values) Then
    For Each value In values
      output = output & separator & Q(value)
      separator = ","
    Next
  End If
  JsonArray = output & "]"
End Function

Function UtcNow()
  Dim moment, value
  Set moment = CreateObject("WbemScripting.SWbemDateTime")
  moment.SetVarDate Now, True
  value = moment.GetVarDate(False)
  UtcNow = Year(value) & "-" & Pad(Month(value)) & "-" & Pad(Day(value)) & "T" & Pad(Hour(value)) & ":" & Pad(Minute(value)) & ":" & Pad(Second(value)) & "Z"
End Function

Function Post(path, body)
  Dim http, status
  Post = ""
  On Error Resume Next
  Set http = CreateObject("MSXML2.ServerXMLHTTP.3.0")
  http.setTimeouts 3000,5000,5000,15000
  http.open "POST", server & path, False
  http.setRequestHeader "Content-Type", "application/json; charset=utf-8"
  If key <> "" Then http.setRequestHeader "X-API-Key", key
  http.send body
  If Err.Number <> 0 Then
    Log "ERROR HTTP " & path & ": " & Err.Description
    Err.Clear
  Else
    status = http.status
    If status >= 200 And status < 300 Then
      Post = http.responseText
    Else
      Log "ERROR HTTP " & path & " status=" & status
    End If
  End If
  On Error GoTo 0
End Function

Function Q(value)
  Dim s, i, c, a, output
  s = ""
  If Not IsNull(value) And Not IsEmpty(value) Then s = CStr(value)
  output = ""
  For i = 1 To Len(s)
    c = Mid(s, i, 1): a = AscW(c)
    If a < 0 Then a = a + 65536
    Select Case a
      Case 34: output = output & "\" & Chr(34)
      Case 92: output = output & "\\"
      Case Else
        If a < 32 Or a >= 127 Then
          output = output & "\u" & Right("0000" & Hex(a), 4)
        Else
          output = output & c
        End If
    End Select
  Next
  Q = Chr(34) & output & Chr(34)
End Function

Function Pad(value)
  Pad = Right("0" & CStr(value), 2)
End Function

Function ReadText(path, fallback)
  Dim f
  ReadText = fallback
  If fso.FileExists(path) Then
    Set f = fso.OpenTextFile(path, 1)
    ReadText = Trim(f.ReadAll)
    f.Close
  End If
End Function

Sub WriteText(path, value)
  Dim f
  Set f = fso.CreateTextFile(path & ".tmp", True)
  f.Write value
  f.Close
  If fso.FileExists(path) Then fso.DeleteFile path
  fso.MoveFile path & ".tmp", path
End Sub

Sub Log(message)
  Dim f
  Set f = fso.OpenTextFile(logPath, 8, True)
  f.WriteLine CStr(Now) & " " & message
  f.Close
  WScript.Echo message
End Sub
