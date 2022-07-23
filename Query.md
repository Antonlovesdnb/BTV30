```
_sourceCategory=windows/events

| formatDate(toLong(_messagetime), "yyyy-MM-dd'T'HH:mm:ss.SSS") as ts
| timeslice 5m
// Parsing
| json field=_raw "EventData.CallTrace" as CallTrace nodrop
| json field=_raw "EventData.SourceProcessGUID" as SourceProcessGUID nodrop
| json field=_raw "EventData.SourceImage" AS SourceImage nodrop
| json field=_raw "EventData.ParentImage" AS ParentImage nodrop
| json field=_raw "EventData.ImageLoaded" AS ImageLoaded nodrop
| json field=_raw "EventData.ProcessGuid" AS ProcessGuid nodrop
| json field=_raw "EventData.TargetObject" AS TargetObject nodrop
| json field=_raw "EventData.CommandLine" AS CommandLine nodrop
| json field=_raw "EventData.GrantedAccess" AS GrantedAccess nodrop
| json field=_raw "EventData.Image" AS Image nodrop
| json field=_raw "EventData.TargetFilename" AS TargetFilename nodrop
| json field=_raw "EventData.RuleName" AS RuleName nodrop
| json field=_raw "EventData.Description" AS Description nodrop
| json field=_raw "EventData.TargetImage" AS TargetImage nodrop


// Normalize GUID Fields
| transactionize SourceProcessGUID,ProcessGuid as GUID

// Qualifiers
| if (ParentImage matches "*OUTLOOK.EXE*","Outlook as Parent Process # score: 2", "") as q1
| if (ImageLoaded matches "*VBE*","VBE DLL Loaded # score: 3", "") as q2
| if (ImageLoaded matches "*combase.dll*","COM DLL Loaded # score: 4", "") as q3
| if (CommandLine matches "*MyFileShare*","File Opened From Trusted Source # score: -6", "") as q4
| if (TargetObject matches "*Trusted Documents*","Trust Record Modification # score: 3", "") as q5
| if (GrantedAccess matches "*0x1fffff*","RWX Granted Access in CallTrace # score: 2", "") as q6
| if (Image matches "*powershell*","PowerShell spawned from Office Product # score: 10", "") as q7
| if (Image matches "*cmd*","Command Prompt spawned from Office Product # score: 10", "") as q8
| if (CommandLine matches "*\\/c*","Command Prompt with suspicious parameters spawned from Office Product # score: 15", "") as q9
| if (Image matches "*cscript.exe*","Cscript spawned from Office Product # score: 10", "") as q10
| if (TargetFilename matches "*\\.jse*","Suspicious JSE File Created # score: 10", "") as q11
| if (TargetFilename matches "*\\.vbs*","Suspicious VBS File Created # score: 10", "") as q12
| if (RuleName matches "*ProviderExecMethod*","Suspicious WMI Function # score: 10", "") as q13
| if (Description matches "*WMI*","Suspicious WMI ImageLoad # score: 10", "") as q14
| if (ImageLoaded matches "*clr.dll*","DotNet Office Load # score: 10", "") as q15
| if (ImageLoaded matches "*assembly*","DotNet Native Image Office Load # score: 10", "") as q16
| if (TargetImage matches "*powershell*","Suspicious TargetImage (PowerShell) # score: 10", "") as q17
| if (TargetImage matches "*cmd*","Suspicious TargetImage (CMD) # score: 10", "") as q18





| concat(q1,q2,q3,q4,q5,q6,q7,q8,q9,q10,q11,q12,q13,q14,q15) as qualifiers1
| concat(q16,q17,q18) as qualifiers2
| concat(qualifiers1,qualifiers2) as qualifiers


| parse regex field=qualifiers "score:\s(?<score>-?\d+)" multi
| values(qualifiers) as qualifiers,sum(score) as score,values(eventid) as event_codes,values(CommandLine) as CommandLines,values(ImageLoaded) as ImagesLoaded, values(ParentImage) as ParentImages by _timeslice 
```
