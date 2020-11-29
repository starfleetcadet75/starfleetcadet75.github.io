---
title: "Flare-On CTF 2020 Challenge 4: report"
summary: "Nobody likes analysing infected documents, but it pays the bills. Reverse this macro thrill-ride to discover how to get it to show you the key."
date: 2020-09-21
categories:
  - "writeups"
tags:
  - "reversing"
  - "forensics"
  - "vba"
---

## Challenge

> Nobody likes analysing infected documents, but it pays the bills.
> Reverse this macro thrill-ride to discover how to get it to show you the key.

## Observations

This challenge provides us with an Excel file that obviously contains a macro.
We can view the macro using the developer tab in Excel:

```vb
Private Declare Function InternetGetConnectedState Lib "wininet.dll" _
(ByRef dwflags As Long, ByVal dwReserved As Long) As Long

Private Declare PtrSafe Function mciSendString Lib "winmm.dll" Alias _
   "mciSendStringA" (ByVal lpstrCommand As String, ByVal _
   lpstrReturnString As Any, ByVal uReturnLength As Long, ByVal _
   hwndCallback As Long) As Long

Private Declare Function GetShortPathName Lib "kernel32" Alias "GetShortPathNameA" _
    (ByVal lpszLongPath As String, ByVal lpszShortPath As String, ByVal lBuffer As Long) As Long

Public Function GetInternetConnectedState() As Boolean
  GetInternetConnectedState = InternetGetConnectedState(0&, 0&)
End Function

Function rigmarole(es As String) As String
    Dim furphy As String
    Dim c As Integer
    Dim s As String
    Dim cc As Integer
    furphy = ""
    For i = 1 To Len(es) Step 4
        c = CDec("&H" & Mid(es, i, 2))
        s = CDec("&H" & Mid(es, i + 2, 2))
        cc = c - s
        furphy = furphy + Chr(cc)
    Next i
    rigmarole = furphy
End Function

Function folderol()
    Dim wabbit() As Byte
    Dim fn As Integer: fn = FreeFile
    Dim onzo() As String
    Dim mf As String
    Dim xertz As Variant

    onzo = Split(F.L, ".")

    If GetInternetConnectedState = False Then
        MsgBox "Cannot establish Internet connection.", vbCritical, "Error"
        End
    End If

    Set fudgel = GetObject(rigmarole(onzo(7)))
    Set twattling = fudgel.ExecQuery(rigmarole(onzo(8)), 48)
    For Each p In twattling
        Dim pos As Integer
        pos = InStr(LCase(p.Name), "vmw") + InStr(LCase(p.Name), "vmt") + InStr(LCase(p.Name), rigmarole(onzo(9)))
        If pos > 0 Then
            MsgBox rigmarole(onzo(4)), vbCritical, rigmarole(onzo(6))
            End
        End If
    Next

    xertz = Array(&H11, &H22, &H33, &H44, &H55, &H66, &H77, &H88, &H99, &HAA, &HBB, &HCC, &HDD, &HEE)

    wabbit = canoodle(F.T.Text, 0, 168667, xertz)
    mf = Environ(rigmarole(onzo(0))) & rigmarole(onzo(1))
    Open mf For Binary Lock Read Write As #fn
      Put #fn, , wabbit
    Close #fn

    mucolerd = mciSendString(rigmarole(onzo(2)) & mf, 0&, 0, 0)
End Function

Function canoodle(panjandrum As String, ardylo As Integer, s As Long, bibble As Variant) As Byte()
    Dim quean As Long
    Dim cattywampus As Long
    Dim kerfuffle() As Byte
    ReDim kerfuffle(s)
    quean = 0
    For cattywampus = 1 To Len(panjandrum) Step 4
        kerfuffle(quean) = CByte("&H" & Mid(panjandrum, cattywampus + ardylo, 2)) Xor bibble(quean Mod (UBound(bibble) + 1))
        quean = quean + 1
        If quean = UBound(kerfuffle) Then
            Exit For
        End If
    Next cattywampus
    canoodle = kerfuffle
End Function
```

## Reversing the Macro

The `rigmarole` function appears to deobfuscate the interesting strings for the script.
We can rewrite it in Python and give it the constant data to decode.

```python
fl = "9655B040B64667238524D15D6201.B95D4E01C55CC562C7557405A532D768C55FA12DD074DC697A06E172992CAF3F8A5C7306B7476B38.C555AC40A7469C234424.853FA85C470699477D3851249A4B9C4E.A855AF40B84695239D24895D2101D05CCA62BE5578055232D568C05F902DDC74D2697406D7724C2CA83FCF5C2606B547A73898246B4BC14E941F9121D464D263B947EB77D36E7F1B8254.853FA85C470699477D3851249A4B9C4E.9A55B240B84692239624.CC55A940B44690238B24CA5D7501CF5C9C62B15561056032C468D15F9C2DE374DD696206B572752C8C3FB25C3806.A8558540924668236724B15D2101AA5CC362C2556A055232AE68B15F7C2DC17489695D06DB729A2C723F8E5C65069747AA389324AE4BB34E921F9421.CB55A240B5469B23.AC559340A94695238D24CD5D75018A5CB062BA557905A932D768D15F982D.D074B6696F06D5729E2CAE3FCF5C7506AD47AC388024C14B7C4E8F1F8F21CB64"

def rigmarole(data):
    furphy = ""

    for i in range(0, len(data), 4):
        c = int(data[i: i + 2], 16)
        s = int(data[i + 2: i + 4], 16)
        cc = c - s
        furphy = furphy + chr(cc)

    return furphy

onzo = fl.split(".")
for i in range(len(onzo)):
    print("{}: {}".format(i, rigmarole(onzo[i])))
```

The unobfuscated strings are:

```none
0: AppData
1: \Microsoft\stomp.mp3
2: play
3: FLARE-ON
4: Sorry, this machine is not supported.
5: FLARE-ON
6: Error
7: winmgmts:\\.\root\CIMV2
8: SELECT Name FROM Win32_Process
9: vbox
10: WScript.Network
11: \Microsoft\v.png
```

Cleaning up the `folderol` function, we can see that the script first searches for any processes that might indicate it is running inside a VM.
It then uses the `canoodle` function to decode what appears to be the contents of an MP3 file and attempts to play it.

```vb
Set fudgel = GetObject("winmgmts:\\.\root\CIMV2")
Set twattling = fudgel.ExecQuery("SELECT Name FROM Win32_Process", 48)
For Each p In twattling
    Dim pos As Integer
    pos = InStr(LCase(p.Name), "vmw") + InStr(LCase(p.Name), "vmt") + InStr(LCase(p.Name), "vbox")
    If pos > 0 Then
        MsgBox "Sorry, this machine is not supported.", vbCritical, "Error"
        End
    End If
Next

xertz = Array(&H11, &H22, &H33, &H44, &H55, &H66, &H77, &H88, &H99, &HAA, &HBB, &HCC, &HDD, &HEE)

wabbit = canoodle(F.T.Text, 0, 168667, xertz)
mf = Environ("AppData" & "\Microsoft\stomp.mp3")
Open mf For Binary Lock Read Write As #fn
  Put #fn, wabbit
Close #fn

mucolerd = mciSendString("play" & mf, 0&, 0, 0)
```

We can rewrite the `canoodle` function in Python and manually decode the stomp.mp3 file.

```python
ft = "58c7661f00634702555f664b7756884c864edc4fef2d9c48881bac0911082214334e424f552f661d7752ce41d54deb70e9468949892db745545270fc333c44aa5525634f772d88699970983b8b18fe1eed3aba1d584c763201724431553e66295a2888269941aa20ef72a435b4359d36312b4b6f4048643d3b3b0927034ca846ee36c295da80b8d9fd3b97d37e51577113dc37cb3dd209a60246e43cfd488a42d938a953fd2a82ee7e8b4d9d582c2dc83b7101d057cee978ed008453950be22c89fdbea6548c106d33c344e4552e6ef87782880b9901fa5b95bcecc09e0c81ff75bd479033d24430558f66fe77b288b39961aabcbb9ccc42ddc5ee33112122e333d944ad55d4666277a78895998faaa6bbc5cca9dd12eeba112e22bf337844d9559066a077c288da998eaa3dbbb4cc38ddb9ee6011f2223233e3443d55f3664a77b2885699d4aa76bb2cccbfddeeeeda118122d0331b44bd552c66bf77af8845997baa32bb92cc7addadeebb11312211339944a855a6669577ec887699b6aab8bb8bccc0dd36ee03116f221833a344b655f366e17750882a9946aa82bbabccbdddb8eeb21152229233ed44de555766af7701888499d4aabbbb85ccb6dd37eebf11d1225833d244bf55ad66e8772e88ca99d3aaf6bb72cc49dd7ceedd1124229733bd443455fd661677b088a699f3aa87bb31ccdadd ...snip..."

def canoodle(panjandrum, offset, s, bibble):
    kerfuffle = b""
    quean = 0

    for i in range(0, len(panjandrum), 4):
        kerfuffle += bytes([int(panjandrum[i + offset : i + offset + 2], 16) ^ bibble[quean % len(bibble)]])
        quean += 1

        if len(kerfuffle) < quean:
            break

    return kerfuffle

xertz = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE
]
wabbit = canoodle(ft, 0, 168667, xertz)

with open("stomp.mp3", "wb") as f:
   f.write(wabbit)
```

[stomp.mp3](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/report/stomp.mp3) contains a short audio clip of some stomping sounds.
The title warns us that we are not looking in the right place.

![stomp_msg](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/report/stomp_msg.PNG)

The use of the phrase *stomp* is probably a hint that [VBA stomping](https://vbastomp.com/) is present in this macro.
VBA macros can exist in three different executable forms that can conceal some of its functionality.
We can use [pcodedmp.py](https://github.com/bontchev/pcodedmp) to view the p-code version.

```vb
None
stream : _VBA_PROJECT_CUR/VBA/ThisWorkbook - 1785 bytes
########################################

Sub Workbook_Open()
  Sheet1.folderol
End Sub

Sub Auto_Open()
  Sheet1.folderol
End Sub
stream : _VBA_PROJECT_CUR/VBA/Sheet1 - 10518 bytes
########################################

...no change...

  xertz = Array(&H11, &H22, &H33, &H44, &H55, &H66, &H77, &H88, &H99, &HAA, &HBB, &HCC, &HDD, &HEE)

  Set groke = CreateObject(rigmarole(onzo(10)))
  firkin = groke.UserDomain
  If firkin <> rigmarole(onzo(3)) Then
    MsgBox rigmarole(onzo(4)), vbCritical, rigmarole(onzo(6))
    End
  End If

  n = Len(firkin)
  For i = 1 To n
    buff(n - i) = Asc(Mid$(firkin, i, 1))
  Next

  wabbit = canoodle(F.T.Text, 2, 285729, buff)
  mf = Environ(rigmarole(onzo(0))) & rigmarole(onzo(11))
  Open mf For Binary Lock Read Write As #fn
' a generic exception occured at line 68: can only concatenate str (not "NoneType") to str
' # Ld fn
' # Sharp
' # LitDefault
' # Ld wabbit
' # PutRec
  Close #fn

  Set panuding = Sheet1.Shapes.AddPicture(mf, False, True, 12, 22, 600, 310)
End Function

stream : _VBA_PROJECT_CUR/VBA/F - 1388 bytes
########################################
```

In this version of the macro, we can see that slightly different arguments are passed to the `canoodle` function.
It also appears that the decoded binary data is now displayed as a picture.
The image can be successfully decoded with some minor modifications to the [Python script](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/report/soln.py).

```python
key = b"FLARE-ON"
buff = list(reversed(key))
wabbit = canoodle(ft, 2, 285729, buff)

with open("flag.png", "wb") as f:
    f.write(wabbit)
```

![flag](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/report/flag.png)
