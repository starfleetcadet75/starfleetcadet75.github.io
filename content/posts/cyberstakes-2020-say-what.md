---
title: "Cyberstakes CTF 2020: Say What?"
summary: "We intercepted some foreign documents. We think there's interesting information inside but the file is protected with a unique password algorithm"
date: 2020-05-03
categories:
  - "writeups"
tags:
  - "reversing"
  - "forensics"
  - "vba"
---

**Category:** Reverse Engineering  
**Points:** 200  

## Challenge

> We intercepted some foreign documents.
> We think there's interesting information inside but the file is protected with a unique password algorithm: [chall.docm](https://github.com/starfleetcadet75/writeups/blob/master/2020-Cyberstakes/say-what/chall.docm)

#### Hints

- Microsoft Office documents sometimes carry with them a powerful set of macros
- Microsoft Office is not required to extract the malicious macro, or solve the challenge
- There are a number of open source security tooling to script the extraction of Office macros
- The macro's obfuscation is rather light, try inserting some MsgBox prints to make sense of what it is doing
- If you're not careful, the document might ... change itself.
- Double check that your solution works against a 'fresh' copy of the challenge.

## Observations

We are provided with a Microsoft Word document that contains a Visual Basic macro.
When we attempt to open the document, the macro executes and prompts us for a password.
Searching for tools to extract VBA macros leads us to this [post](https://www.decalage.info/vba_tools), which points us to [oletools](https://github.com/decalage2/oletools).

Running `olevba` on the document provides the following output:

```vb
olevba 0.55.1 on Python 3.8.2 - http://decalage.info/python/oletools
===============================================================================
FILE: chall.docm
Type: OpenXML
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls
in file: word/vbaProject.bin - OLE stream: 'VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Private Sub Document_Open()
    Call run_unprotect
End Sub
-------------------------------------------------------------------------------
VBA MACRO Module1.bas
in file: word/vbaProject.bin - OLE stream: 'VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Public Const fsagkasiogbiwotiwqoqrvb As String = "NmgvUlt8glilwTJa1vHPVfuIKUKY/dBIT2DZSlN0004="

Function siooiqbaswtjqiowiasg() As String
    siooiqbaswtjqiowiasg = ThisDocument.Shapes(3).AlternativeText
    ThisDocument.Shapes(3).AlternativeText = fsagkasiogbiwotiwqoqrvb
    Documents.Save NoPrompt:=True, OriginalFormat:=wdOriginalDocumentFormat
End Function

Function klgnagjaskjlbgbsajbsagsajgsa(ByRef arrData() As Byte) As String
    Dim objXML As MSXML2.DOMDocument
    Dim objNode As MSXML2.IXMLDOMElement
    Set objXML = New MSXML2.DOMDocument
    Set objNode = objXML.createElement("b64")
    objNode.dataType = "bin.base64"
    objNode.nodeTypedValue = arrData
    klgnagjaskjlbgbsajbsagsajgsa = objNode.Text
    Set objNode = Nothing
    Set objXML = Nothing
End Function

Function jisaksgjksbjksabjksabgjskagbjsakgbkj(ByVal strData As String) As Byte()
    Dim objXML As MSXML2.DOMDocument
    Dim objNode As MSXML2.IXMLDOMElement
    Set objXML = New MSXML2.DOMDocument
    Set objNode = objXML.createElement("b64")
    objNode.dataType = "bin.base64"
    objNode.Text = strData
    jisaksgjksbjksabjksabgjskagbjsakgbkj = objNode.nodeTypedValue
    Set objNode = Nothing
    Set objXML = Nothing
End Function

Function jioasgiosahgiosahgsahgbbbbbafsa(ByVal Text As String) As String
    Dim gasgasgisogiogioaragba As String, i As Integer
    For i = 0 To Len(gjasigasogoabvxzbnbkxnzkgas)
        gasgasgisogiogioaragba = gasgasgisogiogioaragba & Mid(Text, (Length - i), 1)
    Next i
    jioasgiosahgiosahgsahgbbbbbafsa = gasgasgisogiogioaragba
End Function

Sub skagiotiohvasgasgasgassdjjj(ByRef Text As String)
    Dim i As Long
    For i = 1 To Len(Text)
        Mid$(Text, i, 1) = Chr$(Asc(Mid$(Text, i, 1)) Xor ((32 + i) Mod 256))
    Next i
End Sub

Function gdtsrtnbzpsapg(ByRef gjasigasogoabvxzbnbkxnzkgas As String) As String
    Dim josajogjsaojpepeqwwqb As Integer, kngkasngksagnskarkwta As Integer, jifsajgiosthigaohbsb As Integer
    Dim jkasojgoisajgoashrt As String

    For i = 1 To Len(gjasigasogoabvxzbnbkxnzkgas)
        josajogjsaojpepeqwwqb = ((i - 1) Mod 4)
        If josajogjsaojpepeqwwqb = 0 Then
            Mid$(gjasigasogoabvxzbnbkxnzkgas, i, 1) = Chr$(((Asc(Mid(gjasigasogoabvxzbnbkxnzkgas, i, 1)) - 104) + 256) Mod 256)
        ElseIf josajogjsaojpepeqwwqb = 1 Then
            jkasojgoisajgoashrt = Mid(gjasigasogoabvxzbnbkxnzkgas, i, 1)
            Mid$(gjasigasogoabvxzbnbkxnzkgas, i, 1) = Mid(gjasigasogoabvxzbnbkxnzkgas, i - 1, 1)
            Mid$(gjasigasogoabvxzbnbkxnzkgas, i - 1, 1) = jkasojgoisajgoashrt
        ElseIf josajogjsaojpepeqwwqb = 2 Then
            kngkasngksagnskarkwta = (Asc(Mid(gjasigasogoabvxzbnbkxnzkgas, i, 1)) * 16) Mod 256
            jifsajgiosthigaohbsb = Asc(Mid(gjasigasogoabvxzbnbkxnzkgas, i, 1)) \ 16
            Mid$(gjasigasogoabvxzbnbkxnzkgas, i, 1) = Chr$(kngkasngksagnskarkwta + jifsajgiosthigaohbsb)
        ElseIf josajogjsaojpepeqwwqb = 3 Then
            Mid$(gjasigasogoabvxzbnbkxnzkgas, i, 1) = Chr$(Asc(Mid(gjasigasogoabvxzbnbkxnzkgas, i, 1)) Xor Asc(Mid(gjasigasogoabvxzbnbkxnzkgas, i - 1, 1)))
        End If
    Next i
    Call skagiotiohvasgasgasgassdjjj(gjasigasogoabvxzbnbkxnzkgas)
    gdtsrtnbzpsapg = StrReverse(gjasigasogoabvxzbnbkxnzkgas)
    gdtsrtnbzpsapg = klgnagjaskjlbgbsajbsagsajgsa(StrConv(gdtsrtnbzpsapg, vbFromUnicode))

End Function

Sub run_unprotect()
    Dim gjasigasogoabvxzbnbkxnzkgas As String
    Dim jisajgoajgosajohnnvvnv As String
    Dim tietojosapgjpsaje As String
    gjasigasogoabvxzbnbkxnzkgas = InputBox("Enter document password:", "File Decryption")
    If gjasigasogoabvxzbnbkxnzkgas = "" Then
        MsgBox ("No password provided...")
        Exit Sub
    End If
    jisajgoajgosajohnnvvnv = gdtsrtnbzpsapg(gjasigasogoabvxzbnbkxnzkgas)
    tietojosapgjpsaje = siooiqbaswtjqiowiasg()
    If (jisajgoajgosajohnnvvnv = tietojosapgjpsaje) And (jisajgoajgosajohnnvvnv <> fsagkasiogbiwotiwqoqrvb) Then
        MsgBox ("Password accepted!")
    Else
        MsgBox ("Incorrect password...")
    End If
End Sub
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |Document_Open       |Runs when the Word or Publisher document is  |
|          |                    |opened                                       |
|Suspicious|Call                |May call a DLL using Excel 4 Macros (XLM/XLF)|
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|StrReverse          |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Xor                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Base64 Strings      |Base64-encoded strings were detected, may be |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

The macro seems to have been lightly obfuscated by renaming all of the variables to meaningless names.

## Solution

We can dump the contents of the macro to a file and start to rename the variables based on their usage.
There is a base64 value at the beginning that is assigned to a variable called flag.
Unfortunately, base64 decoding it only gives us the encoded bytes.
The first function is called `GetPassword` and reads a value from `ThisDocument.Shapes(3).AlternativeText`.
This seems to imply that one of the shapes in the document contains the password.
Looking at the alternative text for the padlock image, we can see a base64 value which contains the password we need to enter:

![alttext.png](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Cyberstakes/say-what/alttext.png)

The cleaned up version of the macro appears as follows:

```vb
Const flag As String = "NmgvUlt8glilwTJa1vHPVfuIKUKY/dBIT2DZSlN0004="

Function GetPassword() As String
    GetPassword = ThisDocument.Shapes(3).AlternativeText
    ThisDocument.Shapes(3).AlternativeText = flag
    Documents.Save NoPrompt:=True, OriginalFormat:=wdOriginalDocumentFormat
End Function

Function encodeBase64(ByRef arrData() As Byte) As String
    ... snip ...
End Function

Sub XorFunction(ByRef Text As String)
    Dim i As Long
    For i = 1 To Len(Text)
        Mid$(Text, i, 1) = Chr$(Asc(Mid$(Text, i, 1)) Xor ((32 + i) Mod 256))
    Next i
End Sub

Function HashInput(ByRef guess As String) As String
    Dim x As Integer, y As Integer, z As Integer
    Dim s As String

    For i = 1 To Len(guess)
        x = ((i - 1) Mod 4)
        If x = 0 Then
            Mid$(guess, i, 1) = Chr$(((Asc(Mid(guess, i, 1)) - 104) + 256) Mod 256)

        ElseIf x = 1 Then
            s = Mid(guess, i, 1)
            Mid$(guess, i, 1) = Mid(guess, i - 1, 1)
            Mid$(guess, i - 1, 1) = s

        ElseIf x = 2 Then
            y = (Asc(Mid(guess, i, 1)) * 16) Mod 256
            z = Asc(Mid(guess, i, 1)) \ 16
            Mid$(guess, i, 1) = Chr$(y + z)

        ElseIf x = 3 Then
            Mid$(guess, i, 1) = Chr$(Asc(Mid(guess, i, 1)) Xor Asc(Mid(guess, i - 1, 1)))

        End If
    Next i

    Call XorFunction(guess)
    HashInput = StrReverse(guess)
    HashInput = encodeBase64(StrConv(HashInput, vbFromUnicode))
End Function

Sub run_unprotect()
    Dim guess As String
    Dim encodedInput As String
    Dim password As String

    guess = InputBox("Enter document password:", "File Decryption")
    If guess = "" Then
        MsgBox ("No password provided...")
        Exit Sub
    End If

    encodedInput = HashInput(guess)
    password = GetPassword()
    If (encodedInput = password) And (encodedInput <> flag) Then
        MsgBox ("Password accepted!")
    Else
        MsgBox ("Incorrect password...")
    End If
End Sub
```

The entered guess is passed to a function that encodes it and the result is compared against the encoded password.
The encoding function operates on four characters at a time, performing a different operation on each one.

1. The first character is incremented by a value modulo 256 to ensure that it stays within the size of a byte
2. The second character is swapped with the first character
3. The third character is multiplied and then divided by some value
4. The fourth character is xored with the third character

After the individual character operations are completed, every character is xored by 32 plus its position.
The input is then reversed and base64 encoded.

All of the encoding operations are invertible, which means that we can write a script that will perform the same operations in reverse to recover the password.
For our purposes, the `Mid` operation is equivalent to accessing the current element from an array.

```python
import binascii
import string
import base64

# Base64 decode the pasword and undo the reversing of the bytes
password = b"e3n3WxMt9w5Hcf0GE3XOCSMM/k4vHeIYg7ToHMu3+2I="
password = bytearray(base64.b64decode(password)[::-1])

# Xor is invertible by xoring with itself, so we copy the original function
# Take note of the zero-based indexing here versus in the macro itself
for i in range(1, len(password)):
    password[i - 1] = password[i - 1] ^ ((32 + i) % 256)

# Undo the individual character encodings
for i in range(len(password)):
    x = i % 4

    if x == 0:
        # Reswap the first and second characters
        m = password[i]
        password[i] = password[i + 1]
        password[i + 1] = m

        # Flipping the minus sign inverts the increment operation on the first character
        password[i] = ((password[i] + 104) + 256) % 256

    elif x == 3:
        # Reverse the xor first before inverting the previous character
        password[i] = password[i] ^ password[i - 1]

        # The multiply / divide operation is invertible by being repeated on the character
        password[i - 1] = (password[i - 1] * 16) % 256 + int(password[i - 1] / 16)

print("Decoded: {}".format(password))
```

**Flag:** `ACI{699801c58c20d8da33d957a91fd}`
