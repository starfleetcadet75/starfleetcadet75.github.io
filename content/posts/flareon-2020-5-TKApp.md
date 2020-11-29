---
title: "Flare-On CTF 2020 Challenge 5: TKApp"
summary: "This is the mobile device challenge for 2020 and features a pedometer app for the Tizen operating system."
date: 2020-09-22
categories:
  - "writeups"
tags:
  - "reversing"
  - "mobile"
  - "dotnet"
---

## Challenge

> Now you can play Flare-On on your watch!
> As long as you still have an arm left to put a watch on, or emulate the watch's operating system with sophisticated developer tools.

## Observations

This is the mobile device challenge for 2020 and features a pedometer app for the Tizen operating system.
We are provided with a TPK file which is really just a zip file that contains all of the application contents.

![app_extract](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/TKApp/app_extract.PNG)

The Xamarin DLLs hint that this application was written in C# so we can import the TKApp.dll into dnSpy and begin reversing it.

```csharp
using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using TKApp;
using Xamarin.Forms.Xaml;

[assembly: AssemblyVersion("1.0.0.0")]
[assembly: CompilationRelaxations(8)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: TargetFramework("Tizen,Version=v6.0", FrameworkDisplayName = "")]
[assembly: XamlResourceId("TKApp.App.xaml", "App.xaml", typeof(App))]
[assembly: XamlResourceId("TKApp.GalleryPage.xaml", "GalleryPage.xaml", typeof(GalleryPage))]
[assembly: XamlResourceId("TKApp.MainPage.xaml", "MainPage.xaml", typeof(MainPage))]
[assembly: XamlResourceId("TKApp.TodoPage.xaml", "TodoPage.xaml", typeof(TodoPage))]
[assembly: XamlResourceId("TKApp.UnlockPage.xaml", "UnlockPage.xaml", typeof(UnlockPage))]
[assembly: AssemblyCompany("TKApp")]
[assembly: AssemblyConfiguration("Release")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: AssemblyInformationalVersion("1.0.0")]
[assembly: AssemblyProduct("TKApp")]
[assembly: AssemblyTitle("TKApp")]
```

The app appears to contain four different pages.
The `GetImage` function in the main page appears to be where the flag is decrypted.

```csharp
private bool GetImage(object sender, EventArgs e)
{
  if (string.IsNullOrEmpty(App.Password) || string.IsNullOrEmpty(App.Note) || string.IsNullOrEmpty(App.Step) || string.IsNullOrEmpty(App.Desc))
  {
    this.btn.Source = "img/tiger1.png";
    this.btn.Clicked -= this.Clicked;
    return false;
  }
  string text = new string(new char[]
  {
    App.Desc[2],
    App.Password[6],
    App.Password[4],
    App.Note[4],
    App.Note[0],
    App.Note[17],
    App.Note[18],
    App.Note[16],
    App.Note[11],
    App.Note[13],
    App.Note[12],
    App.Note[15],
    App.Step[4],
    App.Password[6],
    App.Desc[1],
    App.Password[2],
    App.Password[2],
    App.Password[4],
    App.Note[18],
    App.Step[2],
    App.Password[4],
    App.Note[5],
    App.Note[4],
    App.Desc[0],
    App.Desc[3],
    App.Note[15],
    App.Note[8],
    App.Desc[4],
    App.Desc[3],
    App.Note[4],
    App.Step[2],
    App.Note[13],
    App.Note[18],
    App.Note[18],
    App.Note[8],
    App.Note[4],
    App.Password[0],
    App.Password[7],
    App.Note[0],
    App.Password[4],
    App.Note[11],
    App.Password[6],
    App.Password[4],
    App.Desc[4],
    App.Desc[3]
  });
  byte[] key = SHA256.Create().ComputeHash(Encoding.ASCII.GetBytes(text));
  byte[] bytes = Encoding.ASCII.GetBytes("NoSaltOfTheEarth");
  try
  {
    App.ImgData = Convert.FromBase64String(Util.GetString(Runtime.Runtime_dll, key, bytes));
    return true;
  }
  catch (Exception ex)
  {
    Toast.DisplayText("Failed: " + ex.Message, 1000);
  }
  return false;
}
```

If the `App.Password`, `App.Note`, `App.Step`, and `App.Desc` fields are not empty, the function will attempt to decrypt and display an image.
A SHA256 hash is created using values that are extracted from those four fields.
The `Util.GetString` function uses AES to decrypt the contents of `Runtime.dll` using the hash as the key and a constant IV of "NoSaltOfTheEarth".

```csharp
internal static byte[] Runtime_dll {
  get {
    return (byte[])Runtime.ResourceManager.GetObject("Runtime.dll", Runtime.resourceCulture);
  }
}
```

`Runtime.dll` is a resource embedded inside the DLL file and we can extract its contents using dnSpy.
In order to decrypt the image, we need to determine the correct values for the four inputs.

## Solution

The UnlockPage prompts the user to enter a password and checks that it is equal to some encoded string.

```csharp
public static byte[] Password = new byte[] { 62, 38, 63, 63, 54, 39, 59, 50, 39 };

public static string Decode(byte[] e)
{
  string text = "";
  foreach (byte b in e)
  {
    text += Convert.ToChar((int)(b ^ 83)).ToString();
  }
  return text;
}
```

The `App.Step` field is set in the MainPage to a value taken from the `tizen-manifest.xml` file.
The "its" metadata key is assigned the value "magic".

```csharp
private void PedDataUpdate(object sender, PedometerDataUpdatedEventArgs e)
{
  if (e.StepCount > 50u && string.IsNullOrEmpty(App.Step))
  {
    App.Step = Application.Current.ApplicationInfo.Metadata["its"];
  }

  ...snip...
}
```

The `App.Desc` field is set in the GalleryPage to the value of the image description field taken from the EXIF data of the 05.jpg image.
We can determine using an EXIF viewer that the value is "water".

```csharp
private void IndexPage_CurrentPageChanged(object sender, EventArgs e)
{
  if (base.Children.IndexOf(base.CurrentPage) == 4)
  {
    using (ExifReader exifReader = new ExifReader(Path.Combine(Application.Current.DirectoryInfo.Resource, "gallery", "05.jpg")))
    {
      string desc;
      if (exifReader.GetTagValue<string>(ExifTags.ImageDescription, out desc))
      {
        App.Desc = desc;
      }
      return;
    }
  }
  App.Desc = "";
}
```

Through an entirely static analysis of the code, we have determined the required inputs for three of the four values.
`App.Note` has only six possible values so we can simply try each one to determine that "keep steaks for dinner" is correct.
We can now decrypt the contents of `Runtime.dll` by reimplementing the decryption function in Python.

```python
import base64
import hashlib
from Crypto.Cipher import AES

# Decode the password
password = ""
for c in [62, 38, 63, 63, 54, 39, 59, 50, 39]:
    password += chr(c ^ 83)

# Possible values for app_note
notes = [
    "and enable GPS", "and survive", "keep steaks for dinner", "maybe fire someone",
    "unless it's a drinking day", "https://youtu.be/kTmZnQOfAF8"
]
note = notes[2]

# Taken from "tizen-manifest.xml" file <metadata key="its" value="magic" />
step = "magic"

# Image description data from 5.jpg by putting into exifviewer
desc = "water"

text = desc[2] + password[6] + password[4] + note[4] + note[0] + note[17] + note[18] + note[16] + note[11] + note[13] + note[12] + note[15] + step[4] + password[6] + desc[1] + password[2] + password[2] + password[4] + note[18] + step[2] + password[4] + note[5] + note[4] + desc[0] + desc[3] + note[15] + note[8] + desc[4] + desc[3] + note[4] + step[2] + note[13] + note[18] + note[18] + note[8] + note[4] + password[0] + password[7] + note[0] + password[4] + note[11] + password[6] + password[4] + desc[4] + desc[3]

# Text is "the kind of challenges we are gonna make here"
print(text)

m = hashlib.sha256()
m.update(text.encode())
key = m.digest()
iv = b"NoSaltOfTheEarth"

with open("Runtime.dll", "rb") as f:
    ct = f.read()

cipher = AES.new(key, AES.MODE_CBC, iv)
imgdata = cipher.decrypt(ct)
imgdata = base64.b64decode(imgdata)

with open("flag.png", "wb") as f:
    f.write(data)
```

![flag](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2020-Flareon-CTF/TKApp/flag.png)
