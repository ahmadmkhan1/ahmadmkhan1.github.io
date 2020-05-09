---
layout: post
title: "Death by Local Admin"
date: 2019-07-08 03:00:00 +0530
categories: ["misc"]
tags: ["localadmin","cososys","dlp","bypass"]

---

I was casually messing around with this nice looking DLP agent, Endpoint Protector by CoSoSys when I realized the power of having Local Admin on a machine.


__Its Deadly.__

_Trust me, it is. It is so deadly that it can kill a Dragon._

<div><center><img src="https://media3.giphy.com/media/3owvKgBIZw89mfo8WA/giphy.gif" title="Killing A Drangon"></center></div>
<br>

So, I had it installed on one of my machines and remotely pushed a policy to deny any attached USB. It worked like a charm and all my USB ports got blocked. Afterwards, I tried uninstalling the agent directly from the machine but I was denied operation. I tried uninstalling it as local admin, but even that didn't work out as the Endpoint Protector requires an OTP provided by its remote administrator.

And that is where the FUN began.

I went to the installation directory of the Endpoint Protector agent _C:\Program Files\CoSoSys\Endpoint Protector_ and moved the following two files out of this directory:

- EPPService.dll
- EPPService.exe

When I attempted to move these files, my machine asked me for administrative access where I simply gave my local admin credentials. But the files didn't get moved from the directory. Instead, it kept showing me this dialog box

<div><center><img src="/assets/img/posts/2019-07-08-epp-bypass-prompt.png" title="EPP Bypass Prompt"></center></div>
<br>

I went to the task manager and tried to stop EPPservice.exe as a normal user but it restarted itself in 4-5 seconds. I stopped it again and then quickly clicked try again on the _File In Use_ dialog box.

Voila. I then forced reboot the machine and found that neither EPP ran on startup nor any policy implemented through it. All of this happened because I had local admin on the machine who was able to move the executable and the DLL file required by EPP for running.

So what can be the solution to this?

__In environments where active directory has been setup, it is always a good practice to disable local admin.__
