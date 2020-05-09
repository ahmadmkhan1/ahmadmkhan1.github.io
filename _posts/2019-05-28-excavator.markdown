---
layout: post
title: "Excavator"
date: 2019-05-28 02:00:00 +0530
categories: ["tools"]
tags: ["excavator","eventlogs","winevt","evtx","elasticsearch","elk"]

---

During an incident response, I felt the need to parse Windows Event Logs and send them to ELK for analysis.

I tried a few parsers like [_evtxtoelk by dgunter_](https://github.com/dgunter/evtxtoelk) which is a good tool but it often misses some event logs while pushing them to ELK. Another nice option was [_winlogbeat_](https://www.elastic.co/downloads/beats/winlogbeat) by elastic which installs itself as a service on the system and keeps pushing the logs to ELK. I noticed a drawback that it sometimes either misses some logs or sends incomplete info of a log.

I needed to push logs with high accuracy and most importantly something that I could trust, so  wrote a python script keeping in mind we don't miss any logs :)

I call it [_Excavator_](https://github.com/EbryxLabs/__DFIR-scripts/tree/master/Excavator). The tool is now actively maintained by EbryxLabs. Feel free to use it.
