---
layout: post
title: "A Portal Into The Dark World"
date: 2020-02-25 17:00:00 +0530
categories: ["misc"]
tags: ["dark web","deep web","ransom","cybercrime"]

---

Since long, cyber-criminals have been exploiting public facing applications vulnerable to publicly known exploits, deploying ransomware and mining crypto-currency for financial gains. To achieve such nefarious goals, cyber-criminals often deploy techniques to avoid detection from AV engines or to secure their malware from getting exposed.


<div><center><img src="https://hackernoon.com/drafts/3g2j1329c.png" title="Cyber Criminal"></center></div>
<br>

I recently happened to observe a case where cyber-crooks used online TOR gateway/proxy service to route traffic from surface to deep web and vice versa. The crypto-mining binary was hosted on a deep-web website and was being fetched by compromised machines through these TOR gateways.

These TOR gateways/proxies serve as portals from surface to deep web and back for these cyber-criminals without actually making the machine part of the TOR network to avoid detection.

## What Needs To Be Done?

Such malicious activity can easily be detected inside your network through your net-flows or DNS logs. Just add the following domains to your rules and its done:

- onion.ws
- onion.pet
- onion.ly
- tor2web.su
- civiclink.network
- onion.glass
- 4tor.ml
- onion.in
- onion.to
- tor2web.to
- tor2web.io
- onion.mn
- d2web.org

Happy Hunting!!!
