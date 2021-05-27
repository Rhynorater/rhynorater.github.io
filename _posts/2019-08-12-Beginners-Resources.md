---
layout: post
title: Beginners Resources
subtitle: Where to get started in bug bounty
permalink: /Beginners-Resources
---
One of the questions I get all the time is `How do I get started in bug bounty?` While I really enjoy teaching and mentoring, it is not possible for me to provide tailored guidance for each and every one of you. **I will gladly point you in the right direction, answer questions that you've already researched (but have been unable to find a solution for), and help you to exploit and escalate vulnerabilities.** However, because I care about your success, I will also try to teach you how to teach yourself (which is not an easy thing to do). 

I will let you know ahead of time, bug bounty requires a large amount of:
- determination in the face of disappointment and self-doubt
- self-motivation
- ability to take research done by others and implement it differently OR ability to come up with innovative ideas (ideally, both)

What bug bounty is not:
- a "get-rich-quick" sorta thing
- passive income with very little initial investment (your time is your most valuable asset)

Now that we've set up expectations, let's discuss how to get started. The point of bug bounty for companies is this: **incentivize hackers to find impactful vulnerabilities in our attack surface**. The point of bug bounty for hackers is a little more wide-spread. Some of the most common motivations for bug bounty I've found are:
- Money
- Prestige 
- Intellectual Challenge
- Adrenaline rush that comes from findings a vulnerability
- Community
- Being on the cutting edge

Whatever your motivation is, I would recommend that you define for yourself why you are doing this. It will be important for you to understand about yourself when you are feeling discouraged.


## Types of bug bounty hackers

Let's talk technical details. There are two kinds of hackers that I've observed that perform well in bug bounty: the hacker that goes deep and the hacker that goes wide. Let's talk abut what kind of hacker you want to be. 

### The hacker that goes deep 
This type of hacker normally targets several of the core applications in the companies scope. For example, if this kind of hacker was targeting Yahoo!, they might focus on Yahoo! Mail, Yahoo! Fantasy Football, and Yahoo! Fiance. These are flagship products and vulnerabilities in these products will likely have a large impact. This hacker then spends several days on these applications in order to understand how they function. Much time is spent reading minified JavaScript files, reading documentation, reading old JavaScript files found in Wayback Machine, ect...

This type of hacker will likely produce impactful vulnerabilities in core applications. The main types of vulnerabilities that sprout from this kind of hacker are: include XSS in core apps, IDORs, Business Logic Errors, Account Takeover, Access Control Issues, Race Conditions, CSRF, Paywall bypasses, XXE, SSRF, ect... However, these hackers may also discover vulnerabilities like RCE and SQLi if they dig deep enough/if these vulnerabilities exist in core products. 

As this type of hacker myself, I'd provide these pieces of advice to someone who is beginning: learn how to read JavaScript and understand the application's purpose then set goals on how to exploit it. For example, Yahoo! Finance allows you to keep track of stocks. A great attack scenario would be figuring out how to leak the stock lists of an individual if you know their email. Set attack scenario goals like this then read all the documentation and JavaScript surrounding these features.

### The hacker that goes wide
This type of hacker normally spends 90 percent of their time on reconnaissance. Their primary focus is asset discovery. They will likely utilize custom and tailored techniques for subdomain enumeration and wordlist generation. These techniques will allow the hacker to discover areas of the target's attack surface which is generally unseen by others - allowing them to discover vulnerabilities most others would not. 

This type of hacker will likely produce impactful vulnerabilities on edge applications or perhaps even **extra** impactful vulnerabilities on out-of-scope targets which still belong to the organization. The types of vulnerabilities most likely to be discovered by this type of hacker include: misconfigurations (subdomain takeover, default creds, SSO bypasses), Information Disclosure, SSRF, RCE, SQLi, access to administrative interfaces. 

### The hacker that can do both
![Both](https://media.giphy.com/media/QqkA9W8xEjKPC/200.gif)
<br>
<br>
The hackers that you will see that perform the best are the hackers that can do both. However, this takes a lot of time and energy and experience. In the beginning, I'd recommend you pick one, build a solid foundation in it, and start reporting vulnerabilities. 


## Technical Resources
In order to learn about all the vulnerabilities that one could find, there are several key resources:
- [Web Hacking 101 by Pete Yaworski](https://leanpub.com/web-hacking-101)
- [PortSwigger Academy](https://portswigger.net/web-security)
- [BugCrowd University](https://www.bugcrowd.com/hackers/bugcrowd-university/)
- [Hacker101](https://www.hacker101.com/videos)
- [The Web Application Hacker's Handbook](https://www.amazon.com/Web-Application-Hackers-Handbook-Exploiting/dp/1118026470)
- [BugBountyNotes](https://www.bugbountynotes.com/)
- [Bug Bounty Forum Resources](https://bugbountyforum.com/resources/)
- Reading every single blog that has ever existed on Bug Bounty
- Follow everyone I follow on Twitter

If you read the above, then you will 100% have the knowledge to find vulnerabilities. Now all you need is persistence, a creative mind, and quite a bit of time and you'll be writing some reports in no time!

You can do it! DM me if you have any questions.
Justin





