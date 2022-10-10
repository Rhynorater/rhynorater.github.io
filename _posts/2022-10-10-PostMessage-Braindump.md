---
layout: post
title: postMessage Braindump
subtitle: a brief postMessage testing methodology
permalink: /postMessage-Braindump
---
## postMessages
PostMessage-related bugs have landed me some serious bounties during the past couple live hacking events. Here is a quick summary of what you need to know about postMessage:

According to the docs, postMessages "safely enables cross-origin communication between Window objects." Whenever we see "cross-origin" as a hacker, our ears should perk up. The communication referred to in the above definition is done in the form of postMessages and Event Listeners. PostMessages are messages sent from the client and Event Listeners are the pieces of code that receive the messages and process them. Sound familiar? It sounds just like a REST API, right? **It may be helpful to consider Event Listeners to be APIs for the browser page that you can trigger from an attacker frame (iframe or window.open Window or otherwise).**

Just as no good web hacker would leave a hidden REST API untested, let's not forget to check for postMessage listeners. A postMessage listener is defined using the `addEventListener("message", (e)=>{})` syntax, however, it is often easier to track them down in the browser using the following two tools:
1. Frans Rosen's postMessage Tracker ([https://github.com/fransr/postMessage-tracker](https://github.com/fransr/postMessage-tracker))
2. DevTools' "Element -> Event Listener -> message" drop-down. ([https://www.sjoerdlangkemper.nl/2018/05/09/attacking-postmessage-interfaces/](https://www.sjoerdlangkemper.nl/2018/05/09/attacking-postmessage-interfaces/))

Once you've determined that your target page has an event listener, it is time to test it. Luckily for us, this is a White Box endeavor as we've got the JavaScript code. We can proceed to set some breakpoints in our JavaScript debugger (See this article of you dont know how to do this: [https://buddy.works/tutorials/debugging-javascript-efficiently-with-chrome-devtools](https://buddy.works/tutorials/debugging-javascript-efficiently-with-chrome-devtools)) and send some example postMessages to our victim page using something like:
```
let vw = window.open("https://vulnerable.com/postMessageListenerPage");
vw.postMessage('{}', "*");
```
Then, when the eventListener fires on the victim page, we can use the debugger to walk through the code that is being run. Once we've identified a path that we'd like to traverse down, then we can modify our postMessage to contain the right values.

For example, a simplified version of a vulnerability I've seen lately: 
```
window.addEventListener("message", (e)=>{
	let data = JSON.parse(e.data)
	switch(data.action){
		case 'SET_ATTRIBUTE':
			document.getElementById("id").setAttribute(data.attr, data.value);
		case 'SET_FOCUS':
			document.getElementById("id").focus();
		//etc...
	}
})
```
The above code would result in XSS if the attacker sends the below two messages in sequence:
```
let vw = window.open("https://vulnerable.com/postMessageListenerPage");
vw.postMessage('{"action":"SET_ATTRIBUTE", "attr":"onfocus", "value":"alert(1)"}', "*");
vw.postMessage('{"action":"SET_FOCUS"}', "*");
```

### Summary
Action Items/Takeaways:
1. Download Frans Rosen's postMessage Tracker
2. When navigating on your target site, look for postMessages in the DevTools (via postMessage Tracker's log output)
3. Use DevTools' "Element -> Event Listener -> message" dropdown to determine where the EventListener is defined
4. Use DevTools' breakpoint features to trace the code that a postMessage activates to find any malicious paths. 

**Side Note:** When securing postMessage listeners, companies often use `event.origin` to check the origin of the postMessage. This is the correct method, however, they also often use regex to do this and mess up with the following regex mistakes:
1. Not escaping a `.` in a domain. For example, the value `wwwRgoogle.com` will pass the regex `/^www.google.com$/`
2. Forgetting the `$` character: For example, the value `www.google.com.poc.rhynorater.com` will pass the regex `/^www\.google\.com/`

Be sure to validate these regexes as well!

That's all for now! Tweet @ me if you've got questions!

Justin (Rhynorater)


