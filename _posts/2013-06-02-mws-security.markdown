---
layout: post
title:  "Security Implications of Modern Web Standards"
color:  green
width:   6
height:  1
date:   2013-06-02 11:31:49 +0200
categories: web security
---

This is the key points I discovered when carrying out a literature review on the current security threats and vulnerabilities developers may come across when using 'modern web standards'.

### Web Storage

Web Storage mechanisms should not be used for session handling due to the threat of session hijacking. To maintain state over HTTP most web applications utilise session cookies. The cookie holds a long random token which is used by the application to recognised the user making the request. If the site is vulnerable to an XSS attack, the attacker may inject the code shown in Listing 2.1, to steal this session cookie and impersonate the user. This problem equally applies to Web storage; with a minor tweak to the code, the cookie can be stolen from the storage medium chosen. However, cookies offer a protection mechanism that is not available to Web Storage and that is the HTTPOnly flag. This flag prevents client side scripts from being able to access the cookie therefore the attacker can no longer steal the cookie using the XSS flaw (OWASP, 2012a).

Session cookies are not the only types of data that can be stolen from the Web Storage medium using a XSS based attack. As Trivero (2008) demonstrates it is possible to dump all of the contents of the client side storage used by an application with one script injected via XSS. Therefore sensitive data such as passwords, credit card numbers and pin numbers to name a few should not be stored using these mechanisms (Trivero, 2008; Schmidt, 2011; WHATWG, 2012).


Previously, the focus was upon the attackers ability to steal data from the Web Storage mediums, the attacker also has the ability to alter and add data to it. Take for example an application that checks if the 'isLoggedIn' value in the Local Storage is true, to determine if the user gets access to a page. An attacker can alter that value by exploiting an XSS flaw. Both (Mcardle, 2011; OWASP, 2012b) agree that the data in these objects can not be trusted.


### Clickjacking
If multiple web applications can share a graphical display then they are subject to a class of attack known as UI  redressing or clickjacking. Hansen and Grossman (2008) coined the term clickjacking and brought UI redressing to the attention of the security community. A typical clickjacking attack is achieved by forcing the UA to render a UI (of which the user is authenticated) into a container controlled by the attacker, this UI is then disguised in some manner, and finally the user is lured in to interacting with the disguised UI without their knowledge (Lekies et al. 2012).
Clickjacking attacks have the potential of causing severe damages, Huang et al. (2012) demonstrates the ability to use clickjacking to compromise a users web cam, anonymity and emails or other private data.

#### X-FRAME-OPTIONS
The recommended mechanism for preventing clickjacking uses the X-FRAME-OPTIONS header that was first introduced in IE8 by Microsoft and is now supported by all of the major browsers. This method again attempts to prevent framing, but this time it is achieved via the capabilities of the browser. The application attaches the X-FRAME-OPTIONS header to an outgoing HTTP request, the value of this header is then used to determine how the application handles frames (Lekies et al. 2012). The headers value can take one of two different options

* DENY:- Designed to Prevent the browser from rendering the document within a frame completely.
* SAMEORIGIN:- Designed allow the frame to be displayed within a frame on a page with the same origin.

OWASP (2012b) recommends the X-FRAME-OPTIONS header as the most suitable solution for preventing clickjacking. When using this header, Law (2010) outlines two best practices for developers to follow

* Ensure that the X-FRAME-OPTIONS header is used on critical configuration pages and other pages that require strong authentication such as account settings, or check-out confirmation pages.
* Only use the SAMEORIGIN option when there is valid use case for this and do not use it on any page that accepts a user generated URL to frame. As this is vulnerable to an attack known as 'Nested Clickjacking' (Lekies et al. 2012).

While X-FRAME-OPTIONS is the recommended defence against clickjacking, both (Lekies et al. 2012; Rydstedt et al. 2010) argue that both frame busting and X-FRAME-OPTIONS assume that clickjacking can be stopped by the prevention of framing alone, however this is not necessarily the case. Attacks, such as double clickjacking and key redirection can use pop up windows (Zalewski, 2012). More research is required to find a more complete solution to this attack. At present, the X-FRAME-OPTIONS header is the best option for developers, as it removes the framing mechanism of exploiting a user.


### Cross-Document Messaging
While this specification is built to enhance the security of a web application, if used incorrectly it can introduce some security issues. Schmidt (2011) outlines two threats when using cross-document messaging:
Disclosure of data: It is possible that data could be sent to the wrong embedded frame using the postMessage API.
Expanded Attack Surface: If a receiving frame does not check the origin of a message and validate the contents, then it is possible for attacks to be launched against it.

To use this mechanism securely both (Schmidt, 2011; OWASP, 2012b) suggest the following points:
The origin of the sender should be checked to see if it has been sent from the expected location.
The received message should be validated and not passed directly into innerHTML.
Validate that the data attribute of the event is as expected.
The target of the message should be set explicitly, wild cards such as * should not be used to avoid the disclosure of data.

### Cross Origin Resource Sharing (CORS)
Many web applications, in an attempt to improve usability, do not load pages via a normal HTTP request when a user clicks on a link, instead the page is loaded via an Ajax request. One typical mechanism that an application would employ to do this works as follows:

When a user clicks on a link to go the account page of an application, the URL is modified to show “http://exampleApp.com/#account.php”.
The application has some JavaScript that intercepts the user triggered event of clicking on the URL.
The JavaScript then takes everything after the hash, performs the Ajax request for the page, and loads the return content into a div.

This is the mechanism that was used by Facebook's Mobile web application 'touch.facebook.com'. Austin (2010) demonstrates the ability to remotely include any content into the DOM of the Facebook application and take full control by socially engineering an authenticated user of Facebook to visit a site with the code from Listing 2.4 in it. This attack would have normally failed before the introduction of CORS due to protection offered by the SOP, but as the attacker added the “Access-Control-Allow-Origin: \*” header to their page, therefore this policy was relaxed and the Ajax request was allowed. To prevent this type of attack from happening, all URLs should be made relative to the base by adding a '/' to the front of all requests. Also, web applications should validate that the origin matches the expected value, by checking the XHR origin attribute Austin (2010).

The ability of an attacker to inject headers, which is based on performing an HTTP Response Splitting attack, is described by OWASP (2011) as using “a weakness in the HTTP protocol definition to inject hostile data into the user’s browser”. Schmidt (2011) demonstrates the ability to add additional line breaks into a response to make the browser think that an additional header was defined by the server. The following request “http://www.csnc.ch/secred.html%0A%0DAccess-Control-Allow-Origin:+\*%0a%0d%0a%0d”(Schmidt 2011, p.13) could possibly override the original Access-Control-Allow-Origin header set by the server. To protect against this type of attack, OWASP (2011) recommend:
Ensuring that all HTTP headers do not contain unvalidated user generated content.
Eliminate any use of “\n\n” or “\r\n” from user generated content that is to be used in HTTP headers.
2.5.3 Implementation Guidelines
When allowing other domains to access a resource, the following guidelines outlined by OWASP (2012b) should be followed when implementing Access-Control-Allow-Origin header on a web application:

* Only use this header on content that is required to be loaded cross domain.
* When the header is used, only allow a select group of trusted domains built from a whitelist.

### Using MWS to provide additional security
While the holy grail of Web security would be a web application that could be developed free from exploitable vulnerabilities, in reality, security is achieved by implementing layers of protection. One of the most consistent problems that has plagued web applications is XSS. While input validation is important, Stamm (2010) argues that it is never perfect and the results of the last report carried out by Grossman (2012) show that this vulnerability is still the most common to be found. Therefore, two MWS and their ability to provide additional layers of defence to help mitigate XSS vulnerabilities are investigated.

#### Content Security Policy (CSP)
SOP is intended to prevent one domain from being able to access the content of another domain. However, as shown in Section 1, Mash Up applications have been bypassing this using a variety of mechanisms, including the use of in-line scripts. The problem is that attackers have also been using these mechanism to subvert the SOP and attack web applications.

CSP, which is currently in the candidate recommendation phase of being accepted as a W3C specification, is an attempt to grant web applications more control over the content that is allowed to run on its pages. While this not advertised as a silver bullet, several authors (Stamm, 2010; W3C, 2012c; Zalewski, 2012) state that this mechanism should be used by web applications as part of a defence in depth strategy.

Unlike some of the MWS discussed, it has not been shown that CSP increases the potential attack surface in any way. This is because that CSP only provides functionality to lock down what a site can do (Stamm, 2010).

#### Iframe Sandbox
Web applications must not trust user generated content, argues Cova et al. (2007), many vulnerabilities are due to insufficient validation on untrusted user content. In computing, a mechanism known as a sandbox is often used to allow untrusted programs to run in an isolated and safe manner, by giving the sandbox a tightly controlled set of resources. The introduction of the sandbox attribute of the iframe element in HTML5 gives web applications this ability.
The sandbox attribute allows the web application to limit the capabilities of the iframe, for example, preventing the execution of JavaScript or plug-ins such as Flash. It is even possible for a developer to pick and choose which capabilities the iframe has by specifying keywords such as 'allow-scripts' along with the sandbox attribute (WHATWG, 2012b).

However, Zalewski (2012) argues that to use the sandbox attribute all plug-ins must be disabled, which means that the sandbox cannot be used with some of its most common use cases, such as videos, games and advertisement. While this does inhibit the potential usefulness of the sandbox attribute, several authors (WHATWG,2012b; OWASP, 2012b; Schmidt, 2011) suggest that this feature should be used as apart of defence in depth strategy.

When using the sandbox attribute the following considerations should be taken:

* In older versions of UAs this attribute may be ignored. It is therefore important to see this as an additional layer of protection. Where possible, the application should check if the UA supports the attribute, and if not, prevent untrusted content from being displayed. (OWASP, 2012b).

* If both the 'allow-scripts' and 'allow-same-origin' are used together when setting up the sandbox, and the iframe contains a page from the same origin as page that created it. Then it is possible for an attacker to remove the sandbox attribute using JavaScript and any protection it offered. (WHATWG, 2012b).


### References
ATTACK AND DEFENSE LABS (ANDLabs) (2009) What is Shell of the Future? [WWW] Available from: http://www.andlabs.org/tools/sotf/sotf.html [Accessed 25/11/12]

AUSTIN, M. (2010) HACKING FACEBOOK WITH HTML5 [WWW] Available from: http://m-austin.com/blog/?p=19 [Accessed 27/11/12]

COVA, M. FELMETSGER, V. and VIGNA, G. (2007) Vulnerability Analysis of
Web-based Applications. In: BARSEI, L. and NITTO, E.D. (eds.) Test and Analysis of Web Services, Berlin: Springer, pp. 363-394

DE RYCK, P. et al. (2011) A security analysis of next generation web standards. European Network and Information Security Agency (ENISA)


FACEBOOK (2012) Facebook, Washington State AG Target Clickjackers [WWW] Available from: https://www.facebook.com/notes/facebook-security/facebook-washington-state-ag-target-9clickjackers/10150494427000766 [Accessed 26/11/12]

GROSSMAN, J. (2012) WHITEHAT SECURITY WEBSITE
STATISTICS REPORT How Does Your Website Security Stack Up Against Your Peers? [WWW] Available from: https://www.whitehatsec.com/assets/WPstats_summer12_12th.pdf [Accessed 27/11/12]

HANSEN, R. and GROSSMAN, J. (2008) Clickjacking. [WWW] Available from: http://www.sectheory.com/clickjacking.htm [Accessed 25/11/12]

HTML5SEC (n.d) HTML5 Security Cheatsheet – What your browser does when you look away [WWW] Available from: http://html5sec.org/#7 [Accessed 24/11/12]

HUANG, L. S. et al. (2012) Clickjacking: attacks and defenses. In: Proceedings of the 21st USENIX conference on Security symposium. August 2012. USENIX Association, pp. 22-22.

JACKSON, C. and WANG, H. J. (2007) Subspace: Secure cross-domain communication for web mashups. In: Proceedings of the 16th International World Wide Web Conference (WWW). May 2007. IW3C2, pp. 611-619.

LEKIES, S. et al. (2012) On the fragility and limitations of current Browser-provided Clickjacking protection schemes In: Proceedings of the 21st USENIX conference on Security symposium. August 2012. USENIX Association



MCARDLE, R. (2011) HTML5 OVERVIEW: A LOOK AT HTML5 ATTACK SCENARIOS [WWW] Trend Micro. Available from: http://www.trendmicro.com/cloud-content/us/pdfs/security-intelligence/reports/rpt_html5-attack-scenarios.pdf [Accessed 24/11/12]

OWASP (2011) Interpreter Injection [WWW]Available from: https://www.owasp.org/index.php/Interpreter_Injection#HTTP_Response_Splitting [Accessed 27/11/12]

OWASP (2012a) HttpOnly [WWW] Available from: https://www.owasp.org/index.php/HttpOnly [Accessed 25/11/12]

OWASP (2012b) HTML5 Security Cheat Sheet [WWW] Available from: https://www.owasp.org/index.php/HTML5_Security_Cheat_Sheet#General_Guidelines [Accessed 25/11/12]

RYDSTEDT, G. et al. (2010) Busting frame busting: a study of clickjacking vulnerabilities at popular sites. In: Oakland Web 2.0 Security and Privacy (W2SP 2010) . IEEE Computer Society

SCHMIDT, M. (2011) HTML5 Web Security [WWW] Compass Security Available from:
http://media.hacking-lab.com/hlnews/HTML5_Web_Security_v1.0.pdf
[Accessed 25/11/12]

STAMM, S. STERNE, B. & MARKHAM, G. (2010). Reining in the web with content security policy. In: Proceedings of the 19th international conference on World Wide Web. ACM. pp. 921-930.



TAIVALSAARI, A. and MIKKONEN, T. (2011) The Web as a Platform: The Saga Continues. In: Proceedings of the Euromicro Conference on Software Engineering and Advanced Applications (SEAA'11). September 2011. IEEE Computer Society, pp. 170-174.

TRIVERO, A. (2008) Abusing HTML 5 Structured Client-side Storage [WWW]Available from: http://packetstorm.wowhacker.com/papers/general/html5whitepaper.pdf [Accessed 25/11/12]

W3C (2012) HTML5 Web Messaging [WWW] Available from: http://www.w3.org/TR/webmessaging/#web-messaging [Accessed 26/11/12].

W3C (2012b) Cross-Origin Resource Sharing [WWW] Available from: http://www.w3.org/TR/cors/ [Accessed 26/11/12]

W3C (2012c) Content Security Policy 1.0 [WWW] Available from: http://www.w3.org/TR/2012/CR-CSP-20121115/ [Accessed 27/11/12]

WEB HYPERTEXT APPLICATION TECHNOLOGY WORKING GROUP (WHATWG) (2012a) HTML Living Standard [WWW] Available from: http://www.whatwg.org/specs/web-apps/current-work/multipage/webstorage.html [Accessed 25/11/12]

WHATWG (2012b) HTML Living Standard [WWW] Available from: http://www.whatwg.org/specs/web-apps/current-work/#attr-iframe-sandbox [Accessed 28/11/12]

WORLD WIDE WEB CONSORTIUM (W3C) (2010) Mobile Web Application Best Practices [WWW] W3C. Available from: http://www.w3.org/TR/mwabp/ [Accessed 24/11/12].

WORLD WIDE WEB CONSORTIUM (W3C) (2012) Cross-Origin Resource Sharing [WWW] Available from: http://www.w3.org/TR/cors/ [Accessed 24/11/12]

ZALEWSKI, M. (2012) The Tangled Web: A Guide to Securing Model Web Applications. No Starch Press, 2011.
