
Reads rules written in a Snort like syntax (as of Snort 2.9.11) from a rule file, puts parsed rule content in a struct and (optionally) prints the rule. 
It than (optionally) constructs HTTP requests that are sent to the configured host (possibly a webserver) that trigger events on a listening IDS related to the parsed rules.
"Snort like" means it accepts Snort rules, but does not require all fields of a Snort rule.

For the moment it only converts hex characters in content patterns that are part of the first 128 readable ASCII characters.
It only parses rules that use one of the following content modifiers: http\_\[method,uri,raw\_uri,stat\_msg,stat\_code,header,raw\header,client\_body,cookie,raw_cookie] or the equivalent modifiers for PCRE content and rules with the uricontent keyword. 
It ignores rules that are not triggering an alert or do not contain the 'content' or the 'pcre' or the 'uricontent' keyword or contain any other unsupported content related keyword.

libcurl is needed for compilation.
Build it by executing "g++ -std=c++11 -lcurl snortRuleParser.cpp"

For generating Strings out of PCREs it uses the python command exrex.
Install it with the command "pip exrex", this requires running python and pip environment are (e.g. sudo apt-get install python-pip)

Run it by executing "./a.out -f \<snortRuleFile\> -s \<webserver\>"
or "./a.out -h" to see more options.
  
For more options run "./a.out -h"

ISSUES:
-libcurl reports a timeout error if an HTTP HEAD request is sent although the request is sent and a response is received. BEWARE: The more likely cause for this error is that the Webserver at the given IP-address is not responding or down or IP is wrong.
-If you see a python "Traceback" error in your stderr than it means that the exrex command hat problems parsing/generating/... the regex from the given rule.

