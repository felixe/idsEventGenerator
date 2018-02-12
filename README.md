# snortRuleEventGenerator: Reads and parses Snort rules and generates and sends packets triggering Snort events related to these rules.

Reads Snort rules (as of Snort 2.9.9) from a rule file, puts rule content in a struct and ev. prints it. 
It than constructs http requests that are sent to the configured host (possibly a webserver) that trigger events related to the parsed rules.

For the moment it only converts hex characters in content patterns that are part of the first 128 readable ASCII characters.
It only parses rules that use one of the following content modifiers: http\_\[method,uri,raw\_uri,stat\_msg,stat\_code].                                 
It ignores rules that are not triggering an alert or do not contain the 'content' keyword . 
Be aware that this is rather a READER than a parser as it does not in-depth structure checks!

libcurl is needed for compilation.
Build it by executing "g++ -std=c++11 -lcurl snortRuleParser.cpp"


Run it by executing "./a.out -f \<snortRuleFile\> -s \<webserver\>"
  
For more options run "./a.out -h"
