# snortRuleParser

This project is continued as part of ccsVermont (https://github.com/felixe/ccsVermont) branch flowBasedSigIDS.

Reads Snort rules (as of Snort 2.9.9.0) from a rule file, puts content in a struct and prints it.
For the moment it only converts hex characters in content patterns that are part of the first 128 readable ASCII characters.
It ignores rules that are not triggering an alert or do not contain the 'content' or 'pcre' keyword (like 'byte_test' rules)i. These (few) rules are not interesting for our purposes.
Be aware that this is rather a READER than a parser as it does not in-depth structure checks!

Build it by executing "g++ snortRuleParser.cpp"
Run it by executing "/a.out <snortRuleFile>"
