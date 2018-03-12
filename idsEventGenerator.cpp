 /*
 * Copyright (C) 2017 Felix Erlacher
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *
 * Reads Snort rules and puts interesting fields in a struct for further usage.
 * This is rather a READER than a parser, as it assumes a basic structure of rules and does not
 * do in-depth checks of structure.
 *
 * REMARKS:
 * -If hex chars are encountered (everything between two '|' signs) it is converted to ascii, but only if part of the first 128 ascii chars and only if printable
 * -Whitespace in content patterns with http_uri modifier is generally converted to the + sign, if you want %20 as whitespace than change it in the rule.
 */

#include <iostream>
#include <fstream>
#include <string>
#include <stdlib.h>
#include <stdint.h>
#include <vector>
#include <locale>
#include <curl/curl.h>
#include <getopt.h>
#include <regex>
#include <algorithm>

#define VECTORRESERVE 10

class ruleBody{
    public:
		std::string msg;
		std::vector<bool> negatedContent;
		std::vector<std::string> contentOriginal;
		std::vector<bool> containsHex;
		std::vector<bool> contentNocase;
		std::vector<std::string> content;
		std::vector<int> contentModifierHTTP;
		//content modifier are encoded for faster processing:
		//1:http_method
		//2:http_uri
		//3:http_raw_uri
		//4:http_stat_msg
		//5:http_stat_code
		std::vector<std::string> pcre;
		std::vector<bool> negatedPcre;
		std::vector<bool> pcreNocase;
		std::string sid;
		std::string rev;
};

class ruleHeader {
    public:
    	std::string action;
		std::string protocol;
		std::string from;
		std::string fromPort;
		bool bidirectional;
		std::string to;
		std::string toPort;
    };

class snortRule {
    public:
    ruleHeader header;
    ruleBody body;
};



std::size_t bodyStartPosition;
bool printResponse=false;
bool continueOnError=false;
bool verbose=false;
int packetCounter=1;

/**
* writes error message to stderr
*/
void parsingError(int line, std::string parsingPart){
    fprintf(stderr,"Error on line %d, failed to parse %s. This does not seem to be a valid Snort rule. Aborting!\n",line, parsingPart.c_str());
}

/**
 * counts single rule fields (-->content vectors size) and checks if numbers match
 * if this check fails something went terribly wrong while parsing!!!
 */
void plausabilityCheck(snortRule* rule, int *linenumber){
	//plausability checks:
	if(rule->body.content.size()==0&&rule->body.pcre.size()==0){
		fprintf(stderr,"SnortRuleParser: There was an error in rule parsing: After parsing, rule with sid %s does not contain any content or pcre to check for. This should not have happened. Aborting!\n",rule->body.sid.c_str());
		if(continueOnError==false){
			exit(1);
		}
	}
	    if(rule->body.content.size()!=rule->body.contentOriginal.size()
	    ||rule->body.content.size()!=rule->body.negatedContent.size()
	    ||rule->body.content.size()!=rule->body.containsHex.size()
		//the pcre http modifiers are written into the contentModifierHTTP
	    ||(rule->body.content.size()+rule->body.pcre.size())!=rule->body.contentModifierHTTP.size()
	    ||rule->body.content.size()!=rule->body.contentNocase.size()
	    ||rule->body.negatedPcre.size()!=rule->body.pcre.size()
		||rule->body.pcreNocase.size()!=rule->body.pcre.size()){
	        fprintf(stderr,"\n\nThere was an Error in rule parsing at line %d, parsed content vectors do not match in size. This should not have happened. Aborting!\n",*linenumber);
	        fprintf(stderr,"content: %lu, contentOriginal: %lu, pcre: %lu, negatedPcre: %lu, pcreNocase: %lu, negatedContent: %lu, containsHex: %lu, ContentModifierHttp: %lu\n",rule->body.content.size(),rule->body.contentOriginal.size(),rule->body.pcre.size(),rule->body.negatedPcre.size(),rule->body.pcreNocase.size(),rule->body.negatedContent.size(),rule->body.containsHex.size(),rule->body.contentModifierHTTP.size());
	        if(continueOnError==false){
	        	exit(1);
	        }
	    }
}

/**
*prints snortRule struct to stdout
*/
void printSnortRule(snortRule* rule){
	std::string modifierHttp;

	//is already done in main(), so basically superfluous. But for some cases (mass checks) I might comment it there, so a "backup" here.
	int dummyInt=-1;
	plausabilityCheck(rule, &dummyInt);

	fprintf(stdout,"Action:\t\t\t\t%s\n",rule->header.action.c_str());
	    fprintf(stdout,"Protocol:\t\t\t%s\n",rule->header.protocol.c_str());
	    fprintf(stdout,"From:\t\t\t\t\"%s\"\n",rule->header.from.c_str());
	    fprintf(stdout,"FromPort:\t\t\t\"%s\"\n",rule->header.fromPort.c_str());
	    fprintf(stdout,"To:\t\t\t\t\"%s\"\n",rule->header.to.c_str());
	    fprintf(stdout,"ToPort:\t\t\t\t\"%s\"\n",rule->header.toPort.c_str());
	    if(rule->header.bidirectional){
	    	fprintf(stdout,"Direction:\t\t\t<>\n");
	    }else{
	    	fprintf(stdout,"Direction:\t\t\t->\n");
	    }

    fprintf(stdout,"Message:\t\t\t%s\n",rule->body.msg.c_str());

    //loop through content related vectors
    for(unsigned long i=0;i<rule->body.content.size();i++){
        if(rule->body.negatedContent.at(i)==true){
            fprintf(stdout,"NOT ");
        }
        //fprintf(stdout,"ContentOriginal:\t%s\n",rule->body.contentOriginal[i].c_str());
        if(rule->body.containsHex.at(i)==true){
            fprintf(stdout,"Content (hex converted):\t%s\n",rule->body.content.at(i).c_str());
        }else{
            fprintf(stdout,"Content:\t\t\t\"%s\"\n",rule->body.content.at(i).c_str());
        }
        switch(rule->body.contentModifierHTTP.at(i)){
                	case 0: modifierHttp=""; break;
                	case 1: modifierHttp="http_method"; break;
                	case 2: modifierHttp="http_uri"; break;
                	case 3: modifierHttp="http_raw_uri"; break;
                	case 4: modifierHttp="http_stat_msg"; break;
                	case 5: modifierHttp="http_stat_code"; break;
                	case 6: modifierHttp="http_header"; break;
                	case 7: modifierHttp="http_raw_header"; break;
                	case 8: modifierHttp="http_client_body"; break;
                	case 9: modifierHttp="http_cookie"; break;
                	case 10: modifierHttp="http_raw_cookie"; break;
                	default: fprintf(stderr,"IpfixIds: Wrong internal content modifier HTTP encoding. Aborting!\n"); exit(0);
                }
        fprintf(stdout,"ContentModifierHttp:\t\t%s\n",modifierHttp.c_str());
        if(rule->body.contentNocase[i]==true){
            fprintf(stdout,"Nocase:\t\t\t\ttrue\n");
        }else{
            fprintf(stdout,"Nocase:\t\t\t\tfalse\n");
        }
    }

    //loop through pcre related vectors
    for(unsigned long j=0;j<rule->body.pcre.size();j++){
        if(rule->body.negatedPcre.at(j)==true){
            fprintf(stdout,"NOT ");
        }
        fprintf(stdout,"pcre:\t\t\t\t%s\n",rule->body.pcre.at(j).c_str());
        switch(rule->body.contentModifierHTTP.at(j+(rule->body.content.size()))){
                        	case 0: modifierHttp=""; break;
                        	case 1: modifierHttp="http_method"; break;
                        	case 2: modifierHttp="http_uri"; break;
                        	case 3: modifierHttp="http_raw_uri"; break;
                        	case 4: modifierHttp="http_stat_msg"; break;
                        	case 5: modifierHttp="http_stat_code"; break;
                        	case 6: modifierHttp="http_header"; break;
                        	case 7: modifierHttp="http_raw_header"; break;
                        	case 8: modifierHttp="http_client_body"; break;
                        	case 9: modifierHttp="http_cookie"; break;
                        	case 10: modifierHttp="http_raw_cookie"; break;
                        	default: fprintf(stderr,"IpfixIds: Wrong internal pcre content modifier HTTP encoding. Aborting!\n"); exit(0);
                        }
		fprintf(stdout,"pcreModifierHttp:\t\t%s\n",modifierHttp.c_str());
		if(rule->body.pcreNocase[j]==true){
					fprintf(stdout,"NocasePcre:\t\t\ttrue\n");
				}else{
					fprintf(stdout,"NocasePcre:\t\t\tfalse\n");
				}

    }

    fprintf(stdout,"sid:\t\t\t\t%s\n",rule->body.sid.c_str());
    fprintf(stdout,"sid rev:\t\t\t%s\n",rule->body.rev.c_str());
    fprintf(stdout,"\n");
}

/**
* returns a string of x Xs
*/
std::string xtimesx(int x){
    std::string returnString="";
    for(int i=0;i<x;i++){
        returnString=returnString+"X";
    }
    return(returnString);
}

/**
*   replaces escaped chars in given text
*   according to the snort manual only 3 chars have to be escaped inside a content rule: ;,",\
*/
std::string replaceEscapedChars(std::string* text){
    std::string returnString;
    std::size_t startPosition;

    returnString=*text;

    //first replace escaped backslash(\\)
    startPosition=returnString.find("\\");
    while(startPosition!=std::string::npos){
        returnString.replace(startPosition,2,"XX");
        startPosition=returnString.find("\\");
    }

    //replace escaped quotes(\")
    startPosition=returnString.find("\\\"");
    while(startPosition!=std::string::npos){
        returnString.replace(startPosition,2,"XX");
        startPosition=returnString.find("\\\"");
    }

    //replace escaped semicolon(\;)
    startPosition=returnString.find("\\;");
    while(startPosition!=std::string::npos){
        returnString.replace(startPosition,2,"XX");
        startPosition=returnString.find("\\;");
    }

    return returnString;
}

/**
* This function replaces everything in quotes of the given string with Xs, this includes also escaped characters
* this can be used in keyword search to avoid finding keywords in escaped strings
*/
std::string replaceQuotedText(std::string* quotedText){
    std::size_t startPosition;
    std::size_t endPosition;
    std::string quotedTextReplaced;

    //replace all escaped chars
    quotedTextReplaced=replaceEscapedChars(quotedText);

    //replace everything else that is quoted
    startPosition=std::string::npos;
    startPosition=quotedTextReplaced.find("\"",0);
    endPosition=quotedTextReplaced.find("\"",startPosition+1);
    while(startPosition!=std::string::npos&&endPosition!=std::string::npos){
        quotedTextReplaced.replace(startPosition,endPosition-startPosition+1,xtimesx(endPosition-startPosition+1));
        startPosition=quotedTextReplaced.find("\"",0);
        endPosition=quotedTextReplaced.find("\"",startPosition+1);
    }

    return quotedTextReplaced;
}

/**
*parses the rule msg from given line and writes it to given snortRule class
*/
void parseMsg(std::string* line, int* linecounter, snortRule* tempRule){
    std::size_t startPosition=line->find("msg:",0)+4;
    std::size_t endPosition=line->find(";",startPosition);
    if(startPosition==(std::string::npos+4)||endPosition==std::string::npos){
        parsingError(*linecounter,"msg");
        exit(1);
    }
    tempRule->body.msg=line->substr(startPosition+1,(endPosition-startPosition)-2);
}

/**
*parses the rule header from given line and writes it to given snortRule class
*/
void parseHeader(std::string* line, int* linecounter, snortRule* tempRule){
		std::string headerString;
	    std::string from;
	    std::string fromPort;
	    std::string to;
	    std::size_t start;
	    std::size_t end;

	    start=line->find("(");
	    if(start==std::string::npos){
	        parsingError(*linecounter, "header");
	    }
	    headerString=line->substr(0,start);
	    end=headerString.find(" ");
	    tempRule->header.action=headerString.substr(0,end);
	    headerString.erase(0,end+1);

	    //TODO: skip rule if it does not apply to tcp... not really necessary
	    end=headerString.find(" ");
	    tempRule->header.protocol=headerString.substr(0,end);
	    headerString.erase(0,end+1);

	    end=headerString.find("<>");
	    if(end==std::string::npos){
	    	end=headerString.find("->");
	    	if(end==std::string::npos){
	    		parsingError(*linecounter,"header direction sign");
	    	}
	    	tempRule->header.bidirectional=false;
	    }else{
	    	tempRule->header.bidirectional=true;
	    }

	    //the end-1 omits the trailing space in this string
		from=headerString.substr(0,end-1);
		headerString.erase(0,end+3);
		to=headerString.substr(0,headerString.size()-1);

		end=from.find(" ");
		if(end==std::string::npos){
			parsingError(*linecounter,"no space between from address and port");
		}
		tempRule->header.from=from.substr(0,end);
		from.erase(0,end+1);
		fromPort=from.substr(0,from.size());
		//this only catches if the default variable is used, but thats life...
		if(fromPort.find("$HTTP_PORTS")!=std::string::npos){
			fprintf(stderr,"Error: Rule looks for packet coming from server ports ($HTTP_PORTS variable). Can not control server responses, please remove this rule. Line: %d\n",*linecounter);
        	if(continueOnError==false){
        		exit(1);
        	}
		}
		tempRule->header.fromPort=fromPort;

		end=to.find(" ");
		if(end==std::string::npos){
			parsingError(*linecounter,"no space between to address and port");
		}
		tempRule->header.to=to.substr(0,end);
		to.erase(0,end+1);
		tempRule->header.toPort=to.substr(0,to.size());
}

/**
* parses rule content (also multiple contents) from given line and writes it to given tempRule class in the corresponding vector of contents,
* it also converts hex characters to ascii characters, if possible, if not it omits them in the output content
*/
void parseContent(std::string* line, int* linecounter, snortRule* tempRule){
    std::size_t startPosition;
    std::size_t endPosition;
    std::size_t hexStartPosition;
    std::size_t hexEndPosition=0;
    std::string hexContent;
    std::string contentOrig;
    std::string contentHexFree;
    std::string tempContent;
    std::string byte;
    //we have to copy the line because we are messing around with it
    std::string lineCopy=*line;
    //this string is the same as line copy, only quotet text is replaces by X. length is the same!
    std::string lineCopySearch=replaceQuotedText(&lineCopy);
    char tempChar;
    std::size_t tempPosition;
    int contentCounter=0;

    //on the first check there should definitively be at least one content
    startPosition=lineCopySearch.find("content:",bodyStartPosition)+8;
    endPosition=lineCopySearch.find(";",startPosition);
    if(startPosition==(std::string::npos+8)||endPosition==std::string::npos){
        parsingError(*linecounter,"content");
        exit(1);
    }

    //loop to detect multiple content keywords, same check as above is repeated, will be true first time for sure, but we dont want to call parsingError the other times
    while(startPosition!=(std::string::npos+8)&&endPosition!=std::string::npos){
        contentHexFree="";
        //check if content is negated BWARE: than also modifiers are negated!!!
        if(lineCopy.substr(startPosition,1)=="!"){
            tempRule->body.negatedContent.push_back(true);
            //cut away negation sign
            lineCopy.erase(startPosition,1);
            lineCopySearch.erase(startPosition,1);
            //because we erase one character, the endPosition moves back on char
            endPosition--;
        }else{
            tempRule->body.negatedContent.push_back(false);
        }

        //we dont have to check for uricontent here because we can take care the same way we do for content. we have to take special care in parseContentModifier

        contentOrig=lineCopy.substr(startPosition,(endPosition-startPosition));
        //cut away quotes
        contentOrig=contentOrig.substr(1,(contentOrig.size()-2));

        //for debug and functionality check purposes write original content
        tempRule->body.contentOriginal.push_back(contentOrig);
        //check if it contains hex
        hexStartPosition=contentOrig.find("|");

        //is checked again below, but necessery here too
        if(hexStartPosition!=std::string::npos||contentOrig.find("|",hexStartPosition+1)!=std::string::npos){
            tempRule->body.containsHex.push_back(1);
            //if it contains hex than add hexfree content before hex content to contentHexFree
            contentHexFree=contentHexFree+contentOrig.substr(0,hexStartPosition);
        }else{
            tempRule->body.containsHex.push_back(0);
            //if it does not contain hex at all add it now to hex free content
            contentHexFree=contentHexFree+contentOrig;
        }
        //find all hex codes and convert them to ascii
        while(hexStartPosition!=std::string::npos){
            hexEndPosition=contentOrig.find("|",hexStartPosition+1);
            if(hexEndPosition==std::string::npos){
                fprintf(stdout,"Debug: content no hex=\t\t%s\nalready converted content:\t%s\n",contentOrig.c_str(),contentHexFree.c_str());
                parsingError(*linecounter,"hex content (no termination sign)");
                exit(1);
            }
            //copying hex string and cutting off first pipe sign
            hexContent=contentOrig.substr(hexStartPosition+1,(hexEndPosition-hexStartPosition)-1);
            //remove spaces from hex string
            tempPosition=hexContent.find(" ");
            while(tempPosition!=std::string::npos){
                hexContent.erase(tempPosition,1);
                tempPosition=hexContent.find(" ",tempPosition);
            }

            std::string asciiString;
            //transform hex to ascii loop, as it always consumes two chars we have to move over two chars after every loop
            //todo ev. convert line break/line feed hex codes to OS specific signs, convert more than 128 ascii signs
            for (uint16_t i=0;i<(hexContent.length());i=i+2){
                char * pEnd;
                byte = hexContent.substr(i,2);
                if(byte=="0d"||byte=="0D"){
                	asciiString=asciiString+"\\r";
                }else if(byte=="0a"||byte=="0A"){
                	asciiString=asciiString+"\\n";
                }else{
					tempChar=(char) (int)strtol(byte.c_str(), &pEnd, 16);
					if(isprint(tempChar)){
						asciiString.push_back(tempChar);
					}else{//warn if not printable
						fprintf(stderr,"WARNING: non-printable hex chars (except 0d and 0a) and hex > 7F are not supported and thus omitted. Hex: %s, rule sid: %s, line:%d\n",byte.c_str(), tempRule->body.sid.c_str(), *linecounter);
					}
                }
            }
            //adding converted string to content
            contentHexFree=contentHexFree+asciiString;
            //content now does not contain previous hex anymore, but may contain pipe sign if converted from hex
            hexStartPosition=contentOrig.find("|",hexEndPosition+1);
            //if more hex, than get content in between last and next hex string
            if(hexStartPosition!=std::string::npos){
                contentHexFree=contentHexFree+contentOrig.substr(hexEndPosition+1,hexStartPosition-hexEndPosition-1);
            //if this was last hex (and here we had at least one hex string) add possible tailing hex free string to content
            }else{
                contentHexFree=contentHexFree+contentOrig.substr(hexEndPosition+1,contentOrig.size()-hexEndPosition+1);
            }
        }//while hex loop
        //add the summed up content to the rule class
        tempRule->body.content.push_back(contentHexFree);
        //erase content keyword, so that loop can find next content keyword or break
        lineCopy.erase(startPosition-8,8);
        //to keep same length do the same for search string
        lineCopySearch.erase(startPosition-8,8);
        startPosition=lineCopySearch.find("content:",bodyStartPosition)+8;
        endPosition=lineCopySearch.find(";",startPosition);
        contentCounter++;
    }//while content loop
}

/**
* parses content modifiers from given line and writes it to given tempRule class in the corresponding vector
* Only nocase and http_* content modifier are supported. rawbytes, depth, offset, distance, within, fast_pattern are ignored by the parser.
*/
void parseContentModifier(std::string* line, int* linecounter, snortRule* tempRule){
    bool uricontent=false;
    std::size_t startPosition;
    std::size_t endPosition;
    std::size_t contentEndPosition;
    std::size_t httpModifierStartPosition;
    std::size_t httpModifierEndPosition;
    std::string temp;
    std::string allModifiers;
    //we have to copy the line because we are messing around with it
    std::string lineCopy=*line;
    //this string is the same as lineCopy, only quoted text is replaces by X. length is the same. this way, searches dont trigger falsely on content found in quotes
    std::string lineCopySearch=replaceQuotedText(&lineCopy);

    //on the first check there should definitively be at least one content
    startPosition=lineCopySearch.find("content:",bodyStartPosition)+8;
    endPosition=lineCopySearch.find("content:",startPosition);
    //for last content in rule the end is marked by the closing bracket of the rule body
    if(endPosition==std::string::npos){
        //do we have a +1 error here because of semicolon AND parentheses? No, because rule requires sid and rev keywords, and they are placed after modifiers
        endPosition=(lineCopySearch.find(";)",startPosition));
    }

    if(startPosition==(std::string::npos+8)||endPosition==std::string::npos){
        parsingError(*linecounter,"content (modifier)");
        exit(1);
    }

    //loop to detect multiple content keywords, same check as above is repeated, will be true first time for sure, but we dont want to call parsingError the other times
    while(startPosition!=(std::string::npos+8)&&endPosition!=std::string::npos){
        temp=lineCopy.substr(startPosition,endPosition-startPosition);
        allModifiers=replaceEscapedChars(&temp);
        contentEndPosition=allModifiers.find(";");
        if(startPosition==(std::string::npos+8)||endPosition==std::string::npos){
            parsingError(*linecounter,"content (modifier), content string end position");
            exit(1);
        }

        //check if its the uricontent keyword:
        if(lineCopy.substr(startPosition-11,3)=="uri"){
        	uricontent=true;
        }

        //erase content keyword and content pattern
        allModifiers.erase(0,contentEndPosition+1);

        //see if it contains the nocase modifier
        if(allModifiers.find("nocase;")==std::string::npos){
            tempRule->body.contentNocase.push_back(false);
        }else{
            tempRule->body.contentNocase.push_back(true);
        }


        if(uricontent){
        	tempRule->body.contentModifierHTTP.push_back(2);
        }else{
        	//find http content modifier:
			httpModifierStartPosition=allModifiers.find("http_");
			if(httpModifierStartPosition==std::string::npos){
				tempRule->body.contentModifierHTTP.push_back(0);
			}else{
				httpModifierEndPosition=allModifiers.find(";",httpModifierStartPosition);
				if(httpModifierEndPosition==std::string::npos){
					parsingError(*linecounter,"content (modifier), content httpModifier end position");
				}
				temp=allModifiers.substr(httpModifierStartPosition,(httpModifierEndPosition-httpModifierStartPosition));
				if(temp=="http_method"){
					tempRule->body.contentModifierHTTP.push_back(1);
				}else if(temp=="http_uri"){
					tempRule->body.contentModifierHTTP.push_back(2);
					//replace whitespaces in content patterns for http uris
					//printf("uri detected, replacing:\n");
					//temp=tempRule->body.content[tempRule->body.contentModifierHTTP.size()-1];
					//printf("uri detected, replacing:\n");
					for(int i = 0; i < tempRule->body.content.at(tempRule->body.contentModifierHTTP.size()-1).length(); i++)
					{
						if(tempRule->body.content.at(tempRule->body.contentModifierHTTP.size()-1).at(i)== ' '){
							tempRule->body.content.at(tempRule->body.contentModifierHTTP.size()-1).at(i) = '+';
						}
					}
					//tempRule->body.content.at(tempRule->body.contentModifierHTTP.size()-1)=temp;
				}else if(temp=="http_raw_uri"){
						tempRule->body.contentModifierHTTP.push_back(3);
				}else if(temp=="http_stat_msg"){
						//fprintf(stderr,"SnortRuleparser: content modifier http_stat_msg not supported in this version\n"); //just uncomment lines to support it
						tempRule->body.contentModifierHTTP.push_back(4);
				}else if(temp=="http_stat_code"){
						tempRule->body.contentModifierHTTP.push_back(5);
				}else if(temp=="http_header"){//BEWARE: this is not supported in Vermont because no IPFIX IE for http header exists
						tempRule->body.contentModifierHTTP.push_back(6);
				}else if(temp=="http_raw_header"){//BEWARE: this is not supported in Vermont because no IPFIX IE for http header exists
						tempRule->body.contentModifierHTTP.push_back(7);
				}else if(temp=="http_client_body"){//BEWARE: this is not supported in Vermont because no IPFIX IE for http header exists
						tempRule->body.contentModifierHTTP.push_back(8);
				}else if(temp=="http_cookie"){//BEWARE: this is not supported in Vermont because no IPFIX IE for http header exists
						tempRule->body.contentModifierHTTP.push_back(9);
				}else if(temp=="http_raw_cookie"){//BEWARE: this is not supported in Vermont because no IPFIX IE for http header exists
						tempRule->body.contentModifierHTTP.push_back(10);
				}else{
					parsingError(*linecounter,"unrecognized content modifier");
				}
		}
	}//if uricontent
        //erase content keyword and content string, so that next content can be found
        lineCopy.erase(startPosition-8,+8);
        lineCopySearch.erase(startPosition-8,+8);

        startPosition=lineCopySearch.find("content:",bodyStartPosition)+8;
        endPosition=lineCopySearch.find("content:",startPosition);
        //for last content in rule, the end is marked by the closing bracket of the rule body
        if(endPosition==std::string::npos){
            endPosition=(lineCopy.find(";)",startPosition))+1;
        }
    }//while
}
/**
 * check given uri for disallowed and unwise characters see rfc-2396
 * print warning if true
 */
void checkUri(std::string uri, std::string sid){
	//delimiters
	if(uri.find("#")!=std::string::npos||uri.find(">")!=std::string::npos||uri.find("<")!=std::string::npos||uri.find("%")!=std::string::npos||uri.find("\"")!=std::string::npos){
		//TODO: check if they are escaped
    	fprintf(stderr,"WARNING: The HTTP uri used for this rule may contain disallowed characters. sid: %s\n",sid.c_str());
	}
	//unwise
	if(uri.find("{")!=std::string::npos||uri.find("}")!=std::string::npos||uri.find("|")!=std::string::npos||uri.find("[")!=std::string::npos||uri.find("]")!=std::string::npos||uri.find("`")!=std::string::npos||uri.find("\\")!=std::string::npos){
	    fprintf(stderr,"WARNING: The HTTP uri used for this rule may contain unwise characters. sid: %s\n",sid.c_str());
	}
}
/**
* parses pcre patterns in given line and writes it to given tempRule class in the corresponding vectors
*/
void parsePcre(std::string* line, int* linecounter, snortRule* tempRule){
    std::size_t startPosition;
    std::size_t endPosition;
    std::size_t iPosition;
    //we have to copy the line because we are messing around with it
    std::string lineCopy=*line;
    //this string is the same as line copy, only quoted text is replaces by X. length is the same!
    std::string lineCopySearch=replaceQuotedText(&lineCopy);
    std::string pcreModifierString;
    std::string pcreString;
    std::string temp;

    //on the first check there should definitively be at least one pcre
    startPosition=lineCopySearch.find("pcre:",bodyStartPosition)+5;
    endPosition=lineCopySearch.find(";",startPosition);
    //if not throw an error
    if(startPosition==(std::string::npos+5)||endPosition==std::string::npos){
    	parsingError(*linecounter,"pcre");
        exit(1);
    }

    //loop to detect multiple pcre keywords, same check as above is repeated, will be true first time for sure, but we dont want to call parsingError the other times
    while(startPosition!=(std::string::npos+5)&&endPosition!=std::string::npos){
        if(lineCopy.substr(startPosition,1)=="!"){
            tempRule->body.negatedPcre.push_back(true);
            //erase negation sign
            lineCopy.erase(startPosition,1);
            lineCopySearch.erase(startPosition,1);
            //adjust endPosition
            endPosition--;
        }else{
            tempRule->body.negatedPcre.push_back(false);
        }
        //copying pcre string (+snort specific modifiers) and cutting off quotes
        temp=lineCopy.substr(startPosition+1,endPosition-startPosition-2);

        //avoid any escaped chars by simply looking for the last occurence of / in the (not anymore) quoted pcre string
        endPosition=temp.find_last_of("/");
        pcreString=temp.substr(1,endPosition-1);
        tempRule->body.pcre.push_back(pcreString);

        //getting pcre modifiers
        pcreModifierString=temp.substr(endPosition+1,temp.length()-endPosition);

        //detailed handling of single pcre modifiers
        iPosition=pcreModifierString.find("i");
        if(iPosition!=std::string::npos){
        	tempRule->body.pcreNocase.push_back(true);
        	pcreModifierString.erase(iPosition,1);
        }else{
        	tempRule->body.pcreNocase.push_back(false);
        }

        //if no modifiers left, no http modifier, so useless:
        if(pcreModifierString.size()==0){
        	fprintf(stderr,"Error with rule sid:%s on line %d, failed to parse pcre modifier: No http modifier for pcre, we need at least one\n",tempRule->body.sid.c_str(),*linecounter);
        	if(continueOnError==false){
        		exit(1);
        	}
        }

        if(pcreModifierString.find("s")!=std::string::npos||pcreModifierString.find("m")!=std::string::npos||pcreModifierString.find("x")!=std::string::npos
        		||pcreModifierString.find("A")!=std::string::npos||pcreModifierString.find("E")!=std::string::npos
				||pcreModifierString.find("G")!=std::string::npos||pcreModifierString.find("R")!=std::string::npos
				||pcreModifierString.find("B")!=std::string::npos||pcreModifierString.find("O")!=std::string::npos){
        	 fprintf(stderr,"Error with rule sid:%s on line %d, failed to parse pcre modifier: The Snort specific (non HTTP) pcre modifiers s,m,x,A,E,G,R,B,O are not supported.\n",tempRule->body.sid.c_str(),*linecounter);
        	 if(continueOnError==false){
				exit(1);
			}
        }
        for(std::string::size_type k = 0; k < pcreModifierString.size(); ++k) {
            switch(pcreModifierString[k]){
            case 'P'://client body
            	tempRule->body.contentModifierHTTP.push_back(8);
            	break;
            case 'H'://http header 6
            	tempRule->body.contentModifierHTTP.push_back(6);
				break;
            case 'D'://raw_header 7
            	tempRule->body.contentModifierHTTP.push_back(7);
				break;
            case 'C'://cookie 9
            	tempRule->body.contentModifierHTTP.push_back(9);
				break;
            case 'K'://raw cookie 19
            	tempRule->body.contentModifierHTTP.push_back(10);
            	break;
            case 'U'://uri
            	//TODO: it would make sense to check already here for unescaped unsupported or unwise chars, on the other hand snort does accept most of them anyway
            	tempRule->body.contentModifierHTTP.push_back(2);
            	break;
            case 'I'://raw uri
            	//checkUriPCRE(pcreString);
            	tempRule->body.contentModifierHTTP.push_back(3);
            	break;
            case 'M'://method
            	tempRule->body.contentModifierHTTP.push_back(1);
            	break;
            case 'S'://response code
            	tempRule->body.contentModifierHTTP.push_back(5);
            	break;
            case 'Y'://response message
            	tempRule->body.contentModifierHTTP.push_back(4);
            	break;
            default:
            	fprintf(stderr,"Error with rule sid:%s on line %d, failed to parse pcre modifier: There was an uncaught, unsupported snort specific modifier. This should not have happened!\n",tempRule->body.sid.c_str(),*linecounter);
            	if(continueOnError==false){
					exit(1);
				}
            }
        }

        //printf("%s\n",temp.c_str());
        //printf("%s\n",pcreString.c_str());
        //printf("%s\n",pcreModifierString.c_str());

        //erase pcre keyword from line so that we can move on to next line
        lineCopy.erase(startPosition-5,5);
        lineCopySearch.erase(startPosition-5,5);
        startPosition=lineCopySearch.find("pcre:",bodyStartPosition)+5;
        endPosition=lineCopySearch.find(";",startPosition);
    }

}
/**
* parses SID and SID rev. number from given line and writes it to given snortRule struct
*/
void parseSid(std::string* line, int* linecounter, snortRule* tempRule){
                std::string lineCopy=replaceQuotedText(line);
                std::size_t startPosition=lineCopy.find("sid:",bodyStartPosition)+4;
                std::size_t endPosition=lineCopy.find(';',startPosition);
                if(startPosition==3||endPosition==std::string::npos){
                    parsingError(*linecounter,"SID");
                    exit(1);
                }
                tempRule->body.sid=lineCopy.substr(startPosition,(endPosition-startPosition));

                //parse rev following SID
                startPosition=lineCopy.find("rev:",startPosition)+4;
                endPosition=lineCopy.find(';',startPosition);
                if(startPosition==3||endPosition==std::string::npos){
                    parsingError(*linecounter,"SID revision");
                    exit(1);
                }
                tempRule->body.rev=lineCopy.substr(startPosition,(endPosition-startPosition));
}

/*
*Function that is used to handle return data from sent requests
*/
size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp){

        //ev. print response which resides in buffer
		if(printResponse){
		}
        return size*nmemb;
}

/**
 * removes \r and \n at beginning and end of strings
 */
std::string removeCRLF(std::string str, std::string ruleSid){
	if(str.size()==0){
		fprintf(stderr,"Error, can not sanitize empty Header for rulesid:%s. Likely, this rule produced an empty pcre string, check pcre.\n",ruleSid.c_str());
		if(continueOnError==false){
			exit(0);
		}
	}
	//remove all \r and \n at end, libcurl will add them anyway
	while((str.at(str.size()-1)=='n'&&str.at(str.size()-2)=='\\')||(str.at(str.size()-1)=='r'&&str.at(str.size()-2)=='\\')){
		str.pop_back();
		str.pop_back();
	}
	//snort rules also search for \r\n at beginning of some fields, remove them too:
	while((str.at(0)=='\\'&&str.at(1)=='r')||(str.at(0)=='\\'&&str.at(1)=='n')){
		str.erase(0,2);
	}
	if(str==""){
		fprintf(stderr,"WARNING: Empty String after removing initial and trailing newlines. sid: %s\n",str.c_str());
	}
	return str;
}


/**
 * 2 steps:
 * 1:remove excess \r\n at end and beginning. libcurl adds a \r\n anyway, so we have to remove them.
 * 2:if colon OR colon+whitespace at end of header are found a value is added.
 * 	WHY?: if a header without a value is set, curl assumes you want to remove the original header, so we have to set a value after colon or colon and space:
 */
std::string sanitizeHeader(std::string header, std::string ruleSid){
	if(header.size()==0){
		fprintf(stderr,"Error, can not sanitize empty Header for rulesid:%s. Likely, this rule produced an empty pcre string, check pcre.\n",ruleSid.c_str());
		if(continueOnError==false){
			exit(0);
		}
	}else{
		header=removeCRLF(header,ruleSid);
		//add dummystuff if missing
		if(header.at(header.size()-1)==':'){
			header=header+" DummyValue";
			if(verbose){
				printf("INFO: added dummy value to incomplete name: value header. sid:%s\n",ruleSid.c_str());
			}
		}else if(header.at(header.size()-1)==' '&&header.at(header.size()-2)==':'){
			header=header+"DummyValue";
			if(verbose){
				printf("INFO: added dummy value to incomplete name: value header. sid:%s\n",ruleSid.c_str());
			}
		}else if(header.find(':')==std::string::npos){
			header="DummyHeader: "+header;
			if(verbose){
				printf("INFO: added dummy value to incomplete name: value header. sid:%s\n",ruleSid.c_str());
			}
		}

	}
	if(header==""){
		fprintf(stderr,"WARNING: Empty header after sanitazion. sid: %s\n",ruleSid.c_str());
	}
	return header;
}

/**
 * this function replaces character classes that are not supported by the exrex and problematic chars by equivalent signs
 */
std::string sanitizePCRE(std::string pcre, std::string sid){
    std::size_t index;
	//replace \s with " ", so whitespace chars become just whitespace and not something like newlines
	while(true){
		index=pcre.find("\\s");
		if(index==std::string::npos){
			break;
		}else{
			pcre.replace(index,2," ");
			index+=3;
			if(verbose){
				printf("INFO: replaced \\s with single whitespace before generation. sid:%s\n",sid.c_str());
			}
		}
	}

	//replace +? with +
	while(true){
		index=pcre.find("+?");
		if(index==std::string::npos){
			break;
		}else{
			pcre.replace(index,2,"+");
			if(verbose){
				printf("INFO: replaced +? with + in pcre before generation. sid:%s\n",sid.c_str());
			}
		}
	}

	//replace *? with *
	while(true){
		index=pcre.find("*?");
		if(index==std::string::npos){
			break;
		}else{
			pcre.replace(index,2,"*");
			if(verbose){
				printf("INFO: replaced *? with * in pcre before generation. sid:%s\n",sid.c_str());
			}
		}
	}

	//replace .+ with [a-z] so that it produces easy to use char and not some weird sh**
	while(true){
		index=pcre.find(".+");
		if(index==std::string::npos){
			break;
		}else{
			pcre.replace(index,2,"[a-z]}");
			if(verbose){
				printf("INFO: replaced .+ with [a-z] in pcre before generation. sid:%s\n",sid.c_str());
			}
		}
	}

	//replace .* with [a-z] so that it produces easy to use char and not some weird sh**
	while(true){
		index=pcre.find(".*");
		if(index==std::string::npos){
			break;
		}else{
			pcre.replace(index,2,"[a-z]");
			if(verbose){
				printf("INFO: replaced .* with [a-z] in pcre before generation. sid:%s\n",sid.c_str());
			}
		}
	}

	//replace .? with [a-z] so that it produces easy to use char and not some weird sh**
	while(true){
		index=pcre.find(".?");
		if(index==std::string::npos){
			break;
		}else{
			pcre.replace(index,2,"[a-z]");
			if(verbose){
				printf("INFO: replaced .? with [a-z] in pcre before generation. sid:%s\n",sid.c_str());
			}
		}
	}

	while(true){
		index=pcre.find("[^&]");
		if(index==std::string::npos){
			break;
		}else{
			pcre.replace(index,4,"[a-z]");
			if(verbose){
				printf("INFO: replaced [^&] with [a-z] in pcre before generation. sid:%s\n",sid.c_str());
			}
		}
	}

	while(true){
			index=pcre.find("[^\\]");
			if(index==std::string::npos){
				break;
			}else{
				pcre.replace(index,4,"[a-z]");
				if(verbose){
					printf("INFO: replaced [^\\] with [a-z] in pcre before generation. sid:%s\n",sid.c_str());
				}
			}
		}

	while(true){
			index=pcre.find("[^\\n]");
			if(index==std::string::npos){
				break;
			}else{
				pcre.replace(index,5,"[a-z]");
				if(verbose){
					printf("INFO: replaced [^\\n] with [a-z] in pcre before generation. sid:%s\n",sid.c_str());
				}
			}
		}

	while(true){
				index=pcre.find("[^\\r\\n]");
				if(index==std::string::npos){
					break;
				}else{
					pcre.replace(index,7,"[a-z]");
					if(verbose){
						printf("INFO: replaced [^\\r\\n] with [a-z] in pcre before generation. sid:%s\n",sid.c_str());
					}
				}
			}
//	while(true){
//					index=pcre.find("[^\\0A\\0D]");
//					if(index==std::string::npos){
//						break;
//					}else{
//						pcre.replace(index,9,"[a-z]");
//						if(verbose){
//							printf("INFO: replaced [^\\0A\\0D] with [a-z] in pcre before generation. sid:%s\n",sid.c_str());
//						}
//					}
//				}
//	while(true){
//					index=pcre.find("[^\\x26\\x3B]");
//					if(index==std::string::npos){
//						break;
//					}else{
//						pcre.replace(index,11,"[a-z]");
//						if(verbose){
//							printf("INFO: replaced [^\\x26\\x3B] with [a-z] in pcre before generation. sid:%s\n",sid.c_str());
//						}
//					}
//				}
	while(true){
					index=pcre.find("[^\\x2f]");
					if(index==std::string::npos){
						break;
					}else{
						pcre.replace(index,7,"[a-z]");
						if(verbose){
							printf("INFO: replaced [^\\x2f] with [a-z] in pcre before generation. sid:%s\n",sid.c_str());
						}
					}
				}
//	while(true){
//					index=pcre.find("[^\\s\\x26\\x3B\\x2f]");
//					if(index==std::string::npos){
//						break;
//					}else{
//						pcre.replace(index,17,"[a-z]");
//						if(verbose){
//							printf("INFO: replaced [^\\s\\x26\\x3B\\x2f] with [a-z] in pcre before generation. sid:%s\n",sid.c_str());
//						}
//					}
//				}

	return pcre;
}
/**
 * generate string from given pcre (with external command)
 */
std::string generateStringFromPCRE(std::string pcreString){
	//pcre payload generation with the help of an external perl script. This script MUST be present in the same folder as this executable file.
	//this opens a shell and executes above command (or script), if script is not found a line is written and program continues
    //hardcoded command name. Of course, this command must exist!!!
    FILE *commandFile;
	const int BUFSIZE = 1000;
	char buf[ BUFSIZE ];
	std::string command="exrex -r ";
	std::string popenCommand=command+pcreString;
	if(verbose){
		printf("INFO: Command for pcre string generation: %s\n",popenCommand.c_str());
	}
	commandFile = popen( popenCommand.c_str(), "r" );
	if ( commandFile == NULL ) {
		fprintf( stderr, "Could not execute command %s to generate regex payload.\n",popenCommand.c_str() );
		exit(-1);
	}
	//write result to buf
	while( fgets( buf, BUFSIZE,  commandFile )) {
		//fprintf( stdout, "%s", buf  );
	}
	std::string pcrePayload=buf;
	pclose( commandFile );
	return pcrePayload;
}
/**
 * sends an HTTP request to the given host containing the pattern(s) of the given rule
 */
void sendRulePacket(snortRule* rule, std::string host,bool verbose){
    //initialize all stuff needed for sending packets with curl
	//NOTE:it would be much more performant to give this method a handle, but libcurl resends cookies from the last http request!!! This was the only option found. And in the end its not really slower...
    curl_global_init(CURL_GLOBAL_ALL);
    CURL *handle;
    //using easy interface, no need for simultaneous transfers
    handle = curl_easy_init();
    CURLcode result;
    std::string hostUri="";
    std::string cookies="";
    //we generally add 6 chars to the client body because
    //Snort does not do any pattern matching if there are less than 6 chars
    std::string clientBody="12345";
	//list for custom headers, here we put the sid number to correlate the request with a rule and additional http_header fields
	struct curl_slist *header=NULL;
	long httpResponseCode=0;
	std::string pcrePayload;


    if(verbose){
    	fprintf(stdout,"\n--------------------------------------------------------\n");
    	fprintf(stdout,"INFO: Starting to generate packet # %d, for ruleSid %s\n", packetCounter, rule->body.sid.c_str());
    	fprintf(stdout,"--------------------------------------------------------\n");
    }
	//reset everything, necessary because curl remembers last cookie and sends it again
	//curl_easy_reset(handle);
	//with the following curl reports an error for every fail message of the server e.g. 404, 403 but not 100...
	//curl_easy_setopt (handle, CURLOPT_FAILONERROR, 1L);
	//tell curl to use custom function to handle return data instead of writing it to stdout
	curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_data);
	//use http protocol, is default anyway so just to make sure
	curl_easy_setopt(handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);
	//set http GET as default method, will be changed in case, this is necessary when using CURLOPT_CUSTOMREQUEST
	curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, NULL);
	curl_easy_setopt(handle, CURLOPT_HTTPGET, 1L);
	//remove Accept: */* header which libcurl sets by default
	header=curl_slist_append(header,"Accept:");
	//remove Content-Type header which libcurl sets by default for POST request, and which makes good sense but is not mandatory. It can still be added by a rule later on.
	header=curl_slist_append(header,"Content-Type:");
	//libcurl also adds the Expect header, removing that header leads to not receiving a response for ages. And there is no rule saying content:!"Expect http_header

    for(int j=0;j<rule->body.content.size();j++){
    	if(rule->body.negatedContent.at(j)){
    		//skip content because content is negated (and hope it is not generated by accident(or random) before)
    	}else{
			switch(rule->body.contentModifierHTTP.at(j)){
						case 1:{//http_method
								if(rule->body.content[j]=="GET"){
									curl_easy_setopt(handle, CURLOPT_HTTPGET, 1L);
								}else if(rule->body.content[j]=="POST"){
									curl_easy_setopt(handle, CURLOPT_POST, 1L);
								//for everything else use the given method string
								}else{
									curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, rule->body.content[j].c_str());
								}
								break;
						}
						case 2://http_uri
						case 3://http_raw_uri
								if(rule->body.content[j].find("//")!=std::string::npos){
									fprintf(stderr,"WARNING: The HTTP uri used for this rule contains multiple slashes. Make sure that your IDS config does not normalize them. sid: %s\n",rule->body.sid.c_str());
								}
								{hostUri=hostUri+rule->body.content[j];
								break;
						}
						case 6://header
						case 7://raw_header
								{header=curl_slist_append(header, sanitizeHeader(rule->body.content[j],rule->body.sid).c_str());
								break;
						}
						case 4://http_stat_msg
						case 5:
								{fprintf(stderr,"Error: Can not control server responses, please remove this rule (sid: %s)\n",rule->body.sid.c_str());
								if(continueOnError==0){
									exit(0);
								}
								break;
						}
						case 8: //client_body. This possibly adds a body also to GET requests, which is not illegal but useless because server is not allowed to interpret it.
							    //remove \n and \r from string
								{clientBody=clientBody+(removeCRLF(rule->body.content[j],rule->body.sid));
								break;
						}
						case 9://cookie
						case 10://raw_cookie
								{//this way it only copies the value from the rule, meaning it might not always result in a name=value pair.
								 //this is still legal and accepted by servers.
									cookies=cookies+rule->body.content[j];
								break;
						}
						default:{
							fprintf(stderr,"HTTP content modifier unsupported! Aborting\n");
							exit(0);
						}

			}
    	}
    }
    for(int k=0;k<rule->body.pcre.size();k++){
    	if(rule->body.negatedPcre.at(k)==true){
    		//skip pcre because pcre is negated (and hope it is not generated by accident before)
    	}else{
			//we dont have to care about nocasePcre because chars will be generated exactly how given in pcre...
				std::string pcreString=rule->body.pcre.at(k);
				//remove newline chars in pcre, fgets only reads one line and in most of our cases they are useless anyway
				std::string::size_type at=0;
				std::string crlf="\\r\\n";
				while (true){
					at=pcreString.find(crlf,at);
					if(at!= std::string::npos){
						//do not remove \r\n if it is negated
						if(pcreString.at(at-1)!='^'){
							pcreString.erase(at, crlf.length());
							fprintf(stderr,"WARNING: Removed \\r\\n in pcre for rule sid:%s\n",rule->body.sid.c_str());
						}else{
							at=at+crlf.length();
						}
					}else{
						break;
					}

				}
				//replace non-supported signs and replace stuff that makes problems with equivalent save stuff
				pcreString=sanitizePCRE(pcreString, rule->body.sid);

				//search for unsupported character classes and warn
				if(pcreString.find("\\C")!=std::string::npos||pcreString.find("\\D")!=std::string::npos||pcreString.find("\\h")!=std::string::npos
						||pcreString.find("\\H")!=std::string::npos||pcreString.find("\\N")!=std::string::npos||pcreString.find("\\p")!=std::string::npos
						||pcreString.find("\\R")!=std::string::npos||pcreString.find("\\S")!=std::string::npos||pcreString.find("\\v")!=std::string::npos
						||pcreString.find("\\V")!=std::string::npos||pcreString.find("\\w")!=std::string::npos||pcreString.find("\\W")!=std::string::npos
						||pcreString.find("\\X")!=std::string::npos
				){
					fprintf(stderr,"WARNING: The pcre in this rule contains one of the not supported character classes: \\C, \\D, \\h, \\H, \\N, \\p, \\P, \\R, \\S, \\v, \\V, \\w, \\W, \\X. sid:%s\n",rule->body.sid.c_str());

				}

				//search for unsupported quantifiers and warn
				if(pcreString.find("?+")!=std::string::npos||pcreString.find("??")!=std::string::npos||pcreString.find("*+")!=std::string::npos
						||pcreString.find("++")!=std::string::npos
				){
					fprintf(stderr,"WARNING: The pcre in this rule contains one of the not supported quantifiers: ?+, ??, *+, ++. sid:%s\n",rule->body.sid.c_str());

				}

				//quote it, if not shell will expand this to nasty stuff
				pcreString="\""+pcreString+"\"";
				//is it ok if whitespaces occur in uri pcres? -->yes it seems so...
				if((pcreString.find(' ')!=std::string::npos)&&(rule->body.contentModifierHTTP.at(rule->body.content.size()+k)!=2)){
					fprintf(stderr,"WARNING: non-encoded whitespace in non-uri pcre in rule with sid:%s. Could lead to problems with pcre generation engine.\n",rule->body.sid.c_str());
				}
				//go!
				pcrePayload=generateStringFromPCRE(pcreString);

				if(pcrePayload==""){
					fprintf(stderr,"WARNING: pcre engine produced empty pcre for pcre:%s, rule sid:%s\n",pcreString.c_str(),rule->body.sid.c_str());
				}
				//strange newlines are introduced, remove them
				pcrePayload.erase(std::remove(pcrePayload.begin(), pcrePayload.end(), '\n'), pcrePayload.end());
				pcrePayload.erase(std::remove(pcrePayload.begin(), pcrePayload.end(), '\r'), pcrePayload.end());
				//libcurl does not like # sign, remove it:
				pcrePayload.erase(std::remove(pcrePayload.begin(), pcrePayload.end(), '#'), pcrePayload.end());


				switch(rule->body.contentModifierHTTP.at(rule->body.content.size()+k)){
					case 1:{//http_method
						if(pcrePayload=="GET"){
							curl_easy_setopt(handle, CURLOPT_HTTPGET, 1L);
						}else if(pcrePayload=="POST"){
							curl_easy_setopt(handle, CURLOPT_POST, 1L);
						//for everything else use the given method string
						}else{
							curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, pcrePayload.c_str());
						}
						break;
					}
					case 2://http_uri
					case 3://http_raw_uri
							{

								if(pcrePayload.find("//")!=std::string::npos){
								fprintf(stderr,"WARNING: The pcre HTTP uri used for this rule contains multiple slashes. Make sure that your IDS config does not normalize them. sid: %s\n",rule->body.sid.c_str());
								}
							    //check for whitespace, if at least one found, replace them all with +, which is http conform and  while ' ' in uri is not...
								for(uint32_t i=0;i<pcrePayload.length();i++){
									if(pcrePayload.at(i)==' '){
										std::replace( pcrePayload.begin(), pcrePayload.end(), ' ', '+');
									}
								}
								//this might lead to multiple slashes, but it should not make a difference for detection.
								hostUri=hostUri+pcrePayload;
							break;
					}
					case 6://header
					case 7://raw_header
							{
							header=curl_slist_append(header, sanitizeHeader(pcrePayload,rule->body.sid).c_str());
							break;
					}
					case 4://http_stat_msg
					case 5://http_stat_code
							{fprintf(stderr,"Error: can not control server responses, please remove this rule (sid: %s)\n",rule->body.sid.c_str());
							if(continueOnError==0){
								exit(0);
							}
							exit(0);
							break;
					}
					case 8://client_body. This possibly adds a body also to GET requests, which is not illegal but useless because server is not allowed to interpret it.
							//it is not useless for our purposes!!
							{clientBody=clientBody+pcrePayload;
							break;
					}
					case 9://cookie
					case 10://raw_cookie
							{//this way it only copies the value from the rule, meaning it might not always result in a name=value pair.
							 //this is still legal and accepted by servers.
								cookies=cookies+pcrePayload;
							break;
					}
					default:{
							fprintf(stderr,"PCRE content modifier unsupported! Aborting");
							exit(0);
					}
				}//switch
			//}
    	}
    }
    //check uri for unsafe and unwise characters rfc-1738, rfc-2396
    // * Hmm, this should probably be done during parsing, and not before sending...
    checkUri(hostUri,rule->body.sid.c_str());
    if(hostUri!=""){
		//put one slash at beginning if there is none
		if(hostUri.at(0)!='/'){
			hostUri.insert(0,"/");
		}
    }
    //prepend host to uri as libcurl does not
    hostUri.insert(0,host);
    //set cookies
	curl_easy_setopt(handle, CURLOPT_COOKIE, cookies.c_str());
	std::string content="Rulesid: ";
	content=content+rule->body.sid.c_str();
	//add custom headers from above NOTE: do not append crlf at the end, is done automatically
	header=curl_slist_append(header, content.c_str());
	//set custom set of headers from list above
	curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header);
    //tell curl which host and uri to use
    curl_easy_setopt(handle, CURLOPT_URL, hostUri.c_str());
    //add client body, if set
    if(clientBody!="12345"){
    	curl_easy_setopt(handle, CURLOPT_POSTFIELDS, clientBody.c_str());
    }
    if(verbose){
    	curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);
    }
    //set request timeout in secs
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 3);
    //do it!
	result=curl_easy_perform(handle);
	if(result != CURLE_OK){
			fprintf(stderr, "curl_easy_perform() failed for packet from rule sid %s, with url %s, with error: %s.\n",rule->body.sid.c_str(),hostUri.c_str(), curl_easy_strerror(result));
	}
	//curl_easy_getinfo (handle, CURLINFO_RESPONSE_CODE, &httpResponseCode);
	long usedPort;
	result = curl_easy_getinfo(handle, CURLINFO_LOCAL_PORT, &usedPort);
	if(result==CURLE_OK) {
		printf("Local port used for this request: %ld\n", usedPort);
	}else{
		printf("Failure in getting local port\n");
	}
	curl_easy_cleanup(handle);
	packetCounter++;
}

/**
 * prints usage message
 */
void usage(std::string progName){
	std::cerr << "Usage: " << progName << " -f <filename> [option]\n"
			<< "where filename is a file containing snort rules\n"
			<< "Options:\n"
			<< "\t-f,--fileile\t\tPath to file with rules\n"
			<< "\t-h,--help\t\tShow this help message\n"
			<< "\t-r,--response\t\tPrint response from server (requires -s)\n"
			<< "\t-s,--server\t\tSpecify the hostname or ip where crafted packets should be sent to, if not set no packets will be sent\n"
			<< "\t-p,--print\t\tPrint rules parsed from file\n"
			<< "\t-v,--verbose\t\tBe verbose when sending packets\n"
			<< "\t-c,--continue\t\tContinue on errors (also fatal ones). Discouraged, this has undefined behavior!\n"
			<< std::endl;
}

int main (int argc, char* argv[]) {
    std::string line, readFile, host;
    bool ruleFileSet=false;
    bool printRules=false;
    bool sendPackets=false;
    bool pushRule=true;

    int linecounter=0,index=0,iarg=0;
    snortRule tempRule;
    std::size_t alertPosition;
    std::size_t contentPosition;
    std::size_t pcrePosition;

    std::vector<snortRule> parsedRules;

    //hardly any rule will use more than 15 content keywords
    tempRule.body.content.reserve(VECTORRESERVE);
    tempRule.body.contentOriginal.reserve(VECTORRESERVE);
    tempRule.body.containsHex.reserve(VECTORRESERVE);
    tempRule.body.negatedContent.reserve(VECTORRESERVE);
    tempRule.body.contentModifierHTTP.reserve(VECTORRESERVE);
    tempRule.body.pcre.reserve(VECTORRESERVE);
    tempRule.body.negatedPcre.reserve(VECTORRESERVE);
    tempRule.body.pcreNocase.reserve(VECTORRESERVE);
    //disable buffering on stdout:
    setbuf(stdout, NULL);

    // Check the number of parameters
    if (argc <= 1) {
        fprintf(stderr,"Too few arguments\n");
        usage(argv[0]);
        exit(0);
    }

    //go through arguments
    while(1){
    	const struct option longOptions[]={
    	        {"print",    no_argument,        0, 'p'},
    	        {"help",     no_argument,        0, 'h'},
				{"response", no_argument,    	 0, 'r'},
				{"verbose",  no_argument,    	 0, 'v'},
				{"continue", no_argument,		 0, 'c'},
    	        {"server",   required_argument,  0, 's'},
    			{"file",     required_argument,  0, 'f'},
    	        {0,			 0,					 0,  0},
    	};
        iarg = getopt_long_only(argc, argv, "s:f:prhvc", longOptions, &index);
        if (iarg == -1){
            break;}
        switch (iarg){
    		case 'h':
            	usage(argv[0]);
            	exit(1);
        	case 'p':
        		printRules=true;
        		std::cout << "Configured to print parsed rules\n";
    			break;
        	case 'c':
        		continueOnError=true;
        		std::cout << "Configured to continue on error. Discouraged, this has undefined behavior!!\n";
    			break;
        	case 'v':
        		verbose=true;
        		std::cout << "Configured with verbose output\n";
    			break;
        	case 'r':
        		printResponse=true;
        		std::cout << "Configured to print response from server\n";
    			break;
        	case 'f':
        		readFile=optarg;
    			ruleFileSet=true;
    			std::cout << "Configured to read from file: "<< readFile <<"\n";
    			break;
        	case 's':
        		host=optarg;
        		sendPackets=true;
        		std::cout << "Configured to send packets to host: "<< host <<"\n";
        		break;
        	case '?':
        		// getopt_long_only returns '?' for an ambiguous match or an extraneous parameter
        		//ignore it
        		break;
        	default:
        		printf("unrecognized argument: %c \n",optarg);
        		usage(argv[0]);
        		exit(1);
        	}

    }

    if(ruleFileSet==false){
    	usage(argv[0]);
    	exit(0);
    }

    std::ifstream ruleFile (readFile.c_str());
    if (ruleFile.is_open()){
        //one line is one snort rule
        while ( getline (ruleFile,line) ){
        	pushRule=true;
        	linecounter++;
            //check if rule is a comment, if yes-> ignore
            if(line.substr(0,1)!="#"){
                //check if rule is alert and if it contains content keyword, almost all rules do and if not it is not interesting for us
                alertPosition=line.substr(0,6).find("alert");
                contentPosition=line.find("content:");
                pcrePosition=line.find("pcre:");
                //sort out rules that we are not interested in
                if(alertPosition==std::string::npos){
                    fprintf(stdout,"WARNING: Rule in line number %d, does not contain alert keyword. Ignored\n",linecounter);
                //the following check inherently also checks for uricontent: keyword
                }else if((contentPosition==std::string::npos)&&(pcrePosition==std::string::npos)){
                	fprintf(stdout,"WARNING: Rule in line number %d, does not contain content or pcre keyword. Ignored\n",linecounter);
            	}else if(line.find("flowbits:")!=std::string::npos||line.find("distance:")!=std::string::npos||line.find("within:")!=std::string::npos||line.find("offset:")!=std::string::npos||line.find("depth:")!=std::string::npos){
            		fprintf(stdout,"WARNING: Rule in line number %d, contains keyword for byte ranges (flowbits,distance,within,depth,offset) which is not supported. Ignored\n",linecounter);
            	}else if(line.find("dce_")!=std::string::npos||line.find("threshold:")!=std::string::npos||line.find("urilen:")!=std::string::npos||
            			line.find("detectionfilter")!=std::string::npos){
            		fprintf(stdout,"WARNING: Rule in line number %d, contains one of the following not supported keywords: dce_*, threshold:, urilen:, detectionfilter. Ignored\n",linecounter);
            	}else if(line.find("from_server")!=std::string::npos||line.find("to_client")!=std::string::npos){
        			fprintf(stdout,"WARNING: Rule looks for packet coming from server ('from_server' or 'to_client' keyword). Can not control server responses. Rule ignored in line: %d\n",linecounter);
            	}else if(line.find("content: ")!=std::string::npos){
        			fprintf(stdout,"WARNING: Content pattern does not start immediately after content keyword. I don't like that. Fix it. Rule ignored in line: %d\n",linecounter);

            	}else{
					//parse sid first, so we can print this info in error msgs
					parseSid(&line, &linecounter,&tempRule);
                    parseHeader(&line,&linecounter,&tempRule);
                    parseMsg(&line,&linecounter,&tempRule);

                    //it might contain no content (just pcre), than skip parseContent
					if(contentPosition!=std::string::npos){
						//if uricontent, skip next test because no http_ is intended
						if(line.substr(contentPosition-3,3)!="uri"){
							if(line.find("http_")==std::string::npos){
								fprintf(stdout,"WARNING: Rule in line number %d contains content keyword but no http_ content modifier. Content part ignored\n", linecounter);
							}
						}
						parseContent(&line, &linecounter,&tempRule);
						parseContentModifier(&line, &linecounter,&tempRule);
					}
                    if(pcrePosition!=std::string::npos){
                        parsePcre(&line, &linecounter,&tempRule);
                    }

                    //do not allow rules which have no http_ content modifier
					for (unsigned long i = 0; i < tempRule.body.content.size();i++) {
						if (tempRule.body.contentModifierHTTP[i] == 0) {
							pushRule = false;
							fprintf(stdout,"WARNING: Rule with sid:%s in line number %d, contains at least one content without http_* content modifier. Ignored\n", tempRule.body.sid.c_str(), linecounter);
						}
					}

					if(continueOnError==false){
						//before pushing rule, check if it makes sense. this will exit() if it fails.
						plausabilityCheck(&tempRule,&linecounter);
					}
					if (pushRule) {
						parsedRules.push_back(tempRule);
					}
            	}
            }
            tempRule.body.containsHex.clear();
            tempRule.body.content.clear();
            tempRule.body.negatedContent.clear();
            tempRule.body.contentOriginal.clear();
            tempRule.body.contentModifierHTTP.clear();
            tempRule.body.contentNocase.clear();
            tempRule.body.pcre.clear();
            tempRule.body.negatedPcre.clear();
            tempRule.body.pcreNocase.clear();
            tempRule.body.msg.clear();
            tempRule.body.rev.clear();
            tempRule.body.sid.clear();
    }
    ruleFile.close();
    }else{
        fprintf(stderr,"Unable to open rule file %s\n", readFile.c_str());
        exit(0);
    }
    std::cout << parsedRules.size() << " rules successfully parsed\n";

    if(printRules){
		for(unsigned long i=0;i<parsedRules.size();i++){
			printSnortRule(&parsedRules[i]);
		}
    }else{
    	std::cout << "Not printing rules\n";
    }

    if(sendPackets){
		for(unsigned long i=0;i<parsedRules.size();i++){
			sendRulePacket(&parsedRules[i],host,verbose);
		}
    }else{
    	std::cout << "Not sending out packets\n";
    }

    std::cout << "--------\n-ByeBye-\n--------\n";
    return 0;
}
