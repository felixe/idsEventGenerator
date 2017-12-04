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
 * -Whitespace in content patterns with http_uri modifier is generally converted to the + sign, if you want %20 as whitespacethan change it in the rule.
 * -flowbits, distance,within,offset,depth keywords are ignored for now without further notice. FIXIT!
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
    std::string sid;
    std::string rev;
};

class snortRule {
    public:
    std::string header;
    ruleBody body;
};

std::size_t bodyStartPosition;
bool printResponse=false;

//TODO
//convert more than the first 128 ascii character (minus nonprintable chars)
/**
* writes error message to stderr
*/
void parsingError(int line, std::string parsingPart){
    fprintf(stderr,"\n\nError on line %d, failed to parse %s. This does not seem to be a valid Snort rule. Aborting!\n",line, parsingPart.c_str());
}

/**
*prints snortRule struct to stdout
*/
void printSnortRule(snortRule* rule){
	std::string modifierHttp;
    //plausability checks:
    if(rule->body.content.size()!=rule->body.contentOriginal.size()
    ||rule->body.content.size()!=rule->body.negatedContent.size()
    ||rule->body.content.size()!=rule->body.containsHex.size()
    ||rule->body.content.size()!=rule->body.contentModifierHTTP.size()
    ||rule->body.content.size()!=rule->body.contentNocase.size()
    ||rule->body.negatedPcre.size()!=rule->body.pcre.size()){
        fprintf(stderr,"\n\nThere was an Error in rule parsing, parsed content vectors do not match in size. This should not have happened. Aborting!\n");
        fprintf(stderr,"content: %lu, contentOriginal: %lu, negatedContent: %lu, containsHex: %lu, ContentModifierHttp: %lu\n",rule->body.content.size(),rule->body.contentOriginal.size(),rule->body.negatedContent.size(),rule->body.containsHex.size(),rule->body.contentModifierHTTP.size());
        exit(1);
    }

    fprintf(stdout,"Message:\t\t\t%s\n",rule->body.msg.c_str());
    fprintf(stdout,"Header:\t\t\t\t%s\n",rule->header.c_str());

    //loop through content related vectors
    for(unsigned long i=0;i<rule->body.content.size();i++){
        if(rule->body.negatedContent[i]==true){
            fprintf(stdout,"NOT ");
        }
        //fprintf(stdout,"ContentOriginal:\t%s\n",rule->body.contentOriginal[i].c_str());
        if(rule->body.containsHex[i]==true){
            fprintf(stdout,"Content (hex converted):\t%s\n",rule->body.content[i].c_str());
        }else{
            fprintf(stdout,"Content:\t\t\t%s\n",rule->body.content[i].c_str());
        }
        switch(rule->body.contentModifierHTTP.at(i)){
                	case 0: modifierHttp=""; break;
                	case 1: modifierHttp="http_method"; break;
                	case 2: modifierHttp="http_uri"; break;
                	case 3: modifierHttp="http_raw_uri"; break;
                	case 4: modifierHttp="http_stat_msg"; break;
                	case 5: modifierHttp="http_stat_code"; break;
                	case 6: modifierHttp="http_header"; break;
                	default: fprintf(stderr,"IpfixIds: Wrong content modifier HTTP encoding. Aborting!\n"); exit(0);
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
        if(rule->body.negatedPcre[j]==true){
            fprintf(stdout,"NOT ");
        }
        fprintf(stdout,"pcre:\t\t\t\t%s\n",rule->body.pcre[j].c_str());
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
    std::size_t bodyStartPosition=line->find("(");
    if(bodyStartPosition==std::string::npos){
        parsingError(*linecounter, "header");
        exit(1);
    }
    tempRule->header=line->substr(0,bodyStartPosition);
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
                tempChar=(char) (int)strtol(byte.c_str(), &pEnd, 16);
                if(isprint(tempChar)){
                    asciiString.push_back(tempChar);
                }//if not printable ignore char
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
* TODO: at the moment only nocase and http_content modifiers are parsed
*/
void parseContentModifier(std::string* line, int* linecounter, snortRule* tempRule){
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
        //erase content keyword and content pattern
        allModifiers.erase(0,contentEndPosition+1);

        //see if it contains the nocase modifier
        if(allModifiers.find("nocase;")==std::string::npos){
            tempRule->body.contentNocase.push_back(false);
        }else{
            tempRule->body.contentNocase.push_back(true);
        }

        //find http content modifier:
        httpModifierStartPosition=allModifiers.find("http_");
        if(httpModifierStartPosition==std::string::npos){
            tempRule->body.contentModifierHTTP.push_back(0);
        }else{
            httpModifierEndPosition=allModifiers.find(";",httpModifierStartPosition);
            if(httpModifierEndPosition==std::string::npos){
                parsingError(*linecounter,"content (modifier), content httpModifier end position");
                exit(1);
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
            	//fprintf(stderr,"SnortRuleparser: content modifier http_stat_code not supported in this version\n"); //just uncomment lines to support it
            	tempRule->body.contentModifierHTTP.push_back(5);
            }else if(temp=="http_header"){
            	//fprintf(stderr,"SnortRuleparser: content modifier http_header not supported in this version\n"); //just uncomment lines to support it
            	tempRule->body.contentModifierHTTP.push_back(6);
            }
        }

        //erase content keyword and content string, so that next content can be found
        lineCopy.erase(startPosition-8,+8);
        lineCopySearch.erase(startPosition-8,+8);

        startPosition=lineCopySearch.find("content:",bodyStartPosition)+8;
        endPosition=lineCopySearch.find("content:",startPosition);
        //for last content in rule, the end is marked by the closing bracket of the rule body
        if(endPosition==std::string::npos){
            endPosition=(lineCopy.find(";)",startPosition))+1;
        }
    }
}

/**
* parses pcre patterns in given line and writes it to given tempRule class in the corresponding vector
* TODO: needs to be improved: does pcre allow content modifiers? at the moment none are parsed, but there are vector length checks that expect a modifier for each pcre
* TODO: at the moment unused
*/
void parsePcre(std::string* line, int* linecounter, snortRule* tempRule){
    std::size_t startPosition;
    std::size_t endPosition;
    //we have to copy the line because we are messing around with it
    std::string lineCopy=*line;
    //this string is the same as line copy, only quotet text is replaces by X. length is the same!
    std::string lineCopySearch=replaceQuotedText(&lineCopy);
    std::string pcreString;

    //on the first check there should definitively be at least on content
    startPosition=lineCopySearch.find("pcre:",bodyStartPosition)+5;
    endPosition=lineCopySearch.find(";",startPosition);

    if(startPosition==(std::string::npos+5)||endPosition==std::string::npos){
        tempRule->body.pcre.push_back("");
        tempRule->body.negatedPcre.push_back(false);
        return;
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
        //copying pcre string and cutting off quotes
        pcreString=lineCopy.substr(startPosition+1,endPosition-startPosition-2);
        tempRule->body.pcre.push_back(pcreString);

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
			printf("\nRESPONSE:\n%s\n", buffer);
		}
        return size*nmemb;
}


/**
 * sends an HTTP request to the given host containing the pattern(s) of the given rule
 */
int sendRulePacket(snortRule* rule, CURL *handle, std::string host,bool verbose){
    CURLcode result;
    std::size_t doppler;
    std::string hostUri="";



	//tell curl to use custom function to handle return data insteat of writing it to stdout
	curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_data);
	//use http protocol, is default anyway so just to make sure
	curl_easy_setopt(handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);
	//set http GET as default method, will be changed in case, this is necessary when using CURLOPT_CUSTOMREQUES
	curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, NULL);
	curl_easy_setopt(handle, CURLOPT_HTTPGET, 1L);

    for(int j=0;j<rule->body.content.size();j++){
    	switch(rule->body.contentModifierHTTP[j]){
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
					case 2:	//http_uri
					case 3:{//http_raw_uri
							hostUri=hostUri+rule->body.content[j].c_str();
							break;
					}
					//TODO: check if this keyword is present in rules and possibly leave this check away if not
					case 4:{//http_stat_msg
							fprintf(stderr,"can not control server responses, please leave this rule (sid: %s) away",rule->body.sid.c_str()); exit(0);
							break;
					}default:{
						fprintf(stderr,"Content modifier unsupported! Aborting");
						exit(0);
					}

    	}
    }
    //make sure there are no double / in hostUri and prepend the host to the uri (curl divides both when doing http)
    while(hostUri.find("/")==0){
    	hostUri.erase(0,1);
    }
    hostUri.insert(0,host+"/");

	//list for custom headers, here we put the sid number to correlate the request with a rule
	struct curl_slist *header=NULL;
	std::string content="Rulesid: ";
	content=content+rule->body.sid.c_str();
	//add custom headers from above NOTE: do not append crlf at the end, is done automatically
	header=curl_slist_append(header, content.c_str());
	//set custom set of headers from list above
	curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header);

    //tell curl which host and uri to use
    curl_easy_setopt(handle, CURLOPT_URL, hostUri.c_str());
    if(verbose){
    	curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);
    }
    //set request timeout in secs
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 1L);
    //do it!
	result=curl_easy_perform(handle);
	if(result != CURLE_OK){
			fprintf(stderr, "curl_easy_perform() failed: %s\n",curl_easy_strerror(result));
			return -1;
	}

}

/**
 * prints usage message
 */
void usage(std::string progName){
	std::cerr << "Usage: " << progName << " -f <filename> [option]\n"
			<< "where filename is a file containing snort rules\n"
			<< "Options:\n"
			<< "\t-f,--file\t\tfile with snort rules\n"
			<< "\t-h,--help\t\tShow this help message\n"
			<< "\t-r,--response\t\tPrint response from server (requires -s)\n"
			<< "\t-s,--server\t\tSpecify the hostname or ip where crafted packets should be sent to, if not set no packets will be sent\n"
			<< "\t-p,--print\t\tPrint rules parsed from file"
			<< std::endl;
}

int main (int argc, char* argv[]) {
    std::string line, readFile, host;
    bool ruleFileSet=false;
    bool printRules=false;
    bool sendPackets=false;
    bool pushRule=true;
    bool verbose=false;

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
    	        {"server",   required_argument,  0, 's'},
    			{"file",     required_argument,  0, 'f'},
    	        {0,			 0,					 0,  0},
    	};
        iarg = getopt_long_only(argc, argv, "s:f:prhv", longOptions, &index);
        //printf("iarg: %d\n",iarg);
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

    //initialize all stuff needed for sending packets with curl
    curl_global_init(CURL_GLOBAL_ALL);
    CURL *easyHandle;
    //using easy interface, no need for simultaneous transfers
    easyHandle = curl_easy_init();

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
                }else if(contentPosition==std::string::npos){
                	fprintf(stdout,"WARNING: Rule in line number %d, does not contain content keyword. Ignored\n",linecounter);
                }else if(pcrePosition!=std::string::npos){
                	fprintf(stdout,"WARNING: Rule in line number %d, contains pcre keyword which is not supported (yet). Ignored\n",linecounter);
            	}else if(line.find("http_")==std::string::npos){
                	fprintf(stdout,"WARNING: Rule in line number %d, does not contain an http_ content modifier. Ignored\n",linecounter);
            	}else if(line.find("http_header")!=std::string::npos){ //but parsing is already implemented
                	fprintf(stdout,"WARNING: Rule in line number %d, contains an http_header content modifier which is not supported (yet). Ignored\n",linecounter);
            	}else if(line.find("http_client_body")!=std::string::npos){
            	    fprintf(stdout,"WARNING: Rule in line number %d, contains an http_client_body content modifier which is not supported (yet). Ignored\n",linecounter);
            	}else if(line.find("http_cookie")!=std::string::npos){
            	    fprintf(stdout,"WARNING: Rule in line number %d, contains an http_cookie content modifier which is not supported (yet). Ignored\n",linecounter);
            	}else if(line.find("http_raw_header")!=std::string::npos){
            	    fprintf(stdout,"WARNING: Rule in line number %d, contains an http_raw_header content modifier which is not supported (yet). Ignored\n",linecounter);
            	}else{
                    parseHeader(&line,&linecounter,&tempRule);
                    parseMsg(&line,&linecounter,&tempRule);
                    //it might contain no content (just pcre), than skip parseContent
                    if(contentPosition!=std::string::npos){
                        parseContent(&line, &linecounter,&tempRule);
                        parseContentModifier(&line, &linecounter,&tempRule);
                    }
                    //TODO: ev. uncomment if pcre's are supported again
                    //no pcre?
                    //if(pcrePosition!=std::string::npos){
                    //    parsePcre(&line, &linecounter,&tempRule);
                    //}
                    parseSid(&line, &linecounter,&tempRule);
                    //do not allow rules which have no content modifier
					for (unsigned long i = 0; i < tempRule.body.content.size();i++) {
						if (tempRule.body.contentModifierHTTP.at(i) == 0) {
							pushRule = false;
							fprintf(stdout,"WARNING: Rule in line number %d, contains at least one content without http_* content modifier. Ignored\n",linecounter);
						}
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
			sendRulePacket(&parsedRules[i],easyHandle,host,verbose);
		}
    }else{
    	std::cout << "Not sending out packets\n";
    }
    //clean up stuff needed for sending packets
    curl_easy_cleanup(easyHandle);

    std::cout << "--------\n-ByeBye-\n--------\n";
    return 0;
}
