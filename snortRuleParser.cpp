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
 */

#include <iostream>
#include <fstream>
#include <string>
#include <stdlib.h>
#include <stdint.h>
#include <vector>
#include <locale>


class ruleBody{
    public:
    std::string msg;
    std::vector<bool> negatedContent;
    std::vector<std::string> contentOriginal;
    std::vector<bool> containsHex;
    std::vector<std::string> content;
    std::string sid;
    std::string rev;
};

class snortRule {
    public:
    std::string header;
    ruleBody body;
};

int linecounter;
std::size_t bodyStartPosition;
std::size_t startPosition;
std::size_t endPosition;

//TODO
//void parseHTTP restrictors
//parse pcre's
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
void printSnorRule(snortRule* rule){
    fprintf(stdout,"Message: %s\n",rule->body.msg.c_str());
    fprintf(stdout,"Header: %s\n",rule->header.c_str());

    for(int i=0;i<rule->body.content.size();i++){
        if(rule->body.negatedContent[i]==true){
            fprintf(stdout,"NOT ");
        }
        fprintf(stdout,"ContentOriginal:\t%s\n",rule->body.contentOriginal[i].c_str());
        if(rule->body.containsHex[i]==true){
            fprintf(stdout,"Content (hex converted):%s\n",rule->body.content[i].c_str());
        }else{
            fprintf(stdout,"Content:\t\t%s\n",rule->body.content[i].c_str());
        }
    }


    fprintf(stdout,"SID: %s\n",rule->body.sid.c_str());
    fprintf(stdout,"SID rev: %s\n",rule->body.rev.c_str());
    fprintf(stdout,"\n");
}

/**
*parses the rule msg from given line and writes it to given snortRule struct
*/
void parseMsg(std::string* line, int* linecounter, snortRule* tempRule){
    startPosition=line->find("msg:",startPosition)+4;
    endPosition=line->find(";",startPosition);
    if(startPosition==(std::string::npos+4)||endPosition==std::string::npos){
        parsingError(*linecounter,"msg");
        exit(0);
    }
    tempRule->body.msg=line->substr(startPosition+1,(endPosition-startPosition)-2);
}

/**
*parses the rule header from given line and writes it to given snortRule class
*/
void parseHeader(std::string* line, int* linecounter, snortRule* tempRule){
    bodyStartPosition=line->find("(");
    if(startPosition==std::string::npos){
        parsingError(*linecounter, "header");
        exit(0);
    }
    tempRule->header=line->substr(0,bodyStartPosition);
}

/**
* parses rule content (also multiple contents) from given line and writes it to given tempRule class in the corresponding vector of contents,
* it also converts hex characters to ascii characters, if possible, in not it omits them in the output content
*/
void parseContent(std::string* line, int* linecounter, snortRule* tempRule){
    std::size_t hexStartPosition;
    std::size_t hexEndPosition=0;
    std::string hexContent;
    std::string contentOrig;
    std::string contentHexFree;
    std::string tempContent;
    std::string byte;
    char tempChar;
    std::size_t tempPosition;
    int contentCounter=0;

    //on the first check there should definitively be at least on content
    startPosition=line->find("content:",bodyStartPosition)+8;
    endPosition=line->find(";",startPosition);
    if(startPosition==(std::string::npos+8)||endPosition==std::string::npos){
        parsingError(*linecounter,"content");
        exit(0);
    }

    //loop to detect multiple content keywords, same check as above is repeated, will be true first time for sure, but we dont want to call parsingError the other times
    while(startPosition!=(std::string::npos+8)&&endPosition!=std::string::npos){
        contentHexFree="";
        //check if content is negated BWARE: than also modifiers are negated!!!
        if(line->substr(startPosition,1)=="!"){
            tempRule->body.negatedContent.push_back(true);
            fprintf(stdout,"WARNING: Line %d contains negated content, this negates content modifiers too but has not been implementet\n",*linecounter);
        }else{
            tempRule->body.negatedContent.push_back(false);
        }
        contentOrig=line->substr(startPosition,(endPosition-startPosition));
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
            //if it does not contain hex at all add it now to hex free content:
            contentHexFree=contentHexFree+contentOrig;
        }
        //find all hex codes and convert them to ascii
        while(hexStartPosition!=std::string::npos){
            hexEndPosition=contentOrig.find("|",hexStartPosition+1);
            if(hexEndPosition==std::string::npos){
                fprintf(stdout,"Debug: content no hex=%s, already converted content: %s\n",contentOrig.c_str(),contentHexFree.c_str());
                parsingError(*linecounter,"hex content (no termination sign)");
                exit(0);
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
            //todo ev. convert line break/line feed hex codes to OS specific signs
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
        line->erase(startPosition-8,8);
        startPosition=line->find("content:",bodyStartPosition)+8;
        endPosition=line->find(";",startPosition);
        contentCounter++;
    }//while content loop
}

/**
* parses SID and SID rev. number from given line and writes it to given snortRule struct
*/
void parseSid(std::string* line, int* linecounter, snortRule* tempRule){
                //parse SID
                startPosition=line->find("sid:",bodyStartPosition)+4;
                endPosition=line->find(';',startPosition);
                if(startPosition==3||endPosition==std::string::npos){
                    parsingError(*linecounter,"SID");
                    exit(0);
                }
                tempRule->body.sid=line->substr(startPosition,(endPosition-startPosition));

                //parse rev following SID
                startPosition=line->find("rev:",startPosition)+4;
                endPosition=line->find(';',startPosition);
                if(startPosition==3||endPosition==std::string::npos){
                    parsingError(*linecounter,"SID revision");
                    exit(0);
                }
                tempRule->body.rev=line->substr(startPosition,(endPosition-startPosition));
}

int main (int argc, char* argv[]) {
    std::string line;
    linecounter=0;
    snortRule tempRule;
    //hardly any rule will use more than 15 content keywords
    tempRule.body.content.reserve(15);
    tempRule.body.contentOriginal.reserve(15);
    tempRule.body.containsHex.reserve(15);
    tempRule.body.negatedContent.reserve(15);
    //disable buffering on stdout:
    setbuf(stdout, NULL);

    // Check the number of parameters
    if (argc != 2) {
        fprintf(stderr,"This is a rule parser for Snort IDS rules.\n\nUsage:\n\"%s filename\"\nwhere 'filename' is the path to a file containing Snort rules.\n",argv[0]);
        exit(1);
    }

    std::ifstream ruleFile (argv[1]);
    if (ruleFile.is_open())
    {
        //one line is one snort rule
        while ( getline (ruleFile,line) )
        {
            linecounter++;

            //check if rule is alert and if it contains content keyword, almost all rules do and if not it is not interesting for us
            startPosition=line.substr(0,6).find("alert");
            endPosition=line.find("content:");
            if(startPosition==std::string::npos||endPosition==std::string::npos){
                fprintf(stdout,"Rule in line number %d, does not contain alert or content keyword. Aborting.\n",linecounter);
                exit(0);
            }else{
                parseMsg(&line,&linecounter,&tempRule);
                parseHeader(&line,&linecounter,&tempRule);
                parseContent(&line, &linecounter,&tempRule);
                parseSid(&line, &linecounter,&tempRule);
                printSnorRule(&tempRule);
            }
            tempRule.body.containsHex.clear();
            tempRule.body.content.clear();
            tempRule.body.negatedContent.clear();
            tempRule.body.contentOriginal.clear();
    }
    ruleFile.close();
    }else{
        fprintf(stderr,"Unable to open rule file\n");
    }
  return 0;
}
