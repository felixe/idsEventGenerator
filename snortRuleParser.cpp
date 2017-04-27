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
#include <stdexcept>
#include <stdlib.h>
#include <stdint.h>

using namespace std;

struct ruleBody{
    bool negatedContent;
    //string contentOriginal;
    string content;
    string sid;
  };

  struct snortRule {
    string header;
    ruleBody body;
  };

void parsingError(int line, string parsingPart){
    fprintf(stderr,"\n\nError on line %d, failed to parse %s. This does not seem to be a valid Snort rule. Aborting!\n",line, parsingPart.c_str());
}

void printSnorRule(snortRule rule){
    fprintf(stdout,"SID: %s\n",rule.body.sid.c_str());
    //TODO: print revision
    fprintf(stdout,"Header: %s\n",rule.header.c_str());
    if(rule.body.negatedContent){
        fprintf(stdout,"NOT ");
    }
    //fprintf(stdout,"Original Content:\n%s\n",rule.body.content.c_str());
    fprintf(stdout,"Content (hex converted):\n%s\n",rule.body.content.c_str());

    fprintf(stdout,"\n");
}


int main (int argc, char* argv[]) {
    string line;
    int linecounter=0;

    //variables used in parsing loop
    size_t bodyStartPosition;
    size_t startPosition;
    size_t endPosition;
    size_t hexStartPosition;
    size_t hexEndPosition;
    size_t tempPosition;
    snortRule tempRule;
    string hexContent;
    string content;
    string tempContent;
    string byte;
    char tempChar;

    //disable buffering on stdout:
    setbuf(stdout, NULL);

    // Check the number of parameters
    if (argc != 2) {
        fprintf(stderr,"Usage: \"snortRuleParser filename\", where filename is the path to a file containing Snort rules\n.");
        exit(1);
    }

    ifstream ruleFile ("100rules.txt");

    if (ruleFile.is_open())
    {
        //one line is one snort rule
        while ( getline (ruleFile,line) )
        {
            linecounter++;
            //check if rule is alert and if it contains content keyword, almost all rules do and if not it is not interesting for us
            startPosition=line.substr(0,6).find("alert");
            endPosition=line.find("content:");
            if(startPosition==string::npos||endPosition==string::npos){
                fprintf(stdout,"Rule in line number %d, does not contain alert or content keyword, ignored.\n",linecounter);
            }else{

                //find header
                bodyStartPosition=line.find("(");
                if(startPosition==string::npos){
                    parsingError(linecounter, "header");
                    exit(0);
                }
                tempRule.header=line.substr(0,bodyStartPosition);

                //find content
                startPosition=line.find("content:",bodyStartPosition)+8;
                endPosition=line.find(";",startPosition);
                if(startPosition==8||endPosition==string::npos){
                    parsingError(linecounter,"content");
                }
                    //check if content is negated BWARE: than also modifiers are negated!!!
                if(line.substr(startPosition,1)=="!"){
                    tempRule.body.negatedContent=1;
                }else{
                    tempRule.body.negatedContent=0;
                }
                content=line.substr(startPosition,(endPosition-startPosition));
                    //cut away quotes
                content=content.substr(1,(content.size()-2));
                //TODO: show original content for comparison purposes
                //tempRule.body.contentOriginal=content;
                    //check if it contains hex
                hexStartPosition=content.find("|");
                while(hexStartPosition!=string::npos){
                    hexEndPosition=content.find("|",hexStartPosition+1);
                    if(hexEndPosition==string::npos){
                        parsingError(linecounter,"hex content (no termination sign)");
                    }
                        //already cutting off first pipe sign
                    hexContent=content.substr(hexStartPosition+1,(hexEndPosition-hexStartPosition)-1);
                        //remove spaces from hex string
                    tempPosition=hexContent.find(" ");
                    while(tempPosition!=string::npos){
                        hexContent.erase(tempPosition,1);
                        tempPosition=hexContent.find(" ",tempPosition);
                    }
                        //transform hex to ascii
                    string asciiString;
                    for (uint16_t i=0;i<(hexContent.length()/2);i++){
                        char * pEnd;
                        byte = hexContent.substr(i,2);
                        tempChar=(char) (int)strtol(byte.c_str(), &pEnd, 16);
                        if(isprint(tempChar)){
                            asciiString.push_back(tempChar);
                        }else{
                            fprintf(stdout,"WARNING: Line %d contains non printable ascii character (converted from hex).\n",linecounter);
                        }
                    }
                    //replace hex content with ascii content:
                    content=content.substr(0,hexStartPosition) + asciiString + content.substr(hexEndPosition+1,(hexEndPosition+1+content.length()));
                    hexStartPosition=content.find("|",hexEndPosition+1);
                }
                //now it should not contain hex anymore
                tempRule.body.content=content;

                //find SID number
                //TODO find revision number
                startPosition=line.find("sid:",bodyStartPosition)+4;
                endPosition=line.find(';',startPosition);
                if(startPosition==3||endPosition==string::npos){
                    parsingError(linecounter,"SID");
                    exit(0);
                }
                tempRule.body.sid=line.substr(startPosition,(endPosition-startPosition));


                printSnorRule(tempRule);
            }
    }
    ruleFile.close();
    }else{
        fprintf(stderr,"Unable to open rule file\n");
    }
  return 0;
}


