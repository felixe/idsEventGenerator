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

using namespace std;

struct ruleBody{
    bool negatedContent;
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
    fprintf(stdout,"%s\n",rule.header.c_str());
    fprintf(stdout,"%s\n",rule.body.sid.c_str());
    if(rule.body.negatedContent){
        fprintf(stdout,"NOT ");
    }
    fprintf(stdout,"%s\n",rule.body.content.c_str());

    fprintf(stdout,"\n");
}

int main () {
  //disable buffering on stdout:
  setbuf(stdout, NULL);
  string line;
  int linecounter=0;
  ifstream ruleFile ("100rules.txt");

  //variables used in parsing loop
  size_t bodyStartPosition;
  size_t startPosition;
  size_t endPosition;
  size_t hexPosition;
  snortRule tempRule;
  string quotedContent;
  string contentWithHex;

  if (ruleFile.is_open())
  {
    //one line is one snort rule
    while ( getline (ruleFile,line) )
    {
        linecounter++;
        //find header
        bodyStartPosition=line.find("(");
        if(startPosition==string::npos){
            parsingError(linecounter, "header");
            exit(0);
        }
        tempRule.header=line.substr(0,bodyStartPosition);


        //find content
        startPosition=line.find("content:",bodyStartPosition)+8;
        endPosition=line.find(';',startPosition);
        if(startPosition==8||endPosition==string::npos){
            parsingError(linecounter,"content");
            exit(0);
        }
            //check if content is negated BWARE: that also modifiers are negated!!!
        if(line.substr(startPosition,1)=="!"){
            tempRule.body.negatedContent=1;
        }else{
            tempRule.body.negatedContent=0;
        }
        quotedContent=line.substr(startPosition,(endPosition-startPosition));
        contentWithHex=quotedContent.substr(1,(quotedContent.size()-2));
            //check if it contains hex
        if(hexPosition=contentWithHex.find("|")!=string::npos){
            //implement
        }else{
            //does not contain hex
            tempRule.body.content=contentWithHex;
        }

        fprintf(stdout,"%s\n",contentWithHex.c_str());

        //find SID number
        startPosition=line.find("sid:",bodyStartPosition)+4;
        endPosition=line.find(';',startPosition);
        if(startPosition==3||endPosition==string::npos){
            parsingError(linecounter,"SID");
            exit(0);
        }
        tempRule.body.sid=line.substr(startPosition,(endPosition-startPosition));

        printSnorRule(tempRule);

    }
    ruleFile.close();
//testing the hex to char converter:
//string hexOfAscii[]={"21","22","23","24","25","26","27","28","29","2A","2B","2C","2D","2E","2F","30","31","32","33","34","35","36","37","38","39","3A","3B","3C","3D","3E","3F","40","41","42","43","44","45","46","47","48","49","4A","4B","4C","4D","4E","4F","50","51","52","53","54","55","56","57","58","59","5A","5B","5C","5D","5E","5F","60","61","62","63","64","65","66","67","68","69","6A","6B","6C","6D","6E","6F","70","71","72","73","74","75","76","77","78","79","7A","7B","7C","7D","7E"};

//            for (int i=0;i<(sizeof(hexOfAscii)/sizeof(hexOfAscii[0]));i++){
//                char hexChar=(char) (int)strtol(hexOfAscii[i].c_str(), NULL, 16);
//                fprintf(stdout,"%c\n",hexChar);
//            }
    }else{
        fprintf(stderr,"Unable to open file\n");
    }
  return 0;
}


