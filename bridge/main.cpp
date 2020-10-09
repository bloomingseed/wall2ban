#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

int showgui();


int main(int argc, char* argv[])
{
    if(argc == 1)   // no arguments passed by user agent; only the program name
    {
        try{
            showgui();
            cout << "Operation succeeded." << endl;
        } catch(...){   // catch any throw
            cout << "Operation failed." << endl;
        }
    } else
    {
        cout << "Passed in " << argc << "parameters:" << endl;
        for(int i = 0; i<argc; ++i)
            cout << argv[i] << endl;
    }
    return 0;
}

int showgui(){  // func to display java GUI to user
    // init variables
    char* const guiappn = "/wall2ban.jar";
    char* path = getcwd((char*)0,0);                // get absolute path for this executable
    string cmd("java -jar ");                       // simple trick to concatenate the command
    cmd.append(path);
    cmd.append(guiappn);

    cout << "Current working dir: " << path << endl;//debugging only
    cout << "Command to execute: " << cmd << endl;  //debugging only

    return system(cmd.c_str());    // !important: run the app from terminal
}
