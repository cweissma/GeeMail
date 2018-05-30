#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <climits>
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h> 
#include <gcrypt.h>
#include "sha256.h"
using namespace std;

/* notes:
1. The geemail.db was initialized with:
    CREATE TABLE users(username text primary key,password text);
    CREATE TABLE messages(rowid INTEGER PRIMARY KEY ASC,msgfrom text,msgto text,msgtext text, passphrase text);
2. SQL commands are from https://www.tutorialspoint.com/sqlite/sqlite_c_cpp.htm
3. SHA256 functions are from http://www.zedwood.com/article/cpp-sha256-function
4. Encryption functions are from http://www.cplusplus.com/forum/windows/128374/
5. Hex conversion functions from // hex conversion from: https://stackoverflow.com/questions/3381614
*/

//************ Declarations of variables (global) **********

char MenuChoice[1]="";
string userinput;
string useroutput;
string passinput;
string passoutput;
string phraseinput;
string phraseoutput;
string readmsgtext;
string readmsgpass;
string getmsgtext;
string getmsgpass;
string msginhex;
string msgencrypted;
string msgpasshashed;
string msgdecrypted;
string msgunhexed;
string loggedinas = "";
int readmsgnum = 0;
char sendmsgto[10];
char sendmsgfrom[10];
char sendmsgtext[200];
char sendmsgpass[20];
bool loggedin = false;


//**************SQL Handling *********

sqlite3 *db;
char *zErrMsg = 0;
int rc;
string sql;
const char* data = ""; //was originally "Callback function called";

//**************SQL Callback Functions ********* // Modified the standard callback to be unique for each menu choice

static int callback_c(void *NotUsed, int argc, char **argv, char **azColName) {
   return 0;
}

static int callback_l(void *data, int argc, char **argv, char **azColName){
   int i;
   for(i = 0; i<argc; i++){
      useroutput = argv[0];
      passoutput = argv[1];
   }
   return 0;
}

static int callback_s(void *NotUsed, int argc, char **argv, char **azColName) {
   return 0;
}

static int callback_r_list(void *data, int argc, char **argv, char **azColName){
    cout << "Message #: " << argv[0] << " From: " << argv[1] << endl;
    return 0;
}

static int callback_r_select(void *data, int argc, char **argv, char **azColName){
    getmsgtext = argv[3];
    getmsgpass = argv[4];
   return 0;
}

//************ Open database function *************

int opendatabase(){
    
    rc = sqlite3_open("./geemail.db", &db);
    if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return(0);
    }
    else {
      fprintf(stderr, "Opened database successfully\n");
   }
}

//************ Hex and Encryption Functions *************

std::string string_to_hex(const std::string& input)
{
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();

    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}
   
std::string hex_to_string(const std::string& input)
{
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();
    if (len & 1) throw std::invalid_argument("odd length");

    std::string output;
    output.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2)
    {
        char a = input[i];
        const char* p = std::lower_bound(lut, lut + 16, a);
        if (*p != a) throw std::invalid_argument("not a hex digit");

        char b = input[i + 1];
        const char* q = std::lower_bound(lut, lut + 16, b);
        if (*q != b) throw std::invalid_argument("not a hex digit");

        output.push_back(((p - lut) << 4) | (q - lut));
    }
    return output;
}

string encrypt(string msg, string key)
{
    string tmp(key);
    while (key.size() < msg.size())
        key += tmp;
    
    for (std::string::size_type i = 0; i < msg.size(); ++i)
        msg[i] ^= key[i];
    return msg;
}

string decrypt(string msg, string key)
{
    return encrypt(msg, key);
}


//************ User and Message Functions *************

int loginuser(){ //called to log in a user
    
    cout << endl;
    cout << "Login with username: ";
    cin >> userinput;
    cout << "Login with password: ";
    cin >> passinput;
    cout << "Trying User: " << userinput << endl;
 
    sql = "SELECT * from users where (username=\"" + userinput + "\");";

    rc = sqlite3_exec(db, sql.c_str(), callback_l, (void*)data, &zErrMsg);
   
   if (userinput == useroutput && sha256(passinput) == passoutput) {
        loggedin = true;
        loggedinas = useroutput;
        cout << "Successfully logged in as user: " << loggedinas << endl;
   }
        
    else {
        cout << endl << "**invalid user or password***" << endl << endl;
    }
    
    std::cin.ignore(); //clear the input buffer
    useroutput="";
    userinput="";
}

int createuser(){ //allows the creation of a new user
    
    cout << endl;
    cout << "Create a username: ";
    cin >> userinput;
    cout << "Create a password: ";
    cin >> passinput;
    cout << endl << "Results:" << endl;
 
    sql = "INSERT INTO USERS (username,password) VALUES (\"" + userinput + "\",\"" + sha256(passinput) + "\");";
    rc = sqlite3_exec(db, sql.c_str(), callback_c, 0, &zErrMsg);
 
    if( rc != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        cout << "FAILED attempting to Create User: " << userinput << endl;}
    else {
      cout << "Successfully Created User: " << userinput << endl;
    }
    std::cin.ignore(); //clear the input buffer
}

int sendmessage(){ //send a message to another user

    cout << endl;
    cout << "Send the message to: ";
    cin.getline(sendmsgto,20);
    cout << "Enter message text up to 200 characters: " << endl;
    cin.getline(sendmsgtext,200);
    cout << "Enter the passphrase: ";
    cin.getline(sendmsgpass,20);
    
    msginhex = string_to_hex(sendmsgtext);
    msgencrypted = encrypt(msginhex,sendmsgpass); //encrypt message
    msgpasshashed = sha256(sendmsgpass); //hash password

    sql = "INSERT INTO MESSAGES (msgfrom,msgto,msgtext,passphrase) VALUES (\"" + loggedinas + "\",\"" + sendmsgto + "\",\"" + msgencrypted + "\",\"" + msgpasshashed + "\");";
 
   rc = sqlite3_exec(db, sql.c_str(), callback_s, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg); } 
    else {
      cout << "Message created successfully - Press Enter to Continue..." << endl;
   }


    std::cin.ignore(); //clear the input buffer
}
    
int readmessage(){ // display messages to logged in user and choose a message by row#, and enter passphrase to decrypt
    
    cout << endl; //show messages
    cout <<"Here are the messages sent to --> " << loggedinas << " <-- " << endl;
    cout << "---------------------------------" << endl; 
    sql = "SELECT * from messages where (msgto=\"" + loggedinas + "\");";
    rc = sqlite3_exec(db, sql.c_str(), callback_r_list, (void*)data, &zErrMsg);
    cout << "---------------------------------" << endl; 

    //select a message to display
    cout << endl << "Enter Message # to display: ";
    cin >> readmsgnum;
    cout << "Enter the passphrase: ";
    cin >> readmsgpass;
    cout << "Trying to read message: " << readmsgnum << endl << endl;

    sql = "SELECT * from messages where (rowid=" + std::to_string(readmsgnum) +");";

    rc = sqlite3_exec(db, sql.c_str(), callback_r_select, (void*)data, &zErrMsg);

    if (sha256(readmsgpass) == getmsgpass) {
        cout << "Successfully entered passphrase! Here is your message:" << endl << endl;
        msgdecrypted = decrypt(getmsgtext,readmsgpass);
        msgunhexed = hex_to_string(msgdecrypted);
        cout << "---> " << msgunhexed << endl;
   }
    else {
        cout << endl << "**invalid passphrase! Sorry :-( ***" << endl;
    }


 std::cin.ignore(); //clear the input buffer
}

//************ Main function ******************

int main(int argc, char* argv[]) {

    opendatabase(); //open database
    
    bool menuactive = true; //display the menu routine
    while (menuactive == true) {
        cout << endl;
        cout << "---------------------------------" << endl;    
        cout << "This is the GeeMail Server" << endl;
        cout << "---------------------------------" << endl;        
        cout << "Please make a choice and press Enter:"<< endl;
        cout << "c. Create a user"<< endl;
        cout << "s. Send a message"<< endl;
        cout << "r. Read a message"<< endl;
        cout << "x. Exit"<< endl;
        cin.getline(MenuChoice,2);
        if (*MenuChoice == 'x') {
            cout << "Exiting... " << endl << endl;
            menuactive = false;
        }
        else if (*MenuChoice == 'c') {    
            createuser();}
        else if (*MenuChoice == 's') {    
            if (loggedin) { sendmessage(); }
            else { 
                loginuser();
                if (loggedin) { sendmessage(); }
                
            }
        }
        else if (*MenuChoice == 'r') {    
            if (loggedin) { readmessage(); }
            else { 
                loginuser();
                if (loggedin) { readmessage(); }
            }
        }
        else {
            cout << "Invalid Entry, please try again: " << endl;}
        }

    sqlite3_close(db); // close database
    // and... we're done.
} 
