#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>

#pragma comment( lib, "cryptlib.lib" )
#include <Crypto++\cryptlib.h>
#include <Crypto++\files.h>
#include <Crypto++\hex.h>
#include <Crypto++\sha.h>
#include <Crypto++\MD5.h>
#include <Crypto++\ripemd.h>
#include <Crypto++\crc.h>
#include <Crypto++\adler32.h>

using std::cout;
using std::endl;
using std::string;
using std::vector;
using std::ifstream;

//Filesystem is a cross-platform standard library for interacting with filesystems/directorys
//It removes the need to wrap the single platform solutions (Windows.h)
//or to use external libraries (boost)
namespace fs = std::experimental::filesystem;

int printUsage(char* filename) {
	cout << "Usage: "<< filename <<" -m [METHOD] [OPTION] [DIR]" << endl
		<< "  -h,--help		display this help and exit" << endl
		<< "  -m [METHOD]		method: SHA1/224/256/384/512, MD5, RIPEMD128/160/256/320, CRC32, Adler32" << endl
		<< "			MUST be defined before -b & -g" << endl
		<< "			Defaults to SHA256" << endl
		<< "  -g [FILE]		use known good hashes from FILE" << endl
		<< "  -b [FILE]		use known bad hashes from FILE" << endl
		<< "  -r			hash directories and their contents recursively" << endl
		<< "  -o			hash only mode, useful for creating bad/good hashes files" << endl;
	return 0;
}

string hash(const char* filename, CryptoPP::HashTransformation* method)
{
	string result;
	try {
		CryptoPP::FileSource(filename, true, new
			CryptoPP::HashFilter(*method, new CryptoPP::HexEncoder(new
				CryptoPP::StringSink(result), false)));
	}
	catch (CryptoPP::FileStore::Err e) {
		return "File read error";
	}
	return result;
}

vector<string> getHashes(const string filename, const int size) {
	vector<string> vec;
	ifstream file;
	file.exceptions(ifstream::badbit);
	file.open(filename);

	string hash;
	while(getline(file, hash)){
		vec.push_back(hash);
	}
	return vec;
}

int main(int argCount, char *arg[]) {
	//If no arguments are passed, print usage then exit
	if (argCount == 1) return printUsage(arg[0]);
	//Store if we're recursively hashing files
	bool recursive = false;
	//Store if we're only printing hashes
	bool hashOnly = false;
	//store the class we're using to hash with
	CryptoPP::HashTransformation* method = new CryptoPP::SHA256;
	//store the good and bad hashes lists
	vector<string> badHashes;
	vector<string> goodHashes;
	for (auto i = 1; i < argCount - 1; i++) {
		string args = arg[i];
		if (args == "-h" || arg[i] == "--help") {
			return printUsage(arg[0]);
		}
		if (args == "-m") {
			i++;
			args = arg[i];
			if (args == "SHA1" || args == "sha1")					method = new CryptoPP::SHA1;
			else if (args == "SHA224" || args == "sha224")			method = new CryptoPP::SHA224;
			else if (args == "SHA256" || args == "sha256")			method = new CryptoPP::SHA256;
			else if (args == "SHA384" || args == "sha384")			method = new CryptoPP::SHA384;
			else if (args == "SHA512" || args == "sha512")			method = new CryptoPP::SHA512;
			else if (args == "RIPEMD128" || args == "ripemd128")	method = new CryptoPP::RIPEMD128;
			else if (args == "RIPEMD160" || args == "ripemd160")	method = new CryptoPP::RIPEMD160;
			else if (args == "RIPEMD256" || args == "ripemd256")	method = new CryptoPP::RIPEMD256;
			else if (args == "RIPEMD320" || args == "ripemd320")	method = new CryptoPP::RIPEMD320;
			else if (args == "MD5" || args == "md5")				method = new CryptoPP::MD5;
			else if (args == "CRC32" || args == "crc32")			method = new CryptoPP::CRC32;
			else if (args == "ADLER32" || args == "Adler32")		method = new CryptoPP::Adler32;
			continue;
		}
		if (args == "-b") {
			i++;
			if (!fs::exists(arg[i])) { 
				cout << "Bad hash file \""<<arg[i]<<"\" doesn't exist";
				printUsage(arg[0]);
				return 1;
			}
			try {
				badHashes = getHashes(arg[i], method->DigestSize());
			}
			catch (...) {
				cout << "Exception opening/reading bad hash file: " << arg[i] << endl;
				return 1;
			}
			continue;
		}
		if (args == "-g") {
			i++;
			if (!fs::exists(arg[i])) {
				cout << "Good hash file \"" << arg[i] << "\" doesn't exist";
				printUsage(arg[0]);
				return 1;
			}
			try {
				goodHashes = getHashes(arg[i], method->DigestSize());
			}
			catch (...) {
				cout << "Exception opening/reading good hash file: " << arg[i] << endl;
				return 1;
			}
			continue;
		}
		if (args == "-r") {
			recursive = true;
			continue;
		}
		if (args == "-o") {
			hashOnly = true;
		}
	}
	//Define a lambda to run per file so that we don't write it twice
	auto perFile = [&](auto& p) {
		string result = hash(p.path().string().c_str(), method);
		//if we are printing the hash, do so
		if (!hashOnly) {
			cout << p << endl;
		}
		//If we have hashes to check against, do so
		if (!goodHashes.empty() || !badHashes.empty()) {
			for (auto good : goodHashes) {
				if (result == good) {
					cout << "GOOD" << endl << result << endl;
					return;
				}
			}
			for (auto bad : badHashes) {
				if (result == bad) {
					cout << "BAD" << endl << result << endl;
					return;
				}
			}
			cout << "UNDECIDED" << endl;
		}
		cout << result << endl;
	};
	if (recursive) {
		//Loop through every file in the directory tree recursively
		for (auto& p : fs::recursive_directory_iterator(arg[argCount - 1]))
		{
			//Skip if is directory not file
			if (fs::is_directory(p)) continue;
			perFile(p);
		}
	}
	else {
		//Loop through every file in the current directory
		for (auto& p : fs::directory_iterator(arg[argCount - 1]))
		{
			//Skip if is directory not file
			if (fs::is_directory(p)) continue;
			perFile(p);
		}
	}
}