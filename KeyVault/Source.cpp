#include <conio.h>
#include "KeyVault.h"
#include "Hash.h"


#ifdef _WIN32
#include <time.h>
#include <objbase.h>
#else
#include <sys/time.h>
#include <uuid/uuid.h>
#endif

 //globals
//Native
//utility::string_t clientId = _XPLATSTR("2cc6882a-f4de-4167-97f5-4b1c3ad9b8a5");

//WEB APP
utility::string_t clientId = _XPLATSTR("313b6b3a-4dd5-48e0-97a4-b7c729a46e82");

utility::string_t clientSecret = _XPLATSTR("lqstpq8B54LLK8HYzs9ANpy0pYdZjEa/ZyM4LnpvN/Y=");

utility::string_t subscriptionID = _XPLATSTR("b0609897-c980-4e7f-91a7-3974d6e37db6");
utility::string_t username = _XPLATSTR("stacy@isolvtech.com");
utility::string_t password = _XPLATSTR("#Itech100solv");
utility::string_t keyVaultName = _XPLATSTR("tf-test-vault");
utility::string_t blobContainer = _XPLATSTR("");


bool verbose = false;


//////////////////////////////////////////////////////////////////////////////
//
#ifdef _WIN32
int wmain(int argc, wchar_t* argv[])
#else
int main(int argc, char* argv[])
#endif
{
	

	//std::wcout << _XPLATSTR("LOGIN") << std::endl;
	//std::wcout << _XPLATSTR("Enter username	:");
	//std::wcin >> username;
	//std::wcout << _XPLATSTR("Enter password	:");
	//std::wcin >> password;
	//

	//std::wcout << _XPLATSTR("LOGIN") << std::endl;
	KeyVault kvc;
	

	/////////////////////////////////////////////////////////////////////////
	// load values from config file
	//GetConfig(_XPLATSTR("vault.conf"));



	
	kvc.Authenticate(clientId, clientSecret, username, password, keyVaultName, subscriptionID).wait();
	//kvc.listSubscriptions().wait();

	std::wcout << _XPLATSTR("Enter Key vault name") << std::endl;
	std::wcout << _XPLATSTR("tf-test-vault") << std::endl;
	//std::wcin >> keyVaultName;
	///////////////////////////////////////////////////////////////////////////
	//// Authenticate with Azure AD
	std::wcout << _XPLATSTR("Authenticating for KeyVault:") << keyVaultName.c_str() << _XPLATSTR("...") << std::endl;
	//std::wcout << _XPLATSTR("clientId : ") << clientId.c_str() << _XPLATSTR("..") << std::endl;

	std::wcout << _XPLATSTR("Input Action eg. create key, list keys etc") << std::endl;
	
	
	utility::string_t type = _XPLATSTR("");
	utility::string_t action = _XPLATSTR("");
	std::wcin >> type >> action;



	/////////////////////////////////////////////////////////////////////////////
	////// Get Azure KeyVault secret
	if (type == _XPLATSTR("key"))
	{
		if (action == _XPLATSTR("create")) {
			std::wcout << _XPLATSTR("Enter key name,type and size ") << std::endl;
			std::wcout << _XPLATSTR("keyname1 RSA 2048") << std::endl;
			utility::string_t keyname = _XPLATSTR("keyname1");
			utility::string_t keytype = _XPLATSTR("RSA");
			utility::string_t keysize = _XPLATSTR("2048");
			std::wcout << _XPLATSTR("Creating key ") << std::endl;
			kvc.createKey(keyname, keytype, keysize).wait();

		}
		else if (action == _XPLATSTR("all")) {
			std::wcout << _XPLATSTR(" Querying KeyVault for all Keys  ") << std::endl;
			web::json::value jsonKey;
			action = _XPLATSTR("");
			bool rc = kvc.GetKeyValue(action, jsonKey);

			if (rc == false) {
				std::wcout << _XPLATSTR("Key doesn't exist") << std::endl;
				return 1;
			}
			std::wcout << _XPLATSTR("Keys  : ") << jsonKey << std::endl;
		}

		else if (action == _XPLATSTR("sign")) {
			std::wcout << _XPLATSTR("Enter key name, algorithm and string") << std::endl;
			std::wcout << _XPLATSTR("tumisho-key RS512 string1") << std::endl;
			utility::string_t keyname = _XPLATSTR("tumisho-key");
			
			std::string string1 = "string1";
			utility::string_t algorithm = _XPLATSTR("RS512");
			std::string hashed = "";

			Hash hashObj;

			if (algorithm == _XPLATSTR("RS256") || algorithm == _XPLATSTR("ES256")) {
				hashed = hashObj.SHA256hash(string1).c_str();
				std::wcout << hashObj.SHA256hash(string1).c_str() << std::endl;
			}
			else if (algorithm == _XPLATSTR("RS384") || algorithm == _XPLATSTR("ES384")) {
				hashed = hashObj.SHA384hash(string1).c_str();
				std::wcout << hashObj.SHA384hash(string1).c_str() << std::endl;
			}
			else if (algorithm == _XPLATSTR("RS512") || algorithm == _XPLATSTR("ES512")) {
				hashed = hashObj.SHA512hash(string1).c_str();
				std::wcout << _XPLATSTR("Digest	:") <<  hashObj.SHA512hash(string1).c_str() << std::endl;
			}
			else
				std::wcout << _XPLATSTR("NOT A VALID ALGORITHM") << std::endl;

		//	std::wcout << _XPLATSTR("Querying KeyVault for Keys ") << keyname.c_str() << _XPLATSTR("...") << std::endl; 
			web::json::value jsonKey;
			bool rc = kvc.GetKeyValue(keyname, jsonKey);

			if (rc == false) {
				std::wcout << _XPLATSTR("Key doesn't exist") << std::endl;
				return 1;
			}
			utility::string_t kid = (jsonKey[_XPLATSTR("key")])[_XPLATSTR("kid")].as_string();


			web::json::value jsonSignature;
			utility::string_t hash = utility::conversions::to_string_t(hashed);
		//	std::wcout << hash.length() << std::endl;

			bool rc2 = kvc.GetSignature(kid, algorithm, hash, jsonSignature);

			if (rc2 == false) {
				std::wcout << _XPLATSTR("Cant sign") << std::endl;
				return 1;
			}

			utility::string_t signValue = (jsonSignature[_XPLATSTR("value")]).as_string();
			std::wcout << _XPLATSTR("Signature  : ") << signValue << std::endl;
			
			std::wcout << _XPLATSTR("Decoding digest") << std::endl;

			std::string unhashed = "";
			unhashed = hashObj.decodeURL(hashed);
			std::wcout << _XPLATSTR("Decoded digest:	")<<unhashed.c_str() << std::endl;

			/*web::json::value jsonVerification;

			bool rc3 = kvc.GetVerification(kid, algorithm, hash, signValue, jsonVerification);
			if (rc3 == false) {
				std::wcout << _XPLATSTR("Cant verify") << std::endl;
				return 1;
			}*/

		//	std::wcout << _XPLATSTR("Verification  : ") << jsonVerification << std::endl;




		}


		else {
			std::wcout << _XPLATSTR("Querying KeyVault for Keys ") << action.c_str() << _XPLATSTR("...") << std::endl;
			web::json::value jsonKey;
			bool rc = kvc.GetKeyValue(action, jsonKey);

			if (rc == false) {
				std::wcout << _XPLATSTR("Key doesn't exist") << std::endl;
				return 1;
			}

			std::wcout << _XPLATSTR("Key   : ") << (jsonKey[_XPLATSTR("key")]) << std::endl;


		}

	}

	else if (type == _XPLATSTR("secret")) {
		
		if (action == _XPLATSTR("all")) {
			std::wcout << _XPLATSTR(" Querying KeyVault for all Secrets  ") << std::endl;
			web::json::value jsonSecret;
			action = _XPLATSTR("");
			bool rc = kvc.GetSecretValue(action, jsonSecret);
			

			if (rc == false) {
				std::wcout << _XPLATSTR("Secret doesn't exist") << std::endl;
				return 1;
			}

			std::wcout << _XPLATSTR("Secrets  : ") << jsonSecret << std::endl;
		}

		else {
			std::wcout << _XPLATSTR("Querying KeyVault for Secret ") << action.c_str() << _XPLATSTR("...") << std::endl;
			web::json::value jsonSecret;
			bool rc = kvc.GetSecretValue(action, jsonSecret);

			if (rc == false) {
				std::wcout << _XPLATSTR("Secret doesn't exist") << std::endl;
				return 1;
			}

			std::wcout  << (jsonSecret[_XPLATSTR("kid")]) << std::endl;
			std::wcout << _XPLATSTR("Secret ID   : ") << jsonSecret[_XPLATSTR("id")] << std::endl;
			std::wcout << _XPLATSTR("Secret Value: ") << jsonSecret[_XPLATSTR("value")] << std::endl;


		}
	}


	return 0;
}









