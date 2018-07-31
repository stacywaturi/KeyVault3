#include <conio.h>
#include "KeyVault.h"


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
	
/*
	std::wcout << _XPLATSTR("LOGIN") << std::endl;
	std::wcout << _XPLATSTR("Enter username	:");
	std::wcin >> username;
	std::wcout << _XPLATSTR("Enter password	:");
	std::wcin >> password;*/
	

	//std::wcout << _XPLATSTR("LOGIN") << std::endl;
	KeyVault kvc;
	

	/////////////////////////////////////////////////////////////////////////
	// load values from config file
	//GetConfig(_XPLATSTR("vault.conf"));


	
	
	kvc.Authenticate(clientId, clientSecret, username, password, keyVaultName, subscriptionID).wait();
	//kvc.listSubscriptions().wait();

	std::wcout << _XPLATSTR("Enter Key vault name") << std::endl;
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
			std::wcout << _XPLATSTR("Creating key ") << std::endl;
			kvc.createKey().wait();
		}
		/*std::wcout << _XPLATSTR("Querying KeyVault for Keys ") << secretName.c_str() << _XPLATSTR("...") << std::endl;
		web::json::value jsonKey;
		bool rc = kvc.GetKeyValue(secretName, jsonKey);

		if (rc == false) {
		std::wcout << _XPLATSTR("Key doesn't exist") << std::endl;
		return 1;
		}*/



		/*if (argc >= 3) {
			std::wcout << _XPLATSTR("Key ID   : ") << (jsonKey[_XPLATSTR("key")])[_XPLATSTR("kid")] << std::endl;
			std::wcout << _XPLATSTR("Key Value   : ") << (jsonKey[_XPLATSTR("key")])[_XPLATSTR("n")] << (jsonKey[_XPLATSTR("key")])[_XPLATSTR("e")] << std::endl << std::endl;
			std::wcout << _XPLATSTR("Signing with key ....") << std::endl;
			utility::string_t string1 = _XPLATSTR("message to be signed");


			utility::string_t kid = (jsonKey[_XPLATSTR("key")])[_XPLATSTR("kid")].as_string();
			web::json::value jsonSignature;
			bool rc = kvc.GetSignature(kid, jsonSignature);

			if (rc == false) {
			std::wcout << _XPLATSTR("Can't sign") << std::endl;
			return 1;
			}
			utility::string_t signValue = (jsonSignature[_XPLATSTR("value")]).as_string();

			std::wcout << _XPLATSTR("Signature  : ") << signValue << std::endl;

			std::wcout << _XPLATSTR("Verifying ....") << std::endl;

			web::json::value jsonVerification;
			bool rc2 = kvc.GetVerification(kid, signValue, jsonVerification);

			if (rc2 == true)
			std::wcout << _XPLATSTR("Verification	:") << jsonVerification[_XPLATSTR("value")] << std::endl;

			else if (rc2 == false) {
			std::wcout << _XPLATSTR("Verification failed") << std::endl;
			return 1;
			}

		}*/

		/*else
		std::wcout << _XPLATSTR("Keys  : ") << jsonKey << std::endl;*/


	}

	//else if (type == _XPLATSTR("secrets"))
	//{
	//	std::wcout << _XPLATSTR("Querying KeyVault for Secrets ") << secretName.c_str() << _XPLATSTR("...") << std::endl;
	//	web::json::value jsonSecret;
	//	bool rc = kvc.GetSecretValue(secretName, jsonSecret);

	//	if (rc == false) {
	//		std::wcout << _XPLATSTR("Secret doesn't exist") << std::endl;
	//		return 1;
	//	}
	//	if (argc >= 3) {
	//		//std::wcout << jsonSecret[_XPLATSTR("kid")] << std::endl;
	//		std::wcout << _XPLATSTR("Secret ID   : ") << jsonSecret[_XPLATSTR("id")] << std::endl;
	//		std::wcout << _XPLATSTR("Secret Value: ") << jsonSecret[_XPLATSTR("value")] << std::endl;
	//	}
	//	else
	//		std::wcout << _XPLATSTR("Secrets  : ") << jsonSecret << std::endl;



	//}
	//else {

	//	std::wcout << _XPLATSTR("Resource doesn't exist") << std::endl;

	//}


	return 0;
}


