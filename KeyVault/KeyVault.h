#ifndef KEYVAULT_H__
#define KEYVAULT_H__
#pragma once
#include "cpprest/http_client.h"
#include "cpprest/containerstream.h"
#include "cpprest/filestream.h"

#ifdef _WIN32
#include <time.h>
#include <objbase.h>
#else
#include <sys/time.h>
#include <uuid/uuid.h>
#endif


class KeyVault
{
public:
	 utility::string_t tokenType;
	utility::string_t accessToken;
	utility::string_t keyVaultUrl;
	utility::string_t loginUrl;
	utility::string_t resourceUrl;
	utility::string_t keyVaultName;
	utility::string_t keyVaultRegion;
	utility::string_t subscriptionID;

private:
	int status_code;
	web::json::value secret;
	web::json::value key;
	web::json::value signature;
	web::json::value verification;

	//Methods

private:
	utility::string_t get_https_url(utility::string_t headerValue);
	void GetLoginUrl();
	pplx::task<void> get_secret(utility::string_t secretName);
	pplx::task<void> get_key(utility::string_t secretName);
	pplx::task<void> sign(utility::string_t secretName);
	pplx::task<void> verify(utility::string_t secretName, utility::string_t signValue);

	utility::string_t NewGuid();
	utility::string_t read_response_body(web::http::http_response response);

public:
	pplx::task<void> Authenticate(utility::string_t& clientId, utility::string_t& clientSecret,
		utility::string_t& username, utility::string_t& password, utility::string_t& keyVaultName, utility::string_t& subscriptionID);
	bool GetSecretValue(utility::string_t secretName, web::json::value& secret);
	bool GetKeyValue(utility::string_t secretName, web::json::value& key);
	bool GetSignature(utility::string_t secretName, web::json::value& signature);
	bool GetVerification(utility::string_t secretName, utility::string_t signValue, web::json::value& verification);
	pplx::task<void> listSubscriptions();
	pplx::task<void> createKey();
};

#endif

