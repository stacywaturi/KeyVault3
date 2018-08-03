#include "KeyVault.h"


//////////////////////////////////////////////////////////////////////////////
// helper to generate a new guid (currently Linux specific, for Windows we 
// should use ::CoCreateGuid() 
utility::string_t KeyVault::NewGuid()
{
	utility::string_t guid;
#ifdef _WIN32
	GUID wguid;
	::CoCreateGuid(&wguid);
	wchar_t		uuid_str[38 + 1];
	::StringFromGUID2((const GUID&)wguid, uuid_str, sizeof(uuid_str));
#else
	uuid_t uuid;
	uuid_generate_time_safe(uuid);
	char uuid_str[37];
	uuid_unparse_lower(uuid, uuid_str);
#endif
	guid = uuid_str;
	return guid;
}
//////////////////////////////////////////////////////////////////////////////
//
utility::string_t KeyVault::read_response_body(web::http::http_response response)
{
	auto bodyStream = response.body();
	concurrency::streams::stringstreambuf sb;
	auto& target = sb.collection();
	bodyStream.read_to_end(sb).get();
#ifdef _WIN32 // Windows uses UNICODE but result is in UTF8, so we need to convert it
	utility::string_t wtarget;
	wtarget.assign(target.begin(), target.end());
	return wtarget;
#else
	return target;
#endif
}
//////////////////////////////////////////////////////////////////////////////
// Call Azure KeyVault REST API to retrieve a secret
bool KeyVault::GetSecretValue(utility::string_t secretName, web::json::value &secret)
{
	get_secret(secretName).wait();
	secret = this->secret;
	return this->status_code == 200;
}
pplx::task<void> KeyVault::get_secret(utility::string_t secretName)
{
	auto impl = this;
	// create the url path to query the keyvault secret
	utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/secrets/") + secretName + _XPLATSTR("?api-version=2015-06-01");

	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);
	web::http::http_request request(web::http::methods::GET);
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());
	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	//std::wcout << request.to_string() << std::endl;
	// Azure HTTP REST API call
	return client.request(request).then([impl](web::http::http_response response)
	{
		//std::wcout << response.to_string() << std::endl;
		std::error_code err;
		impl->status_code = response.status_code();
		if (impl->status_code == 200) {

			utility::string_t target = impl->read_response_body(response);
			//std::wcout << target << std::endl;


			impl->secret = web::json::value::parse(target.c_str(), err);
			//std::wcout << impl->secret << std::endl;

		}
		else {
			impl->secret = web::json::value::parse(_XPLATSTR("{\"id\":\"\",\"value\":\"\"}"), err);
		}
	});
}

//////////////////////////////////////////////////////////////////////////////
// Call Azure KeyVault REST API to retrieve a key
bool KeyVault::GetKeyValue(utility::string_t secretName, web::json::value &secret)
{
	get_key(secretName).wait();
	secret = this->key;
	return this->status_code == 200;
}
pplx::task<void> KeyVault::get_key(utility::string_t secretName)
{
	auto impl = this;
	// create the url path to query the keyvault secret
	utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/keys/") + secretName + _XPLATSTR("?api-version=2015-06-01");

	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);
	web::http::http_request request(web::http::methods::GET);
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());
	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	//std::wcout << request.to_string() << std::endl;
	// Azure HTTP REST API call
	return client.request(request).then([impl](web::http::http_response response)
	{
		//std::wcout << response.to_string() << std::endl;
		std::error_code err;
		impl->status_code = response.status_code();
		if (impl->status_code == 200) {

			utility::string_t target = impl->read_response_body(response);
			//std::wcout << target << std::endl;


			impl->key = web::json::value::parse(target.c_str(), err);
			//std::wcout << impl->secret << std::endl;

		}
		else {
			impl->secret = web::json::value::parse(_XPLATSTR("{\"id\":\"\",\"value\":\"\"}"), err);
		}
	});
}
bool KeyVault::GetSignature(utility::string_t kid, utility::string_t algorithm, utility::string_t string1, web::json::value& signature)
{
	sign(kid,algorithm,string1).wait();
	signature = this->signature;
	return this->status_code == 200;
}

pplx::task<void> KeyVault::sign(utility::string_t kid, utility::string_t algorithm, utility::string_t string1)
{
	auto impl = this;
	// create the url path to query the keyvault key
	utility::string_t url = kid + _XPLATSTR("/sign?api-version=2015-06-01");

	std::wcout << url << std::endl;
	web::http::client::http_client client(url);
	std::wcout << string1.length() << std::endl;
	web::json::value postData;
	postData[U("alg")] = web::json::value::string(algorithm);
	postData[U("value")] = web::json::value::string(string1);



	web::http::http_request request(web::http::methods::POST);
	request.headers().add(_XPLATSTR("Content-Type"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());
	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	request.set_body(postData);

	std::wcout << request.to_string() << std::endl;
	// response from IDP is a JWT Token that contains the token type and access token we need for
	// Azure HTTP REST API calls
	return client.request(request).then([impl](web::http::http_response response)
	{

		std::wcout << response.to_string() << std::endl;

		impl->status_code = response.status_code();
		if (impl->status_code == 200) {
			utility::string_t target = impl->read_response_body(response);

			impl->signature = web::json::value::parse(target.c_str());

			std::error_code err;
			web::json::value jwtToken = web::json::value::parse(target.c_str(), err);
			if (err.value() == 0) {
				utility::string_t target = impl->read_response_body(response);
				//std::wcout << target << std::endl;
				//std::wcout << _XPLATSTR("SUCCESS") << std::endl;
			}
		}
	});
}
bool KeyVault::GetVerification(utility::string_t key, utility::string_t algorithm, utility::string_t string1, utility::string_t signValue, web::json::value& verification)
{
	verify(key, algorithm, string1, signValue).wait();
	verification = this->verification;
	return this->status_code == 200;
}
pplx::task<void> KeyVault::verify(utility::string_t kid, utility::string_t algorithm, utility::string_t string1, utility::string_t signValue)
{
	auto impl = this;
	// create the url path to query the keyvault key
	utility::string_t url = kid + _XPLATSTR("/verify?api-version=2015-06-01");

	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);

	web::json::value postData;

	postData[L"alg"] = web::json::value::string(algorithm);
	postData[L"digest"] = web::json::value::string(string1);
	postData[L"value"] = web::json::value::string(signValue);



	web::http::http_request request(web::http::methods::POST);
	request.headers().add(_XPLATSTR("Content-Type"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());
	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	request.set_body(postData);

	//std::wcout << request.to_string() << std::endl;
	// response from IDP is a JWT Token that contains the token type and access token we need for
	// Azure HTTP REST API calls
	return client.request(request).then([impl](web::http::http_response response)
	{

		//std::wcout << response.to_string() << std::endl;

		impl->status_code = response.status_code();
		if (impl->status_code == 200) {
			utility::string_t target = impl->read_response_body(response);
			//std::wcout << target << std::endl;
			impl->verification = web::json::value::parse(target.c_str());

			std::error_code err;
			web::json::value jwtToken = web::json::value::parse(target.c_str(), err);
			if (err.value() == 0) {
				utility::string_t target = impl->read_response_body(response);
				//std::wcout << target << std::endl;
				//std::wcout << _XPLATSTR("Failed") << std::endl;
			}
		}
	});
}


//////////////////////////////////////////////////////////////////////////////
// helper to parse out https url in double quotes
utility::string_t KeyVault::get_https_url(utility::string_t headerValue)
{
	size_t pos1 = headerValue.find(_XPLATSTR("https://"));
	if (pos1 >= 0) {
		size_t pos2 = headerValue.find(_XPLATSTR("\""), pos1 + 1);
		if (pos2 > pos1) {
			utility::string_t url = headerValue.substr(pos1, pos2 - pos1);
			headerValue = url;
		}
		else {
			utility::string_t url = headerValue.substr(pos1);
			headerValue = url;
		}
	}
	return headerValue;
}
//////////////////////////////////////////////////////////////////////////////
// Make a HTTP POST to oauth2 IDP source to get JWT Token containing
// access token & token type
pplx::task<void> KeyVault::Authenticate(utility::string_t& clientId, utility::string_t& clientSecret,
	utility::string_t& username, utility::string_t& password, utility::string_t& keyVaultName, utility::string_t& subscriptionID)
{
	auto impl = this;
	impl->keyVaultName = keyVaultName;
	impl->subscriptionID = subscriptionID;


	// make a un-auth'd request to KeyVault to get a response that contains url to IDP
	impl->GetLoginUrl();

	// create the oauth2 authentication request and pass the clientId/Secret as app identifiers
	utility::string_t url = impl->loginUrl + _XPLATSTR("/oauth2/token");
	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);
	utility::string_t postData = _XPLATSTR("resource=") + web::uri::encode_uri(impl->resourceUrl) + _XPLATSTR("&client_id=") + clientId + _XPLATSTR("&client_secret=") + clientSecret
		+ _XPLATSTR("&username=") + username + _XPLATSTR("&password=") + password + _XPLATSTR("&grant_type=password");
	//std::wcout << postData << std::endl;


	web::http::http_request request(web::http::methods::POST);
	request.headers().add(_XPLATSTR("Content-Type"), _XPLATSTR("application/x-www-form-urlencoded"));
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("return-client-request-id"), _XPLATSTR("true"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());
	request.set_body(postData);

	////std::wcout << request.to_string() << std::endl;
	// response from IDP is a JWT Token that contains the token type and access token we need for
	// Azure HTTP REST API calls
	return client.request(request).then([impl](web::http::http_response response)
	{
		//std::wcout << response.to_string() << std::endl;

		impl->status_code = response.status_code();
		if (impl->status_code == 200) {
			std::wcout << _XPLATSTR("Login Successful") << std::endl;
			utility::string_t target = impl->read_response_body(response);
			std::error_code err;
			web::json::value jwtToken = web::json::value::parse(target.c_str(), err);
			if (err.value() == 0) {
				impl->tokenType = jwtToken[_XPLATSTR("token_type")].as_string();
				impl->accessToken = jwtToken[_XPLATSTR("access_token")].as_string();
			}
		}

		else
		{
			std::wcout << _XPLATSTR("Login Failed.. please check username/password") << std::endl;
		}
	});
}
//////////////////////////////////////////////////////////////////////////////
// Make a HTTP Get to Azure KeyVault unauthorized which gets us a response 
// where the header contains the url of IDP to be used
void KeyVault::GetLoginUrl()
{
	auto impl = this;
	utility::string_t part;
	impl->loginUrl = impl->get_https_url(_XPLATSTR("https://login.windows.net/723fe33c-2f51-455c-a1b3-465ffd4abe51"));
	impl->resourceUrl = impl->get_https_url(_XPLATSTR("https://vault.azure.net"));

}
//////////////////////////////////////////////////////////////////////////////
// List Subscriptions

pplx::task<void>  KeyVault::listSubscriptions() {
	auto impl = this;

	utility::string_t url = _XPLATSTR("https://management.azure.com/subscriptions/") + impl->subscriptionID + _XPLATSTR("?api-version=2018-07-01");
	//utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/secrets/secretname?api-version=2015-06-01");
	web::http::client::http_client client(url);
	std::wcout << url << std::endl;
	web::http::http_request request(web::http::methods::GET);
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());
	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	std::wcout << request.to_string() << std::endl;
	// Azure HTTP REST API call
	return client.request(request).then([impl](web::http::http_response response)
	{
		std::wcout << response.to_string() << std::endl;
		std::error_code err;
		impl->status_code = response.status_code();
		if (impl->status_code == 200) {

			utility::string_t target = impl->read_response_body(response);
			std::wcout << target << std::endl;


			impl->secret = web::json::value::parse(target.c_str(), err);
			std::wcout << impl->secret << std::endl;

		}
		else {
			impl->secret = web::json::value::parse(_XPLATSTR("{\"id\":\"\",\"value\":\"\"}"), err);
		}
	});
}
pplx::task<void>  KeyVault::createKey(utility::string_t& keyname, utility::string_t& keytype, utility::string_t& keysize) {
	auto impl = this;
	//utility::string_t keyname = _XPLATSTR("key-name");

	utility::string_t url = _XPLATSTR("https://tf-test-vault.vault.azure.net/keys/") + keyname + _XPLATSTR("/create?api-version=2016-10-01");
	//utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/secrets/secretname?api-version=2015-06-01");
	web::http::client::http_client client(url);
	//std::wcout << url << std::endl;
	web::http::http_request request(web::http::methods::POST);
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());

	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	web::json::value postData;

	postData[L"kty"] = web::json::value::string(keytype);
	postData[L"key_size"] = web::json::value::string(keysize);
	

	request.set_body(postData);
	//std::wcout << request.to_string() << std::endl;
	// Azure HTTP REST API call
	return client.request(request).then([impl](web::http::http_response response)
	{
		//std::wcout << response.to_string() << std::endl;
		std::error_code err;
		impl->status_code = response.status_code();
		if (impl->status_code == 200) {

			utility::string_t target = impl->read_response_body(response);
			std::wcout << target << std::endl;


		}
		else {
			impl->secret = web::json::value::parse(_XPLATSTR("{\"id\":\"\",\"value\":\"\"}"), err);
		}
	});
}

