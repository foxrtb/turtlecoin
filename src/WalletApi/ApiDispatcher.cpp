// Copyright (c) 2018, The TurtleCoin Developers
// 
// Please see the included LICENSE file for more information.

////////////////////////////////////
#include <WalletApi/ApiDispatcher.h>
////////////////////////////////////

#include <config/CryptoNoteConfig.h>

#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>

#include "json.hpp"

#include <WalletApi/Constants.h>

#include <WalletBackend/JsonSerialization.h>

using namespace web::http;
using namespace web::http::experimental::listener;

ApiDispatcher::ApiDispatcher(
    const uint16_t bindPort,
    const bool acceptExternalRequests,
    const std::string rpcPassword)
{
    std::string host = acceptExternalRequests ? "0.0.0.0" : "127.0.0.1";

    m_server = http_listener("http://" + host + ":" + std::to_string(bindPort));

    using namespace CryptoPP;

    /* Using SHA256 as the algorithm */
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;

    /* Salt of all zeros (this is bad...) */
    byte salt[16] = {};

    byte key[16];

    /* Hash the password with pbkdf2 */
    pbkdf2.DeriveKey(
        key, sizeof(key), 0, (byte *)rpcPassword.c_str(),
        rpcPassword.size(), salt, sizeof(salt), ApiConstants::PBKDF2_ITERATIONS
    );

    /* Store this later for rpc requests */
    m_hashedPassword = Common::podToHex(key);

    m_server.support(methods::GET, [this](http_request request) {
        this->middleware(request);
    });

    m_server.support(methods::POST, [this](http_request request){
        this->middleware(request);
    });

    m_server.support(methods::PUT, [this](http_request request) {
        this->middleware(request);
    });

    m_server.support(methods::DEL, [this](http_request request) {
        this->middleware(request);
    });
}

void ApiDispatcher::start()
{
    m_server.open().wait();
}

void ApiDispatcher::stop()
{
    m_server.close().wait();
}

void ApiDispatcher::middleware(http_request &request)
{
    try
    {
        /* TODO: Uncomment 
        if (!checkAuthenticated(request))
        {
            return;
        }
        */

        request.headers().set_content_type("application/json");

        const std::string path = request.request_uri().path();

        const std::string method = request.method();

        const std::vector<std::string> splitPath = web::uri::split_path(path);

        nlohmann::json body;

        try
        {
            body = json::parse(request.extract_string(true).get());
        }
        catch (const json::parse_error &)
        {
            /* Failed to deserialize, not neccessarily an error if the body
               isn't needed */
        }

        std::cout << "Incoming " << method << " request: " << path << std::endl;

        if (!body.empty())
        {
            std::cout << "Body:\n" << std::setw(4) << body << std::endl;
        }

        if (method == "GET")
        {
            getRequestHandler(request, splitPath);
        }
        else if (method == "POST")
        {
            postRequestHandler(request, splitPath, body);
        }
        else if (method == "PUT")
        {
            putRequestHandler(request, splitPath, body);
        }
        else if (method == "DELETE")
        {
            deleteRequestHandler(request, splitPath);
        }
    }
    catch (const nlohmann::json::exception &e)
    {
        std::cout << "Threw error parsing request: " << e.what() << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cout << "Unexpected error processing request: " << e.what() << std::endl;
    }
    catch (const boost::exception &e)
    {
        std::cout << "Unexpected error processing request: "
                  << dynamic_cast<std::exception const &>(e).what()
                  << std::endl;
    }

    /* Reply if we threw an exception or something unexpected happened */
    request._reply_if_not_already(status_codes::BadRequest);
}

void ApiDispatcher::getRequestHandler(
    const http_request &request,
    const std::vector<std::string> path)
{
    if (isWalletClosed(request))
    {
        return;
    }
}

void ApiDispatcher::postRequestHandler(
    const http_request &request,
    const std::vector<std::string> path,
    const nlohmann::json body)
{
    if (path.size() == 2 && path[0] == "wallet")
    {
        std::scoped_lock lock(m_mutex);

        if (isWalletAlreadyOpen(request))
        {
            return;
        }

        if (path[1] == "open")
        {
            openWallet(request, body);
        }
        else if (path[1] == "keyimport")
        {
            keyImportWallet(request, body);
        }
        else if (path[1] == "seedimport")
        {
            seedImportWallet(request, body);
        }
        else if (path[1] == "viewkeyimport")
        {
            importViewWallet(request, body);
        }
        else if (path[1] == "create")
        {
            createWallet(request, body);
        }
    }
}

void ApiDispatcher::putRequestHandler(
    const http_request &request,
    const std::vector<std::string> path,
    const nlohmann::json body)
{
    if (isWalletClosed(request))
    {
        return;
    }
}

void ApiDispatcher::deleteRequestHandler(
    const http_request &request,
    const std::vector<std::string> path)
{
    if (isWalletClosed(request))
    {
        return;
    }

    if (path.size() == 1 && path[0] == "wallet")
    {
        std::scoped_lock lock(m_mutex);

        /* Need to check here again, could have changed between aquiring mutex */
        if (isWalletClosed(request))
        {
            return;
        }

        closeWallet();
    }
}

bool ApiDispatcher::checkAuthenticated(const http_request &request) const
{
    const http_headers &headers = request.headers();

    const auto it = headers.find("X-API-KEY");

    if (it == headers.end())
    {
        std::cout << "Rejecting unauthorized request: X-API-KEY header is missing." << std::endl;
        request.reply(status_codes::Unauthorized);
        return false;
    }

    if (it->second == m_hashedPassword)
    {
        return true;
    }

    std::cout << "Rejecting unauthorized request: X-API-KEY is incorrect.\n"
                 "Expected: " << m_hashedPassword
              << "\nActual: " << it->second << std::endl;

    request.reply(status_codes::Unauthorized);

    return false;
}

void ApiDispatcher::openWallet(
    const http_request &request,
    const nlohmann::json body)
{
    const auto [daemonHost, daemonPort, filename, password] = getDefaultWalletParams(body);

    WalletError error;

    std::tie(error, m_walletBackend) = WalletBackend::openWallet(
        filename, password, daemonHost, daemonPort
    );

    if (error)
    {
        writeError(request, error);
    }
    else
    {
        request.reply(status_codes::OK);
    }
}

void ApiDispatcher::keyImportWallet(
    const http_request &request,
    const nlohmann::json body)
{
    const auto [daemonHost, daemonPort, filename, password] = getDefaultWalletParams(body);

    Crypto::SecretKey privateViewKey = body.at("privateViewKey").get<Crypto::SecretKey>();
    Crypto::SecretKey privateSpendKey = body.at("privateSpendKey").get<Crypto::SecretKey>();

    uint64_t scanHeight = 0;

    if (body.find("scanHeight") != body.end())
    {
        scanHeight = body.at("scanHeight").get<uint64_t>();
    }

    WalletError error;

    std::tie(error, m_walletBackend) = WalletBackend::importWalletFromKeys(
        privateSpendKey, privateViewKey, filename, password, scanHeight,
        daemonHost, daemonPort
    );

    if (error)
    {
        writeError(request, error);
    }
    else
    {
        request.reply(status_codes::OK);
    }
}

void ApiDispatcher::seedImportWallet(
    const http_request &request,
    const nlohmann::json body)
{
    const auto [daemonHost, daemonPort, filename, password] = getDefaultWalletParams(body);

    std::string mnemonicSeed = body.at("mnemonicSeed").get<std::string>();

    uint64_t scanHeight = 0;

    if (body.find("scanHeight") != body.end())
    {
        scanHeight = body.at("scanHeight").get<uint64_t>();
    }

    WalletError error;

    std::tie(error, m_walletBackend) = WalletBackend::importWalletFromSeed(
        mnemonicSeed, filename, password, scanHeight, daemonHost, daemonPort
    );

    if (error)
    {
        writeError(request, error);
    }
    else
    {
        request.reply(status_codes::OK);
    }
}

void ApiDispatcher::importViewWallet(
    const http_request &request,
    const nlohmann::json body)
{
    const auto [daemonHost, daemonPort, filename, password] = getDefaultWalletParams(body);

    std::string address = body.at("address").get<std::string>();
    Crypto::SecretKey privateViewKey = body.at("privateViewKey").get<Crypto::SecretKey>();

    uint64_t scanHeight = 0;

    if (body.find("scanHeight") != body.end())
    {
        scanHeight = body.at("scanHeight").get<uint64_t>();
    }

    WalletError error;

    std::tie(error, m_walletBackend) = WalletBackend::importViewWallet(
        privateViewKey, address, filename, password, scanHeight,
        daemonHost, daemonPort
    );

    if (error)
    {
        writeError(request, error);
    }
    else
    {
        request.reply(status_codes::OK);
    }
}

void ApiDispatcher::createWallet(
    const http_request &request,
    const nlohmann::json body)
{
    const auto [daemonHost, daemonPort, filename, password] = getDefaultWalletParams(body);

    WalletError error;

    std::tie(error, m_walletBackend) = WalletBackend::createWallet(
        filename, password, daemonHost, daemonPort
    );

    if (error)
    {
        writeError(request, error);
    }
    else
    {
        request.reply(status_codes::OK);
    }
}

std::tuple<std::string, uint16_t, std::string, std::string>
    ApiDispatcher::getDefaultWalletParams(const nlohmann::json body) const
{
    std::string daemonHost = "127.0.0.1";
    uint16_t daemonPort = CryptoNote::RPC_DEFAULT_PORT;

    std::string filename = body.at("filename").get<std::string>();
    std::string password = body.at("password").get<std::string>();

    if (body.find("daemonHost") != body.end())
    {
        daemonHost = body.at("daemonHost").get<std::string>();
    }

    if (body.find("daemonPort") != body.end())
    {
        daemonPort = body.at("daemonPort").get<uint16_t>();
    }

    return {daemonHost, daemonPort, filename, password};
}

bool ApiDispatcher::isWalletAlreadyOpen(const http_request &request) const
{
    if (m_walletBackend != nullptr)
    {
        std::cout << "Client requested to open a wallet, whilst once is already open" << std::endl;

        request.reply(status_codes::Forbidden);

        return true;
    }

    return false;
}

bool ApiDispatcher::isWalletClosed(const http_request &request) const
{
    if (m_walletBackend != nullptr)
    {
        return false;
    }

    std::cout << "Client requested to modify a wallet, whilst no wallet is open" << std::endl;

    request.reply(status_codes::Forbidden);

    return true;
}

void ApiDispatcher::writeError(
    const http_request &request,
    const WalletError error) const
{
    nlohmann::json j;

    j["errorCode"] = error.getErrorCode();
    j["errorMessage"] = error.getErrorMessage();

    request.reply(status_codes::BadRequest, j.dump());
}

void ApiDispatcher::closeWallet()
{
    m_walletBackend = nullptr;
}
