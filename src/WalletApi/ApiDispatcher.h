// Copyright (c) 2018, The TurtleCoin Developers
// 
// Please see the included LICENSE file for more information.

#pragma once

#include <WalletBackend/WalletBackend.h>

#include "cpprest/http_listener.h"

class ApiDispatcher
{
    public:
        //////////////////
        /* Constructors */
        //////////////////

        ApiDispatcher(
            const uint16_t bindPort,
            const bool acceptExternalRequests,
            const std::string rpcPassword);

        /////////////////////////////
        /* Public member functions */
        /////////////////////////////

        /* Starts the server */
        void start();

        /* Stops the server */
        void stop();
        
    private:

        //////////////////////////////
        /* Private member functions */
        //////////////////////////////

        /* Checks authentication, catches exceptions, forwards to correct handler */
        void middleware(web::http::http_request &request);

        /* Handles an incoming get request */
        void getRequestHandler(
            const web::http::http_request &request,
            const std::vector<std::string> path);

        /* Handles an incoming post request */
        void postRequestHandler(
            const web::http::http_request &request,
            const std::vector<std::string> path,
            const nlohmann::json body);

        /* Handles an incoming put request */
        void putRequestHandler(
            const web::http::http_request &request,
            const std::vector<std::string> path,
            const nlohmann::json body);

        /* Handles an incoming delete request */
        void deleteRequestHandler(
            const web::http::http_request &request,
            const std::vector<std::string> path);

        /* Verifies that the request has the correct X-API-KEY, and sends a 401
           if it is not. */
        bool checkAuthenticated(const web::http::http_request &request) const;

        /* Opens a wallet */
        void openWallet(
            const web::http::http_request &request,
            const nlohmann::json body);

        void keyImportWallet(
            const web::http::http_request &request,
            const nlohmann::json body);

        void seedImportWallet(
            const web::http::http_request &request,
            const nlohmann::json body);

        void importViewWallet(
            const web::http::http_request &request,
            const nlohmann::json body);

        void createWallet(
            const web::http::http_request &request,
            const nlohmann::json body);

        /* Check we don't already have a wallet open, returns 403 if we do */
        bool isWalletAlreadyOpen(const web::http::http_request &request) const;

        /* Check we have a wallet open, returns 403 if we don't */
        bool isWalletClosed(const web::http::http_request &request) const;

        /* Extracts {host, port, filename, password}, from body */
        std::tuple<std::string, uint16_t, std::string, std::string>
            getDefaultWalletParams(const nlohmann::json body) const;

        /* Writes the error message to the response */
        void writeError(
            const web::http::http_request &request,
            const WalletError error) const;

        void closeWallet();

        //////////////////////////////
        /* Private member variables */
        //////////////////////////////

        std::shared_ptr<WalletBackend> m_walletBackend = nullptr;

        web::http::experimental::listener::http_listener m_server;

        std::string m_hashedPassword;

        std::mutex m_mutex;
};
