// Copyright (c) 2018, The TurtleCoin Developers
// 
// Please see the included LICENSE file for more information.

////////////////////////
#include <Nigel/Nigel.h>
////////////////////////

#include <config/CryptoNoteConfig.h>

#include <WalletBackend/Utilities.h>
#include <WalletBackend/ValidateParameters.h>

using namespace web::http;
using namespace web::http::client;

using json = nlohmann::json;

////////////////////////////////
/* Constructors / Destructors */
////////////////////////////////

Nigel::Nigel(
    const std::string daemonHost, 
    const uint16_t daemonPort) : 
    Nigel(daemonHost, daemonPort, std::chrono::seconds(10))
{
}

Nigel::Nigel(
    const std::string daemonHost, 
    const uint16_t daemonPort,
    const std::chrono::milliseconds timeout)
{
    m_config.set_timeout(timeout);

    m_httpClient = std::make_shared<http_client>(
        "http://" + daemonHost + ":" + std::to_string(daemonPort), m_config
    );
}

Nigel::~Nigel()
{
    stop();
}

//////////////////////
/* Member functions */
//////////////////////

void Nigel::swapNode(const std::string daemonHost, const uint16_t daemonPort)
{
    stop();

    m_localDaemonBlockCount = 0;
    m_networkBlockCount = 0;
    m_peerCount = 0;
    m_lastKnownHashrate = 0;

    m_httpClient = std::make_shared<http_client>(
        "http://" + daemonHost + ":" + std::to_string(daemonPort), m_config
    );

    init();
}

pplx::task<std::vector<WalletTypes::WalletBlockInfo>> Nigel::getWalletSyncData(
    const std::vector<Crypto::Hash> blockHashCheckpoints,
    uint64_t startHeight,
    uint64_t startTimestamp) const
{
    http_request req(methods::POST);
    req.set_request_uri("/getwalletsyncdata");

    json j = {
        {"blockHashCheckpoints", blockHashCheckpoints},
        {"startHeight", startHeight},
        {"startTimestamp", startTimestamp}
    };

    req.set_body(j.dump());

    return m_httpClient->request(req).then(
    [](http_response response)
    {
        return response.extract_string(true);
    })
    .then([](std::string body) -> std::vector<WalletTypes::WalletBlockInfo>
    {
        try
        {
            json j = json::parse(body);

            if (j.at("status").get<std::string>() != "OK")
            {
                return {};
            }

            return j.at("items").get<std::vector<WalletTypes::WalletBlockInfo>>();
        }
        catch (const json::exception &e)
        {
            std::cout << e.what() << std::endl;
        }

        return {};
    });
}

void Nigel::stop()
{
    m_shouldStop = true;

    if (m_backgroundThread.joinable())
    {
        m_backgroundThread.join();
    }
}

void Nigel::init()
{
    m_shouldStop = false;

    /* Get the initial daemon info, and the initial fee info before returning.
       This way the info is always valid, and there's no race on accessing
       the fee info or something */
    try
    {
        (getDaemonInfo() && getFeeInfo()).wait();
    }
    catch (const std::exception &e)
    {
        /* TODO */
        std::cout << e.what() << std::endl;
    }

    /* Launch in parallel, wait for both to complete */
    m_backgroundThread = std::thread(&Nigel::backgroundRefresh, this);
}

pplx::task<void> Nigel::getDaemonInfo()
{
    return m_httpClient->request(methods::GET, "/getinfo").then(
    [](http_response response)
    {
        return response.extract_string(true);
    })
    .then([this](std::string body)
    {
        try
        {
            json j = json::parse(body);

            m_localDaemonBlockCount = j.at("height").get<uint64_t>();
            m_networkBlockCount = j.at("network_height").get<uint64_t>();

            m_peerCount = j.at("incoming_connections_count").get<uint64_t>()
                        + j.at("outgoing_connections_count").get<uint64_t>();

            m_lastKnownHashrate = j.at("difficulty").get<uint64_t>() 
                                / CryptoNote::parameters::DIFFICULTY_TARGET;
        }
        catch (const json::exception &e)
        {
        }

        return;
    });
}

pplx::task<void> Nigel::getFeeInfo()
{
    return m_httpClient->request(methods::GET, "/feeinfo").then(
    [](http_response response)
    {
        return response.extract_string(true);
    })
    .then([this](std::string body)
    {
        try
        {
            json j = json::parse(body);

            std::string tmpAddress = j.at("address").get<std::string>();

            uint32_t tmpFee = j.at("amount").get<uint32_t>();

            const bool integratedAddressesAllowed = false;

            if (validateAddresses({tmpAddress}, integratedAddressesAllowed))
            {
                m_nodeFeeAddress = tmpAddress;
                m_nodeFeeAmount = tmpFee;
            }
        }
        catch (const json::exception &e)
        {
        }

        return;
    });
}

void Nigel::backgroundRefresh()
{
    while (!m_shouldStop)
    {
        getDaemonInfo().wait();

        Utilities::sleepUnlessStopping(std::chrono::seconds(10), m_shouldStop);
    }
}

bool Nigel::isOnline() const
{
    return m_localDaemonBlockCount != 0 ||
           m_networkBlockCount != 0 ||
           m_peerCount != 0 ||
           m_lastKnownHashrate != 0;
}

uint64_t Nigel::localDaemonBlockCount() const
{
    return m_localDaemonBlockCount;
}

uint64_t Nigel::networkBlockCount() const
{
    return m_networkBlockCount;
}

uint64_t Nigel::peerCount() const
{
    return m_peerCount;
}

uint64_t Nigel::hashrate() const
{
    return m_lastKnownHashrate;
}


std::tuple<uint64_t, std::string> Nigel::nodeFee() const
{
    return {m_nodeFeeAmount, m_nodeFeeAddress};
}

/* Returns a bool on success or not */
pplx::task<bool> Nigel::getTransactionsStatus(
    const std::unordered_set<Crypto::Hash> transactionHashes,
    std::unordered_set<Crypto::Hash> &transactionsInPool,
    std::unordered_set<Crypto::Hash> &transactionsInBlock,
    std::unordered_set<Crypto::Hash> &transactionsUnknown) const
{
}

pplx::task<std::vector<CryptoNote::RandomOuts>> Nigel::getRandomOutsByAmounts(
    const std::vector<uint64_t> amounts,
    const uint64_t requestedOuts) const
{
}

pplx::task<std::tuple<bool, bool>> Nigel::sendTransaction(
    const CryptoNote::Transaction) const
{
}

pplx::task<std::unordered_map<Crypto::Hash, std::vector<uint64_t>>>
    Nigel::getGlobalIndexesForRange(
        const uint64_t startHeight,
        const uint64_t endHeight) const
{
}
