// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//#include <boost/assign/list_of.hpp>

//#include "wallet.h"
//#include "walletdb.h"
#include "bitcoinrpc.h"
#include "init.h"
//#include "base58.h"

//using namespace std;
//using namespace boost;
//using namespace boost::assign;
//using namespace json_spirit;

std::string HelpRequiringPassphrase()
{
    return pwalletMain->IsCrypted()
        ? "\nrequires wallet passphrase to be set with walletpassphrase first"
        : "";
}

void EnsureWalletIsUnlocked()
{
    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    if (fWalletUnlockMintOnly)
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Wallet unlocked for block minting only, unable to create transaction.");
}
