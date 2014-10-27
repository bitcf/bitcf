#include "db.h"
#include "bitcoinrpc.h"
#include "base58.h"

class CNameIndex
{
public:
    CDiskTxPos txPos;
    unsigned int nHeight;
    std::vector<unsigned char> vValue;

    CNameIndex()
    {
    }

    CNameIndex(CDiskTxPos txPosIn, unsigned int nHeightIn, std::vector<unsigned char> vValueIn)
    {
        txPos = txPosIn;
        nHeight = nHeightIn;
        vValue = vValueIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(txPos);
        READWRITE(nHeight);
        READWRITE(vValue);
    )
};

class CNameDB : public CDB
{
public:
    CNameDB(const char* pszMode="r+") : CDB("nameindex.dat", pszMode) {}

    //bool WriteName(std::vector<unsigned char>& name, std::vector<CDiskTxPos> vtxPos)
//    bool WriteName(const std::vector<unsigned char>& name, std::vector<CNameIndex>& vtxPos)
//    {
//        return Write(make_pair(std::string("namei"), name), vtxPos);
//    }

    bool WriteName(const std::vector<unsigned char>& name, std::vector<CNameIndex>& vtxPos, int nExpiresAt)
    {
        return Write(make_pair(std::string("namei"), name), make_pair(vtxPos, nExpiresAt));
    }

    //bool ReadName(std::vector<unsigned char>& name, std::vector<CDiskTxPos>& vtxPos)
//    bool ReadName(const std::vector<unsigned char>& name, std::vector<CNameIndex>& vtxPos)
//    {
//        return Read(make_pair(std::string("namei"), name), vtxPos);
//    }

    bool ReadName(const std::vector<unsigned char>& name, std::vector<CNameIndex>& vtxPos, int &nExpiresAt)
    {
        std::pair< std::vector<CNameIndex>, int > v;
        bool ret = Read(make_pair(std::string("namei"), name), v);
        vtxPos = v.first;
        nExpiresAt = v.second;
        return ret;
    }

    bool ExistsName(const std::vector<unsigned char>& name)
    {
        return Exists(make_pair(std::string("namei"), name));
    }

    bool EraseName(const std::vector<unsigned char>& name)
    {
        return Erase(make_pair(std::string("namei"), name));
    }

    bool ScanNames(
            const std::vector<unsigned char>& vchName,
            int nMax,
            std::vector<
                std::pair<
                    std::vector<unsigned char>,
                    std::pair<CNameIndex, int>
                >
            >& nameScan
            );

    bool ReconstructNameIndex();
};

static const int NAMECOIN_TX_VERSION = 0x0666; //0x0666 is initial version
static const int MAX_NAME_LENGTH = 512;
static const int MAX_VALUE_LENGTH = 20*1024;
static const int MAX_RENTAL_DAYS = 100*365; //100 years
static const int OP_NAME_NEW = 0x01;
static const int OP_NAME_UPDATE = 0x02;
static const int OP_NAME_DELETE = 0x03;
static const int MIN_FIRSTUPDATE_DEPTH = 12;

static const int RELEASE_HEIGHT = 1<<16;

extern std::map<std::vector<unsigned char>, uint256> mapMyNames;
extern std::map<std::vector<unsigned char>, std::set<uint256> > mapNamePending;

int IndexOfNameOutput(const CTransaction& tx);

bool GetNameCurrentAddress(const std::vector<unsigned char> &vchName, CBitcoinAddress &address, std::string &error);
bool GetExpirationData(CNameDB& dbName, const std::vector<unsigned char> &vchName, int& nTotalLifeTime, int& nHeight);
bool GetTxPosHeight(const CDiskTxPos& txPos, int& nHeight);
std::string stringFromVch(const std::vector<unsigned char> &vch);
std::vector<unsigned char> vchFromString(const std::string &str);

int64 GetNameOpFee(const CBlockIndex* pindexBlock, const int nRentalDays, int op, const std::vector<unsigned char> &vchName, const std::vector<unsigned char> &vchValue);

struct NameTxInfo
{
    std::vector<unsigned char> vchName;
    std::vector<unsigned char> vchValue;
    int nRentalDays;
    int op;
    int nOut;
    std::string err_msg; //in case function that takes this as argument have something to say about it

    //used only by DecodeNameScript()
    std::string strAddress;
    bool fIsMine;

    //used only by GetNameList()
    int nExpiresAt;

    NameTxInfo(): nRentalDays(-1), op(-1), nOut(-1), fIsMine(false), nExpiresAt(-1) {}
    NameTxInfo(std::vector<unsigned char> vchName1, std::vector<unsigned char> vchValue1, int nRentalDays1, int op1, int nOut1, std::string err_msg1):
        vchName(vchName1), vchValue(vchValue1), nRentalDays(nRentalDays1), op(op1), nOut(nOut1), err_msg(err_msg1), fIsMine(false), nExpiresAt(-1) {}
};

bool DecodeNameScript(const CScript& script, NameTxInfo& ret, bool checkValuesCorrectness = true, bool checkAddressAndIfIsMine = false);
bool DecodeNameScript(const CScript& script, NameTxInfo& ret, CScript::const_iterator& pc, bool checkValuesCorrectness = true, bool checkAddressAndIfIsMine = false);
bool DecodeNameTx(const CTransaction& tx, NameTxInfo& nti, bool checkValuesCorrectness = true, bool checkAddressAndIfIsMine = false);

void GetNameList(const std::vector<unsigned char> &vchNameUniq, std::map<std::vector<unsigned char>, NameTxInfo> &mapNames, std::map<std::vector<unsigned char>, NameTxInfo> &mapPending);

struct NameTxReturn
{
     bool ok;
     std::string err_msg;
     RPCErrorCode err_code;
     std::string address;
     uint256 hex;   // Transaction hash in hex
};
NameTxReturn name_new(const std::vector<unsigned char> &vchName,
              const std::vector<unsigned char> &vchValue,
              const int nRentalDays);
NameTxReturn name_update(const std::vector<unsigned char> &vchName,
              const std::vector<unsigned char> &vchValue,
              const int nRentalDays, std::string strAddress = "");
NameTxReturn name_delete(const std::vector<unsigned char> &vchName);
