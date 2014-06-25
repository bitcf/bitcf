#include "db.h"
#include "bitcoinrpc.h"

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

void encodeOrDecode(std::vector<unsigned char> &vchData);

//NOTE: CNameDB stores data in xor-encoded form to prevent antivirus from complaining about nameindex.dat.
//      All access to CNameDB should be done in pure un-encoded form.
//      And you should NOT attempt to read/write to CNameDB with CDB functions - use CNameDB public functions instead!
//      TODO: reimplement this class to have CDB as a private member or as a private inheritance, so that users of this class cannot directly invoke CDB functions.
class CNameDB : public CDB
{
protected:
    bool fHaveParent;
public:
    CNameDB(const char* pszMode="r+") : CDB("nameindex.dat", pszMode) {
        fHaveParent = false;
    }

    CNameDB(const char* pszMode, CDB& parent) : CDB("nameindex.dat", pszMode) {
        vTxn.push_back(parent.GetTxn());
        fHaveParent = true;
    }

    ~CNameDB()
    {
        if (fHaveParent)
            vTxn.erase(vTxn.begin());
    }

    bool WriteName(std::vector<unsigned char> name, std::vector<CNameIndex> vtxPos)
    {
        //encode before writing
        encodeOrDecode(name);
        BOOST_FOREACH(CNameIndex& ind, vtxPos)
            encodeOrDecode(ind.vValue);

        return Write(make_pair(std::string("namei"), name), vtxPos);
    }

    bool ReadName(std::vector<unsigned char> name, std::vector<CNameIndex>& vtxPos)
    {
        //encode name before reading data
        encodeOrDecode(name);
        if (!Read(make_pair(std::string("namei"), name), vtxPos))
            return false;

        //decode returned data
        BOOST_FOREACH(CNameIndex& ind, vtxPos)
            encodeOrDecode(ind.vValue);

        return true;
    }

    bool ExistsName(std::vector<unsigned char> name)
    {
        //encode name before doing check
        encodeOrDecode(name);

        return Exists(make_pair(std::string("namei"), name));
    }

    bool EraseName(std::vector<unsigned char> name)
    {
        //encode name before erasing
        encodeOrDecode(name);

        return Erase(make_pair(std::string("namei"), name));
    }

    bool ScanNames(
            std::vector<unsigned char> vchName,
            int nMax,
            std::vector<std::pair<std::vector<unsigned char>, CNameIndex> >& nameScan);

    bool ReconstructNameIndex();
};

static const int NAMECOIN_TX_VERSION = 0x0666; //0x0666 is initial version
static const int MAX_NAME_LENGTH = 512;
static const int MAX_VALUE_LENGTH = 20*1024;
static const int MAX_RENTAL_DAYS = 100*365; //100 years
static const int OP_NAME_NEW = 0x01;
static const int OP_NAME_UPDATE = 0x02;
static const int MIN_FIRSTUPDATE_DEPTH = 12;

extern std::map<std::vector<unsigned char>, uint256> mapMyNames;
extern std::map<std::vector<unsigned char>, std::set<uint256> > mapNamePending;

int IndexOfNameOutput(const CTransaction& tx);

bool GetNameOfTx(const CTransaction& tx, std::vector<unsigned char>& name);
bool GetValueOfNameTx(const CTransaction& tx, std::vector<unsigned char>& value);
bool GetRentalDaysOfNameTx(const CTransaction& tx, int &nRentalDays);
bool GetValueOfTxPos(const CDiskTxPos& txPos, std::vector<unsigned char>& vchValue, uint256& hash, int& nHeight);
bool GetNameTotalLifeTime(const std::vector<unsigned char> &vchName, int &nTotalLifeTime);
bool GetExpirationData(const std::vector<unsigned char> &vchName, int& nTotalLifeTime, int& nHeight);
int GetTxPosHeight(const CDiskTxPos& txPos);
bool GetNameTxAddress(const CTransaction& tx, std::string& strAddress);
std::string stringFromVch(const std::vector<unsigned char> &vch);
int GetNameHeight(CNameDB& dbName, std::vector<unsigned char> vchName);
std::vector<unsigned char> vchFromString(const std::string &str);

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
    int nIsMine;  //  -1 - unknown,   0 - not mine,   1 - is mine

    //used only by GetNameList()
    int nTimeLeft;

    NameTxInfo(): nRentalDays(-1), op(-1), nOut(-1), nIsMine(-1), nTimeLeft(-1) {}
    NameTxInfo(std::vector<unsigned char> vchName1, std::vector<unsigned char> vchValue1, int nRentalDays1, int op1, int nOut1, std::string err_msg1):
        vchName(vchName1), vchValue(vchValue1), nRentalDays(nRentalDays1), op(op1), nOut(nOut1), err_msg(err_msg1), nIsMine(-1), nTimeLeft(-1) {}
};

bool DecodeNameScript(const CScript& script, NameTxInfo& ret, bool checkValuesCorrectness = true, bool checkAddressAndIfIsMine = false);
bool DecodeNameScript(const CScript& script, NameTxInfo& ret, CScript::const_iterator& pc, bool checkValuesCorrectness = true, bool checkAddressAndIfIsMine = false);
bool DecodeNameTx(const CTransaction& tx, NameTxInfo& nti, bool checkValuesCorrectness = true, bool checkAddressAndIfIsMine = false);

std::map<std::vector<unsigned char>, NameTxInfo> GetNameList(const std::vector<unsigned char> &vchNameUniq = std::vector<unsigned char>());

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
