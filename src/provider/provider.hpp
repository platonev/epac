#ifndef NDN_EPAC_PROVIDER_HPP
#define NDN_EPAC_PROVIDER_HPP

#include "core/version.hpp"
#include "core/common.hpp"
#include "active-user-table.hpp"

using namespace CryptoPP;

namespace ndn {
namespace epac {

class Provider : boost::noncopyable
{
public:
  explicit
  Provider(char* programName);

  void
  usage();

  void
  setForceData();

  void
  setUseDigestSha256();

  void
  setIdentityName(char* identityName);

  void
  setLastAsFinalBlockId();

  void
  setFreshnessPeriod(int freshnessPeriod);

  void
  setTimeout(int timeout);

  void
  setPrefixName(char* prefixName);

  time::milliseconds
  getDefaultTimeout();

  shared_ptr<Data>
  createDataPacket();

  void
  onInterest(const Name& name,
             const Interest& interest,
             shared_ptr<Data> dataPacket);

  void
  onRegisterFailed(const Name& prefix, const std::string& reason);

  void
  run();

  bool
  isDataSent() const;

  void
  saveKey(const std::string &filename, const CryptoMaterial &key);

  std::string
  encrypt(const std::string &payload);

  std::string
  decrypt(const std::string &cipher);

  void
  doRegister(std::string uid, RSA::PublicKey &pubKey);

private:
  std::string m_programName;
  bool m_isForceDataSet;
  bool m_isUseDigestSha256Set;
  shared_ptr<Name> m_identityName;
  bool m_isLastAsFinalBlockIdSet;
  time::milliseconds m_freshnessPeriod;
  time::milliseconds m_timeout;
  Name m_prefixName;
  bool m_isDataSent;
  Face m_face;

  ActiveUserTable aut;

  RSA::PrivateKey *privateKey;
  RSA::PublicKey * publicKey;
};
} // namespace epac
} // namespace ndn

#endif
