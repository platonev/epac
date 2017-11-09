#ifndef NDN_TOOLS_NDNPEEK_NDNPOKE_HPP
#define NDN_TOOLS_NDNPEEK_NDNPOKE_HPP

#include "core/version.hpp"

#include <sstream>

namespace ndn {
namespace peek {

class NdnPoke : boost::noncopyable
{
public:
  explicit
  NdnPoke(char* programName);

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

private:
  KeyChain m_keyChain;
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
};
} // namespace peek
} // namespace ndn

#endif