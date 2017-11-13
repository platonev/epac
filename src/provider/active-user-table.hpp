#ifndef NDN_EPAC_ACTIVE_USER_TABLE_HPP
#define NDN_EPAC_ACTIVE_USER_TABLE_HPP

#include <core/common.hpp>

using namespace CryptoPP;

namespace ndn {
namespace epac {

class ActiveUserTable
{
public:
  void
  add(std::string uid, RSA::PublicKey &pubKey);

  RSA::PublicKey
  findPublicKeyByUserId(std::string uid);

private:
  std::unordered_map<std::string, RSA::PublicKey> aut;
};
}
} // namespace ndn

#endif
