#include "active-user-table.hpp"

namespace ndn {
namespace epac {

void
ActiveUserTable::add(std::string uid, RSA::PublicKey &pubKey)
{
  aut.insert({uid, pubKey});
}

RSA::PublicKey
ActiveUserTable::findPublicKeyByUserId(std::string uid) {
  return aut.find(uid)->second;
}

} // namespace epac
} // namespace ndn
