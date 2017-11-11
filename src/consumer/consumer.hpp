#ifndef NDN_EPAC_CONSUMER_HPP
#define NDN_EPAC_CONSUMER_HPP

#include "core/common.hpp"
#include <ndn-cxx/link.hpp>

#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

namespace ndn {
namespace epac {

/**
 * @brief options for Consumer
 */
struct PeekOptions
{
  std::string prefix;
  int minSuffixComponents;
  int maxSuffixComponents;
  time::milliseconds interestLifetime;
  time::milliseconds timeout;
  shared_ptr<Link> link;
  bool isVerbose;
  bool mustBeFresh;
  bool wantRightmostChild;
  bool wantPayloadOnly;
};

enum class ResultCode {
  NONE = -1,
  DATA = 0,
  NACK = 4,
  TIMEOUT = 3
};

class Consumer : boost::noncopyable
{
public:
  Consumer(Face& face, const PeekOptions& options);

  /**
   * @return the timeout
   */
  time::milliseconds
  getTimeout() const;

  /**
   * @return the result of Peek execution
   */
  ResultCode
  getResultCode() const;

  /**
   * @brief express the Interest
   * @note The caller must invoke face.processEvents() afterwards
   */
  void
  start();

private:
  Interest
  createInterest() const;

  /**
   * @brief called when a Data packet is received
   */
  void
  onData(const Data& data);

  /**
   * @brief called when a Nack packet is received
   */
  void
  onNack(const lp::Nack& nack);

  void
  loadPrivateKey(const std::string& filename, RSA::PrivateKey& key);

  std::string
  decrypt(const std::string &cipher);

private:
  Face& m_face;
  const PeekOptions& m_options;
  time::steady_clock::TimePoint m_expressInterestTime;
  time::milliseconds m_timeout;
  ResultCode m_resultCode;

  RSA::PrivateKey *privateKey;
};

} // namespace epac
} // namespace ndn

#endif // NDN_EPAC_CONSUMER_HPP
