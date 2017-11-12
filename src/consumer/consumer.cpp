#include "consumer.hpp"

namespace ndn {
namespace epac {

Consumer::Consumer(Face& face, const PeekOptions& options)
  : m_face(face)
  , m_options(options)
  , m_timeout(options.timeout)
  , m_resultCode(ResultCode::TIMEOUT)
{
  if (m_timeout < time::milliseconds::zero()) {
    m_timeout = m_options.interestLifetime < time::milliseconds::zero() ?
                DEFAULT_INTEREST_LIFETIME : m_options.interestLifetime;
  }

  AutoSeededRandomPool rng;
  InvertibleRSAFunction params;

  params.GenerateRandomWithKeySize(rng, 1024);

  privateKey = new RSA::PrivateKey(params);
  publicKey = new RSA::PublicKey(params);
}

void
Consumer::loadPrivateKey(const std::string &filename, RSA::PrivateKey &key)
{
  ByteQueue queue;
  FileSource file(filename.c_str(), true /*pumpAll*/);
  file.TransferTo(queue);
  queue.MessageEnd();
  key.Load(queue);
}

std::string
Consumer::decrypt(const std::string &cipher)
{
  AutoSeededRandomPool rng;
  std::string recovered;
  RSAES_OAEP_SHA_Decryptor d(*privateKey);
  StringSource ss2(cipher, true,
    new PK_DecryptorFilter(rng, d,
      new StringSink(recovered)
    ) // PK_DecryptorFilter
  ); // StringSource

  return recovered;
}

time::milliseconds
Consumer::getTimeout() const
{
  return m_timeout;
}

ResultCode
Consumer::getResultCode() const
{
  return m_resultCode;
}

void
Consumer::start()
{
  m_face.expressInterest(createInterest(),
                         bind(&Consumer::onData, this, _2),
                         bind(&Consumer::onNack, this, _2),
                         nullptr);
  m_expressInterestTime = time::steady_clock::now();
}

Interest
Consumer::createInterest() const
{
  Interest interest(m_options.prefix);

  if (m_options.minSuffixComponents >= 0)
    interest.setMinSuffixComponents(m_options.minSuffixComponents);

  if (m_options.maxSuffixComponents >= 0)
    interest.setMaxSuffixComponents(m_options.maxSuffixComponents);

  if (m_options.interestLifetime >= time::milliseconds::zero())
    interest.setInterestLifetime(m_options.interestLifetime);

  if (m_options.link != nullptr)
    interest.setForwardingHint(m_options.link->getDelegationList());

  if (m_options.mustBeFresh)
    interest.setMustBeFresh(true);

  if (m_options.wantRightmostChild)
    interest.setChildSelector(1);

  if (m_options.isVerbose) {
    std::cerr << "INTEREST: " << interest << std::endl;
  }

  return interest;
}

void
Consumer::onData(const Data& data)
{
  m_resultCode = ResultCode::DATA;

  if (m_options.isVerbose) {
    std::cerr << "DATA, RTT: "
              << time::duration_cast<time::milliseconds>(time::steady_clock::now() - m_expressInterestTime).count()
              << "ms" << std::endl;
  }

  if (m_options.wantPayloadOnly) {
    const Block& block = data.getContent();
    std::string info = std::string(reinterpret_cast<const char*>(block.value()), block.value_size());
    std::string result = decrypt(info);
    std::cout << result << std::endl;
    //std::cout.write(reinterpret_cast<const char*>(block.value()), block.value_size());
  }
  else {
    const Block& block = data.wireEncode();
    std::cout.write(reinterpret_cast<const char*>(block.wire()), block.size());
  }
}

void
Consumer::onNack(const lp::Nack& nack)
{
  m_resultCode = ResultCode::NACK;
  lp::NackHeader header = nack.getHeader();

  if (m_options.isVerbose) {
    std::cerr << "NACK, RTT: "
              << time::duration_cast<time::milliseconds>(time::steady_clock::now() - m_expressInterestTime).count()
              << "ms" << std::endl;
  }

  if (m_options.wantPayloadOnly) {
    std::cout << header.getReason() << std::endl;
  }
  else {
    const Block& block = header.wireEncode();
    std::cout.write(reinterpret_cast<const char*>(block.wire()), block.size());
  }
}

} // namespace epac
} // namespace ndn
