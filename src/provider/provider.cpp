#include "provider.hpp"

namespace ndn {
namespace epac {

Provider::Provider(char* programName)
  : m_programName(programName)
  , m_isForceDataSet(false)
  , m_isUseDigestSha256Set(false)
  , m_isLastAsFinalBlockIdSet(false)
  , m_freshnessPeriod(-1)
  , m_timeout(-1)
  , m_isDataSent(false)
{
  AutoSeededRandomPool rng;
  InvertibleRSAFunction params;

  params.GenerateRandomWithKeySize(rng, 1024);

  privateKey = new RSA::PrivateKey(params);
  publicKey = new RSA::PublicKey(params);

  saveKey("publicKey.key", *publicKey);
  saveKey("privateKey.key", *privateKey);
}

void
Provider::saveKey(const std::string &filename, const CryptoMaterial &key)
{
  ByteQueue queue;
  key.Save(queue);

  FileSink file(filename.c_str());
  queue.CopyTo(file);
  file.MessageEnd();
}

std::string
Provider::encrypt(const std::string &payload)
{
  std::string cipher;
  AutoSeededRandomPool rng;
  RSAES_OAEP_SHA_Encryptor e(*publicKey);

  StringSource ss1(payload, true,
    new PK_EncryptorFilter(rng, e,
      new StringSink(cipher)
    ) // PK_EncryptorFilter
  ); // StringSource

  return cipher;
}

std::string
Provider::decrypt(const std::string &cipher)
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

void
Provider::doRegister(std::string uid, RSA::PublicKey &pubKey)
{
  aut.add(uid, pubKey);
}

void
Provider::usage()
{
  std::cout << "\n Usage:\n " << m_programName << " "
    "[-f] [-D] [-i identity] [-F] [-x freshness] [-w timeout] ndn:/name\n"
    "   Reads payload from stdin and sends it to local NDN forwarder as a "
    "single Data packet\n"
    "   [-f]          - force, send Data without waiting for Interest\n"
    "   [-D]          - use DigestSha256 signing method instead of "
    "SignatureSha256WithRsa\n"
    "   [-i identity] - set identity to be used for signing\n"
    "   [-F]          - set FinalBlockId to the last component of Name\n"
    "   [-x]          - set FreshnessPeriod in time::milliseconds\n"
    "   [-w timeout]  - set Timeout in time::milliseconds\n"
    "   [-h]          - print help and exit\n"
    "   [-V]          - print version and exit\n"
    "\n";
  exit(1);
}

void
Provider::setForceData()
{
  m_isForceDataSet = true;
}

void
Provider::setUseDigestSha256()
{
  m_isUseDigestSha256Set = true;
}

void
Provider::setIdentityName(char* identityName)
{
  m_identityName = make_shared<Name>(identityName);
}

void
Provider::setLastAsFinalBlockId()
{
  m_isLastAsFinalBlockIdSet = true;
}

void
Provider::setFreshnessPeriod(int freshnessPeriod)
{
  if (freshnessPeriod < 0)
    usage();

  m_freshnessPeriod = time::milliseconds(freshnessPeriod);
}

void
Provider::setTimeout(int timeout)
{
  if (timeout < 0)
    usage();

  m_timeout = time::milliseconds(timeout);
}

void
Provider::setPrefixName(char* prefixName)
{
  m_prefixName = Name(prefixName);
}

time::milliseconds
Provider::getDefaultTimeout()
{
  return time::seconds(10);
}

shared_ptr<Data>
Provider::createDataPacket()
{
  auto dataPacket = make_shared<Data>(m_prefixName);

  std::stringstream payloadStream;
  payloadStream << std::cin.rdbuf();
  std::string payloadPlain = payloadStream.str();
  std::string payload = encrypt(payloadPlain);
  dataPacket->setContent(reinterpret_cast<const uint8_t*>(payload.c_str()), payload.length());

  if (m_freshnessPeriod >= time::milliseconds::zero())
    dataPacket->setFreshnessPeriod(m_freshnessPeriod);

  if (m_isLastAsFinalBlockIdSet) {
    if (!m_prefixName.empty())
      dataPacket->setFinalBlockId(m_prefixName.get(-1));
    else {
      std::cerr << "Name Provided Has 0 Components" << std::endl;
      exit(1);
    }
  }

  return dataPacket;
}

void
Provider::onInterest(const Name& name,
           const Interest& interest,
           shared_ptr<Data> dataPacket)
{
  m_face.put(*dataPacket);
  m_isDataSent = true;
  m_face.shutdown();
}

void
Provider::onRegisterFailed(const Name& prefix, const std::string& reason)
{
  std::cerr << "Prefix Registration Failure." << std::endl;
  std::cerr << "Reason = " << reason << std::endl;
}

void
Provider::run()
{
  try {
    shared_ptr<Data> dataPacket = createDataPacket();
    if (m_isForceDataSet) {
      m_face.put(*dataPacket);
      m_isDataSent = true;
    }
    else {
      m_face.setInterestFilter(m_prefixName,
                               bind(&Provider::onInterest, this, _1, _2, dataPacket),
                               RegisterPrefixSuccessCallback(),
                               bind(&Provider::onRegisterFailed, this, _1, _2));
    }

    if (m_timeout < time::milliseconds::zero())
      m_face.processEvents(getDefaultTimeout());
    else
      m_face.processEvents(m_timeout);
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << "\n" << std::endl;
    exit(1);
  }
}

bool
Provider::isDataSent() const
{
  return m_isDataSent;
}

int
main(int argc, char* argv[])
{
  int option;
  Provider program(argv[0]);
  while ((option = getopt(argc, argv, "hfDi:Fx:w:V")) != -1) {
    switch (option) {
    case 'h':
      program.usage();
      break;
    case 'f':
      program.setForceData();
      break;
    case 'D':
      program.setUseDigestSha256();
      break;
    case 'i':
      program.setIdentityName(optarg);
      break;
    case 'F':
      program.setLastAsFinalBlockId();
      break;
    case 'x':
      program.setFreshnessPeriod(atoi(optarg));
      break;
    case 'w':
      program.setTimeout(atoi(optarg));
      break;
    case 'V':
      std::cout << "ndnpoke " << tools::VERSION << std::endl;
      return 0;
    default:
      program.usage();
      break;
    }
  }

  argc -= optind;
  argv += optind;

  if (argv[0] == 0)
    program.usage();

  program.setPrefixName(argv[0]);
  program.run();

  if (program.isDataSent())
    return 0;
  else
    return 1;
}

} // namespace epac
} // namespace ndn

int
main(int argc, char** argv)
{
  return ndn::epac::main(argc, argv);
}
