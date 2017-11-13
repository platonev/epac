#ifndef NDN_EPAC_CORE_COMMON_HPP
#define NDN_EPAC_CORE_COMMON_HPP

#include <cinttypes>
#include <cstddef>
#include <sstream>
#include <iostream>
#include <list>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/assert.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/noncopyable.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>

#include <ndn-cxx/data.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/link.hpp>
#include <ndn-cxx/util/backports.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <ndn-cxx/util/scheduler-scoped-event-id.hpp>
#include <ndn-cxx/util/signal.hpp>

#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>

namespace ndn {

using std::size_t;

using boost::noncopyable;

namespace signal = util::signal;
namespace scheduler = util::scheduler;

} // namespace ndn

#endif // NDN_EPAC_CORE_COMMON_HPP
