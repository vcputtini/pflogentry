/***************************************************************************
 * Copyright (c) 2021                                                      *
 *      Volnei Cervi Puttini.  All rights reserved.                        *
 *      vcputtini@gmail.com
 *                                                                         *
 * Redistribution and use in source and binary forms, with or without      *
 * modification, are permitted provided that the following conditions      *
 * are met:                                                                *
 * 1. Redistributions of source code must retain the above copyright       *
 *    notice, this list of conditions and the following disclaimer.        *
 * 2. Redistributions in binary form must reproduce the above copyright    *
 *    notice, this list of conditions and the following disclaimer in the  *
 *    documentation and/or other materials provided with the distribution. *
 * 4. Neither the name of the Author     nor the names of its contributors *
 *    may be used to endorse or promote products derived from this software*
 *    without specific prior written permission.                           *
 *                                                                         *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND *
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE   *
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR      *
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS  *
 * BE LIABLEFOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR   *
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF    *
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS*
 * INTERRUPTION)                                                           *
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,     *
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING   *
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE      *
 * POSSIBILITY OFSUCH DAMAGE.                                              *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#ifndef PFLOGENTRY_H
#define PFLOGENTRY_H

#include <algorithm>
#include <chrono>
#include <climits> // INT_MAX, LONG_MAX, UINT_MAX, ...
#include <cstddef> // size_t
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iomanip> // std::setw()
#include <iostream>
#include <map>
#include <numeric> // accumulate
#include <regex>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include <tinyxml2.h>
using namespace tinyxml2;

#if defined(_MSC_VER) || defined(WIN64) || defined(_WIN64) ||                  \
  defined(__WIN64__) || defined(WIN32) || defined(_WIN32) ||                   \
  defined(__WIN32__) || defined(__NT__)
#define Q_DECL_EXPORT __declspec(dllexport)
#define Q_DECL_IMPORT __declspec(dllimport)
#else
#define Q_DECL_EXPORT __attribute__((visibility("default")))
#define Q_DECL_IMPORT __attribute__((visibility("default")))
#endif

#if defined(PFLogentry_LIBRARY)
#define PFLogentry_EXPORT Q_DECL_EXPORT
#else
#define PFLogentry_EXPORT Q_DECL_IMPORT
#endif

namespace pflogentry {

/*!
 * \brief The FilterData class, contains options and data definitions.
 * \note More details:
 * https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html
 */
struct PFLogentry_EXPORT FilterData
{
  /// Raw filter log format
  struct LogData
  {

    struct Header
    {
      std::string id = {}; // RFC-5424: <nnn>n

      // The default is a string from Jan to Dec. Converted to
      // number from 1 to 12 to simplify queries.
      int month = {};
      int day = 0;
      std::string time = {}; // both: RFC-5424 and RFC-3164
      std::tm tm_time = {};
    } header;

    std::string hostname = {};

    long rule_number = 0;
    long sub_rule_number = 0;
    std::string anchor = {};
    long tracker = 0;
    std::string real_iface = {};
    std::string reason = {};
    std::string action = {};
    std::string direction = {};
    int ip_version = 0;

    struct IPv4Data
    {
      std::string tos = {};
      std::string ecn = {};
      int ttl = 0;
      int packet_id = 0;
      int offset = 0;
      std::string flags = {};
    } ipv4_data;

    struct IPv6Data
    {
      std::string class_data = {};
      std::string flow_label = {};
      int hop_limit = 0;
    } ipv6_data;

    // IPv4 or IPv6
    int proto_id = 0;
    std::string proto_text = {}; // "tcp"|"udp"|"icmp" etc.

    int length_data = 0; // Length of the packet in bytes
    std::string ip_src_addr = {};
    std::string ip_dst_addr = {};

    // TCP or UDP
    int src_port = 0;
    int dst_port = 0;
    long data_len = 0; // Data/payload length

    struct ProtoTCP
    {
      std::string flags = {};
      long seq = 0;
      std::string seq_s = {}; // "value_a:value_b" eg: "2571621285:2571621573"
      long ack = 0;
      long window = 0;
      long urg = 0;
      std::string options = {};
    } tcp;

    // ipv4(1) & ipv6(58)
    struct ProtoICMP
    {
      std::string type = {};
      std::string echo_type = {};
      int id = 0;
      long seq = 0;
      std::string src_addr = {};
      std::string dst_addr = {};
      int proto_id = 0;
      int port = 0;
      std::string descr = {};
      int mtu = 0;
      uint32_t otime = 0; // original unix-timestamp
      uint32_t rtime = 0; // received
      uint32_t ttime = 0; // transmit
    } icmp;

    struct ProtoIGMP
    { // ID 2
      std::string src = {};
      std::string dst = {};
    } igmp;

    struct ProtoCARP
    {                        // ID 112
      std::string type = {}; // CARP/VRRP
      int ttl = 0;
      int vhid = 0;
      int version = 0;
      int advbase = 0;
      int advskew = 0;
    } carp;
  };

  /*!
   * \enum LogFormat
   * This enum contains the options available for choosing
   * between log formats.
   *
   * \note https://datatracker.ietf.org/doc/html/rfc3164
   * \note: https://datatracker.ietf.org/doc/html/rfc5424#section-6.2
   */
  enum class LogFormat
  {
    LogBSD = 0x00, //!< BSD RFC-3164 Default
    LogSyslog      //!< RFC-5424 w/ RFC-3339 microssecond-prec timestamp
  };

  /*!
   * \enum This enum contains the options to set the behavior of internal
   * functions, as well as choosing the behavior by user.
   */
  enum class IPVersion
  {
    IPv4 = 4, //!< IP version 4
    IPv6 = 6  //!< IP version 6
  };

  /*!
   * \enum This enum contains the options that identifies the protocol types.
   */
  enum ProtoID
  {
    ProtoHOPOPT = 0, //!< IPv6 Hop-by-Hop Option [RFC8200]
    ProtoIGMP = 2,   //!< IGMP
    ProtoTCP = 6,    //!< IGMP
    ProtoUDP = 17,   //!< UDP
    ICMPv4 = 1,      //!< ICMP v4
    ICMPv6 = 58,     //!< ICMP v6
    ProtoCARP = 112, //!< CARP
  };

  enum ICMPType
  {
    Request = 0x00,
    Reply,
    UnReachProto,
    UnReachPort,
    UnReach,
    TimeExceed,
    ParamProb,
    Redirect,
    MaskReply,
    NeedFrag,
    TStamp,
    TStampReply
  };

  std::map<const std::string, ICMPType> icmp_m = {
    { "request", Request },
    { "reply", Reply },
    { "unreachproto", UnReachProto },
    { "unreachPort", UnReachPort },
    { "unreach", UnReach },
    { "timexceed", TimeExceed },
    { "paramprob", ParamProb },
    { "redirect", Redirect },
    { "maskreply", MaskReply },
    { "needfrag", NeedFrag },
    { "tstamp", TStamp },
    { "tstampreply", TStampReply }
  };

  /*!
   * \enum The Fields enum contains the options that identifies each data field
   * of log entries.
   */
  enum Fields
  {
    HdrID = 0x00,
    HdrMonth,
    HdrDay,
    HdrTimeStamp,
    HostName,
    RuleNumber,
    SubRuleNumber,
    Anchor,
    Tracker,
    RealIFace,
    Reason,
    Action,
    Direction,
    IpVersion,
    Ipv4DataTOS,
    Ipv4DataECN,
    Ipv4DataTTL,
    Ipv4DataPKTID,
    Ipv4DataOFFSET,
    Ipv4DataFLAGS,
    Ipv6DataCLASS,
    Ipv6DataFLOWLABEL,
    Ipv6DataHOPLIM,
    ProtoId,
    ProtoText,
    Length,
    IpSrcAddr,
    IpDstAddr,
    SrcPort,
    DstPort,
    DataLen,
    TcpFLAGS,
    TcpSEQ,
    TcpACK,
    TcpWIN,
    TcpURG,
    TcpOPTS,
    IcmpType,
    IcmpEchoType,
    IcmpID,
    IcmpSEQ,
    IcmpSrcAddr,
    IcmpDstAddr,
    IcmpProtoId,
    IcmpPort,
    IcmpDescr,
    IcmpMTU,
    IcmpOTime,
    IcmpRTime,
    IcmpTTime,
    IgmpSrc,
    IgmpDst,
    CarpType,
    CarpTTL,
    CarpVHID,
    CarpVersion,
    CarpAdvBase,
    CarpAdvSkew
  };

  /*!
   * \internal
   * \brief The PFLError enum
   */
  enum class PFLError
  {
    PFL_SUCCESS = 0x00,
    PFL_ERR_ARG1_GT_ARG2,
    PFL_ERR_INCOMPLETE_NUM_ARGS,
    PFL_ERR_INDEX_OUT_OF_RANGE,
    PFL_ERR_INVALID_DATE_FORMAT,
    PFL_ERR_INVALID_TIME_FORMAT,
    PFL_ERR_INVALID_DATE_TIME_FORMAT,
    PFL_ERR_PARSE_INVALID_LINE,
    PFL_ERR_PARSE_INVALID_RULENUM,
    PFL_ERR_PARSE_INVALID_PROTOCOL,
    PFL_ERR_XML_FILE_NOT_SAVE,
    PFL_ERR_XML_FILE_NAME_INCONSISTENT,
    PFL_ERR_UNKNOWN
  };

  /*!
   * \internal
   */
  std::map<PFLError, const std::string> mError = {
    { PFLError::PFL_SUCCESS, "Success!" },
    { PFLError::PFL_ERR_ARG1_GT_ARG2, "Arg1_ > Arg2_" },
    { PFLError::PFL_ERR_INCOMPLETE_NUM_ARGS,
      "Incomplete Number of Arguments." },
    { PFLError::PFL_ERR_INDEX_OUT_OF_RANGE, "Index Out of Range." },
    { PFLError::PFL_ERR_INVALID_DATE_FORMAT,
      "Date is not in ISO format (yyyy-mm-dd)." },
    { PFLError::PFL_ERR_INVALID_TIME_FORMAT,
      "Time is not in hh:mm:ss format." },
    { PFLError::PFL_ERR_INVALID_DATE_TIME_FORMAT,
      "Date (yyyy-mm-dd) and/or time (hh:mm:ss) are not in valid format.." },
    { PFLError::PFL_ERR_PARSE_INVALID_LINE, "Invalid log line." },
    { PFLError::PFL_ERR_PARSE_INVALID_RULENUM,
      "Rule Number must greater than zero." },
    { PFLError::PFL_ERR_PARSE_INVALID_PROTOCOL, "Invalid Protocol." },
    { PFLError::PFL_ERR_XML_FILE_NOT_SAVE, "File cannnot be save." },
    { PFLError::PFL_ERR_XML_FILE_NAME_INCONSISTENT,
      "File name is inconsistent." },
    { PFLError::PFL_ERR_UNKNOWN, "Unknown Error." }
  };
};

/* -------------------------------------------------------------------------- */

/*!
 * \internal
 * \brief Implements Visitor, a helper function for deducing the type of data
 * stored in the variable std::variant.
 * \note based on: https://en.cppreference.com/w/cpp/utility/variant/visit
 */
template<class... Ts>
struct overloadedP : Ts...
{
  using Ts::operator()...;
};
template<class... Ts>
overloadedP(Ts...) -> overloadedP<Ts...>;
struct PFLogentry_EXPORT Visitor
{
public:
  enum class TypeVar
  {
    TInt = 0x00,
    TLong,
    TUint,
    TString
  };
  using var_t = std::variant<int, long, uint32_t, std::string>;
  TypeVar varType(var_t t_) const;
};

/* -------------------------------------------------------------------------- */

/*!
 * \brief The PFLogentry class is the principal inteface of this library.
 */
class PFLogentry_EXPORT PFLogentry
  : public Visitor
  , public FilterData
{
public:
  explicit PFLogentry(LogFormat fmt_ = LogFormat::LogBSD, const int year_ = 0);
  ~PFLogentry();

  PFLogentry& append(const std::string& raw_log_);
  void clear();
  size_t size() const;
  // PFLError toXML(const std::string fn_);
  PFLError toXML(const std::string&& fn_ = std::string(),
                 const std::string&& d0_ = std::string(),
                 const std::string&& t0_ = std::string(),
                 const std::string&& d1_ = std::string(),
                 const std::string&& t1_ = std::string());

  PFLError errorNum() const noexcept;
  std::string getErrorText() const;

  enum Compare
  {
    EQ = 0x00,
    LT,
    GT,
    LE,
    GE,
    NE,
    BTWAND,
    BTWOR
  };
  static constexpr std::string_view invalidText = "@@@"; // Don't change!

private:
  using var_t = Visitor::var_t;

  /*
   * Don't change the regular expressions below, it will make the whole program
   * crash!
   */
  std::regex re_id_rfc3164_ = {};
  std::regex re_id_rfc5424_ = {};
  static constexpr char cp_id_rfc3164_[] =
    "^(\\S+)\\s+(\\S+) (\\S+) (.*?) (.+)";
  static constexpr char cp_id_rfc5424_[] =
    "^(<[0-9]{1,3}>[0-9])*\\ (\\S+?)\\ (\\S+?)\\ filterlog\\ \\S+?\\ \\S+?\\ "
    "\\S+?\\ (.*)$";

  std::regex re_time_rfc3164_ = {};
  std::regex re_time_rfc5424_ = {};
  static constexpr char cp_time_rfc3164_[] =
    "^([0-9]{2}):([0-9]{2}):([0-9]{2})$";
  static constexpr char cp_time_rfc5424_[] =
    "^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2}).([0-"
    "9]{6})(\\S+)$";

  static constexpr char month_names_[] = "JanFebMarAprMayJunJulAugSepOctNovDec";

  std::vector<std::string> split(const std::string&& s_, const char sep_ = ',');
  inline bool isMonth(const std::string&& s_);
  inline int monthToNumber(const std::string&& s_) const;
  inline bool isValidEntry(const std::string s_);

protected:
  PFLError pflError = PFLError::PFL_SUCCESS;

  std::string raw_ = {};
  std::string err_msg_ = {};
  LogFormat log_fmt_ = {};
  int bsd_year_ = 0;

  std::set<std::string> uniq_ip_src = {};
  std::set<std::string> uniq_ip_dst = {};

  struct Accumulator
  {
    int accHopOpt = 0; // IPv6 Options
    int accTCP4 = 0;
    int accTCP6 = 0;
    int accUDP = 0;
    int accUDP6 = 0;
    int accICMP4 = 0;
    int accICMP6 = 0;
    int accIGMP = 0;
    int accCARP = 0;
  } acc_t;

  Fields fld;

  LogData log_data;
  using filter_pair_ = std::pair<int, LogData>;
  using range_mmap_it = std::multimap<int, LogData>::const_iterator;
  std::multimap<int, LogData> filter_m = {};

  inline LogFormat logFormat();
  [[maybe_unused]] long toLong(const std::string&& s_) const;

  void setError(PFLError e_);

  PFLError parse();

  std::tm mkTime(const std::string d_, const std::string t_) const;

  bool isValidDate(const std::string d_) const;
  bool isValidTime(const std::string t_) const;

  int compareDT(const std::string tm_end_,
                const std::string tm_beginning_) const;
  bool compareDT1(const std::string data_ = std::string(),
                  const std::string tm_end_ = std::string(),
                  const std::string tm_begining_ = std::string(),
                  Compare Comp_ = BTWAND) const;

  template<typename TVarD, typename TMin, typename TMax, typename TCompare>
  bool decision(TVarD&& data_, TMin&& min_, TMax&& max_, TCompare&& cmp_) const;

  template<typename TVarS, typename TVarD, typename TCompare>
  bool decision(TVarS&& lhs_, TVarD&& rhs_, TCompare&& cmp_) const;

  template<typename Ta, typename Tb>
  float percent(Ta lhs_, Tb rhs_) const;

  int intFields(Fields f_, const LogData& d_) const;
  long longFields(Fields f_, const LogData& d_) const;
  uint32_t uint32Fields(Fields f_, const LogData& d_) const;
  std::string strFields(Fields f_, const LogData& d_) const;
};

/* -------------------------------------------------------------------------- */
/*!
 * \brief The PFCounter class
 */
class PFLogentry_EXPORT PFCounter : public PFLogentry
{
public:
public:
  explicit PFCounter();
  explicit PFCounter(PFLogentry* pf_);
  explicit PFCounter(PFLogentry* pf_, Fields fld_);

  PFCounter& count(Fields fld_);

  size_t eq(Visitor::var_t&& t_) const;
  size_t lt(Visitor::var_t&& t_) const;
  size_t gt(Visitor::var_t&& t_) const;
  size_t le(Visitor::var_t&& t_) const;
  size_t ge(Visitor::var_t&& t_) const;
  size_t ne(Visitor::var_t&& t_) const;
  size_t betweenAND(Visitor::var_t&& t_min, Visitor::var_t&& t_max) const;
  size_t betweenOR(Visitor::var_t&& t_min, Visitor::var_t&& t_max) const;

  size_t size() const;

private:
  Fields fld_f;

  using var_t = Visitor::var_t;
  using log_data_v = std::vector<LogData>;

  size_t compute(var_t t_, Compare comp_) const;
  size_t compute(var_t t_min, var_t t_max, Compare comp_) const;
};

/* -------------------------------------------------------------------------- */
/*!
 * \brief The PFQuery class
 */
class PFLogentry_EXPORT PFQuery : public PFLogentry
{
public:
  explicit PFQuery();
  explicit PFQuery(PFLogentry* pf_);

  PFQuery& select(const std::string&& d0_ = std::string(),
                  const std::string&& t0_ = std::string(),
                  const std::string&& d1_ = std::string(),
                  const std::string&& t1_ = std::string());

  void field(Fields fld_, Compare cmp_, Visitor::var_t&& t_);

  int getInt(size_t idx_, Fields fld_) const;
  long getLong(size_t idx_, Fields fld_) const;
  uint32_t getUint(size_t idx_, Fields fld_) const;
  std::string getText(size_t idx_, Fields fld_) const;

  bool exists(Fields fld_, Compare cmp_, Visitor::var_t&& t_);
  size_t size() const;
  void clear();

private:
  Fields fld_f;
  PFLError pflError = PFLError::PFL_SUCCESS;

  using var_t = Visitor::var_t;
  std::vector<LogData> log_data_v_ = {};

  struct Info
  {
    int flag = {};
    struct std::tm tm_begin = {};
    struct std::tm tm_end = {};
  } info_t;
};

/* -------------------------------------------------------------------------- */
/*!
 * \brief The PFSummary class
 */
class PFLogentry_EXPORT PFSummary : public PFLogentry
{
public:
  explicit PFSummary(PFLogentry* pf_);

  PFLError setDateTime(const std::string&& d0_ = std::string(),
                       const std::string&& t0_ = std::string(),
                       const std::string&& d1_ = std::string(),
                       const std::string&& t1_ = std::string());
  void setHostName(const std::string&& hn_ = std::string());
  void setIfName(const std::string&& ifname_ = std::string());
  void setLinesPage(const int lp_ = 50);

  void protocol(ProtoID id_ = ProtoID::ProtoTCP,
                IPVersion ipver_ = IPVersion::IPv4);

  void getGrandTotals();

  void report(ProtoID id_ = ProtoID::ProtoTCP,
              IPVersion ipver_ = IPVersion::IPv4);

  enum class UniqueType
  {
    Overview,
    Details
  };

  void reportUnique(UniqueType uniq_ = UniqueType::Overview,
                    ProtoID id_ = ProtoID::ProtoTCP,
                    IPVersion ipver_ = IPVersion::IPv4);

private:
  using log_data_v_ = std::vector<LogData>;
  log_data_v_ tmp_log_data_v_;

  PFLError pflError = PFLError::PFL_SUCCESS;
  UniqueType uniqType = UniqueType::Overview;

  int lines_per_page_ = 0;
  static constexpr int lines_header = 9;

  struct Info
  {
    bool flag = true;
    struct std::tm tm_begin = {};
    struct std::tm tm_end = {};
    std::string hostname = {};
    std::string ifname = {};
    ProtoID proto_id;
    IPVersion ip_version = {};
  } info_t;

  struct Results
  {
    int accTcp4 = 0;
    int accTcp6 = 0;
    int accUdp4 = 0;
    int accUdp6 = 0;
    long accUdpDataLen = 0;
  } results_t;

  int mat_in_[2][4] = {};
  int mat_out_[2][4] = {};
  void countReasonByAction(const std::string direction_,
                           const std::string reason_,
                           const std::string action_);
  template<typename ForwardIt>
  void compute(ForwardIt iter_, ProtoID id_, IPVersion ipver_);

  template<typename ForwardIt>
  void compute(ForwardIt lower_,
               ForwardIt upper_,
               ProtoID id_,
               IPVersion ipver_);

  inline void heading();
  void printGrandTotals();
  void printTabReasonByAction(ProtoID id_, IPVersion ipver_);

  void reportHeader();
  void reportHdrDetails();
  void reportDetails();

  template<typename ForwardIt>
  int print(ForwardIt it_);

  template<typename TSet, typename TMin, typename TMax>
  void printUnique(TSet set_, TMin min_, TMax max_);
};

/* -------------------------------------------------------------------------- */
/*!
 * \internal
 * \brief Helper object for XML file creation. <b>Internal use only.</b>
 */
class PFLogentry_EXPORT PFRawToXML : public PFLogentry
{
public:
  explicit PFRawToXML();
  explicit PFRawToXML(LogFormat fmt_);

  PFRawToXML& append(LogData& log_data_t);

  PFLError save(const std::string fn_);
  PFLError close();

private:
  XMLDocument doc;
  XMLElement* root;
  XMLElement* root_node;
  XMLDeclaration* decl;

  PFLError pflError = PFLError::PFL_SUCCESS;
  LogFormat log_fmt_;
  LogData log_data_ = {};

  std::string fname_ = {};

  void writePart();
  std::string dateTime() const;
  PFLError normFn(std::string& fn_);
};

}; // namespace pflogentry

#endif // PFLOGENTRY_H
