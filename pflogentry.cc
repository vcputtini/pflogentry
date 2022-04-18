/***************************************************************************
 * Copyright (c) 2021-22                                                   *
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

#include "pflogentry.h"

namespace pflogentry {

/* Visitor ------------------------------------------------------------------ */
/*!
 * \internal
 * \brief After deducing the type of data stored in the var_t structure, it
 * returns a corresponding integer value.
 * \param t std::variant() structure with data stored for type deduction.
 * \return int Variable type.
 */
Visitor::TypeVar
Visitor::varType(var_t t_) const
{
  TypeVar typ = {};
  std::visit(overloadedP{
               [&typ]([[maybe_unused]] int arg) { typ = TypeVar::TInt; },
               [&typ]([[maybe_unused]] long arg) { typ = TypeVar::TLong; },
               [&typ]([[maybe_unused]] uint32_t arg) { typ = TypeVar::TUint; },
               [&typ]([[maybe_unused]] const std::string& arg) {
                 typ = TypeVar::TString;
               } },
             t_);
  return typ;
}

/* PFLogentry --------------------------------------------------------------- */
/*!
 * \brief Constructs a PFLogentry object. (default)
 */
PFLogentry::PFLogentry(LogFormat fmt_, const int year_)
  : re_id_rfc3164_(cp_id_rfc3164_, std::regex::optimize)
  , re_id_rfc5424_(cp_id_rfc5424_, std::regex::optimize)
  , re_time_rfc3164_(cp_time_rfc3164_, std::regex::optimize)
  , re_time_rfc5424_(cp_time_rfc5424_, std::regex::optimize)
  , pflError(PFLError::PFL_SUCCESS)
{
  if (fmt_ == LogFormat::LogBSD) {
    bsd_year_ = std::move(year_);
    log_fmt_ = std::move(fmt_);
  } else {
    bsd_year_ = 0;
    log_fmt_ = std::move(fmt_);
  }
}

PFLogentry::~PFLogentry()
{
  clear();
}

/*!
 * \brief Appends the filter log entries to the system.
 * \param raw__log_
 */
PFLogentry&
PFLogentry::append(const std::string& raw__log_)
{
  raw_.resize(raw__log_.size());
  raw_ = std::move(raw__log_);
  if (parser() == PFLError::PFL_SUCCESS) {
    filter_m.insert({ std::mktime(&log_data.header.tm_time), log_data });
  }
  return *this;
}

/*!
 * \brief Erase all entries read.
 */
void
PFLogentry::clear()
{
  filter_m.clear();
  uniq_ip_src.clear();
  uniq_ip_dst.clear();
  pflError = PFLError::PFL_SUCCESS;
};

/*!
 * \brief returns the number of log entries read.
 * \return size_t  Is an unsigned integral type.
 */
size_t
PFLogentry::size() const
{
  return filter_m.size();
}

/*!
 * \internal
 * \brief Returns true or false if month name is corret
 * \param s Month name abbreviation
 * \return true|false
 * \code{.cc}
 * bool b = isMonth("Jan");
 * \endcode
 */
bool
PFLogentry::isMonth(const std::string&& s_)
{
  auto begin_ = std::cbegin(nmonths_);
  auto end_ = std::cend(nmonths_);

  auto f_ = std::find_if(begin_, end_, [&s_](const char* cptr_) {
    if (std::strcmp(s_.c_str(), cptr_) == 0) {
      return true;
    }
    return false;
  });

  return (f_ != end_);
}

/*!
 * \internal
 * \brief Converts the month name abbreviation to number.
 * \param s
 * \return
 */
int
PFLogentry::monthToNumber(const std::string&& s_) const
{
  auto begin_ = std::cbegin(nmonths_);
  auto end_ = std::cend(nmonths_);

  auto f_ = std::find_if(begin_, end_, [&s_](const char* cptr_) {
    if (std::strcmp(s_.c_str(), cptr_) == 0) {
      return true;
    }
    return false;
  });

  if (f_ != end_) {
    return std::distance(begin_, f_) + 1;
  }
  return 0;
}

/*!
 * \internal
 * \brief Try to ensure that the input is valid.
 * \param s_ Entry line
 * \return bool
 * \note It doesn't check whether the entire line is empty.
 * If the first character is blank then it considers the line invalid. But an
 * entirely blank line should just be ignored and not be considered an error.
 */
bool
PFLogentry::isValidEntry(const std::string s_)
{
  if (s_.find("filterlog") != std::string::npos) {
    if (s_[0] == '<' && s_[4] == '>' && std::isdigit(s_[5])) { // <nnn>n
      return true;
    } else if (!std::isalpha(s_[0]) || std::isblank(s_[0])) {
      return false;
    }
    return true;
  }
  return false;
};

/*!
 * \brief Return a error code.
 * \return
 */
PFLogentry::PFLError
PFLogentry::errorNum() const noexcept
{
  return pflError;
}

/*!
 * \brief Return the description of the error.
 * \return std::string
 */
std::string
PFLogentry::getErrorText() const
{
  if (auto it_ = mError.find(pflError); it_ != mError.cend()) {
    return it_->second.data();
  }
  return mError.at(PFLError::PFL_ERR_UNKNOWN).data();
}

/*!
 * \internal
 * \brief Splits a string according to the entered separator.
 * \param sv The string that should be split
 * \param sep The type of separator
 * \return A string vector
 * \note The logic used to 'split' the CSV string, was based on:
 * https://www.tutorialspoint.com/
 *                            parsing-a-comma-delimited-std-string-in-cplusplus
 */
std::vector<std::string>
PFLogentry::split(const std::string&& s_, const char sep_)
{
  std::vector<std::string> result;
  std::stringstream ss(s_.data());
  while (ss.good()) {
    std::string tok{};
    std::getline(ss, tok, sep_);
    result.push_back(std::move(tok));
  }
  return result;
}

/*!
 * \brief Converts log entries to XML format and writes to file.
 * \param fn File name with path (Mandatory).
 * \param Beginning date
 * \param Beginning time
 * \param End date
 * \param End time
 * \note If the user does not inform the '.xml' extension, the library will
 * provide it. If another extension is informed, it will not be considered valid
 * and the function will return -1.
 * \warning Important: The PFRawToXML object will always erase the data read
 * after writing the XML file.
 */
PFLogentry::PFLError
PFLogentry::toXML(const std::string&& fn_,
                  const std::string&& d0_,
                  const std::string&& t0_,
                  const std::string&& d1_,
                  const std::string&& t1_)
{
  if (fn_.empty()) {
    setError(PFLError::PFL_ERR_XML_FILE_NAME_INCONSISTENT);
    return PFLError::PFL_ERR_XML_FILE_NAME_INCONSISTENT;
  }
  if ((pflError == PFLError::PFL_SUCCESS) && (filter_m.size() != 0)) {

    PFRawToXML xml(log_fmt_);

    if (xml.save(fn_) != PFLError::PFL_SUCCESS) {
      setError(PFLError::PFL_ERR_XML_FILE_NAME_INCONSISTENT);
      return PFLError::PFL_ERR_XML_FILE_NAME_INCONSISTENT;
    }

    if ((!d0_.empty() && !t0_.empty()) && (!d1_.empty() && !t1_.empty())) {
      struct std::tm tm_begin = {};
      struct std::tm tm_end = {};
      tm_begin = mkTime(d0_, t0_);
      tm_end = mkTime(d1_, t1_);
      auto lower_ = filter_m.lower_bound(std::move(std::mktime(&tm_begin)));
      auto upper_ = filter_m.upper_bound(std::move(std::mktime(&tm_end)));
      for (auto& it_ = lower_; it_ != upper_; ++it_) {
        if (!it_->second.hostname.empty()) {
          xml.append(it_->second);
        }
      }
    } else {
      for (auto& a : filter_m) {
        if (!a.second.hostname.empty()) {
          xml.append(a.second);
        };
      }
    }

    if (xml.close() != PFLError::PFL_SUCCESS) {
      setError(PFLError::PFL_ERR_XML_FILE_NOT_SAVE);
      return PFLError::PFL_ERR_XML_FILE_NOT_SAVE;
    }
  }

  return pflError;
}

/*!
 * \internal
 */
PFLogentry::LogFormat
PFLogentry::logFormat()
{
  return log_fmt_;
};

/*!
 * \internal
 * \brief Convert std::string to a long int. It differs from std::stol() in
 * that it allows the first digit to be an alphanumeric. \param s \return long
 * \note long l = toLong("# 10"); // OK
 * \note long l = std::stol("# 10"); // std::invalid_argument
 */
long
PFLogentry::toLong(const std::string&& s_) const
{
  std::string aux = {};
  for (auto& a : s_) {
    if (std::isdigit(static_cast<char>(a))) {
      aux += std::move(a);
    }
  }
  return std::stol(aux);
}

/*!
 * \internal
 * \brief PFLogentry::setError
 * \param e_ Error code
 */
void
PFLogentry::setError(PFLError e_)
{
  pflError = e_;
}

/*!
 * \internal
 *
 * \note The constants below are defined in CMakeLists.txt
 *
 * DEBUG_PARSER
 *
 */

/*!
 * \internal
 * \brief Parses the log line to internal format.
 * \details Performs several checks on the log line to ensure that it is
 * valid. \note (1) The basis of this parse logic is based on the script
 * "/usr/local/bin/filterparse.php" which is used in pfSense(R). Since the
 * logic used is good enough for the job to be done, we don't consider develop
 * a new logic from scratch.
 */
PFLogentry::PFLError
PFLogentry::parser()
{
  if (raw_.empty() ||
      (raw_.find("newsyslog") != std::string::npos)) { // ignore empty lines
    setError(PFLError::PFL_SUCCESS);
    return PFLError::PFL_SUCCESS;
  }

  if (isValidEntry(raw_)) {

#ifdef DEBUG_PARSER
    std::cout << raw_ << "\n\n";
#endif

    try {
      log_data = {};
      std::match_results<std::string::const_iterator> match;
      switch (log_fmt_) {
        case LogFormat::LogBSD:
          std::regex_match(raw_.cbegin(), raw_.cend(), match, re_id_rfc3164_);
          break;
        case LogFormat::LogSyslog:
          std::regex_match(raw_.cbegin(), raw_.cend(), match, re_id_rfc5424_);
      }
#ifdef DEBUG_PARSER
      std::cout << "-0 = " << match[0] << "\n"
                << "-1 = " << match[1] << "\n"
                << "-2 = " << match[2] << "\n"
                << "-3 = " << match[3] << "\n"
                << "-4 = " << match[4] << "\n"
                << "-5 = " << match[5] << "\n"
                << "max = " << match.size() << "\n";
#endif
      if (raw_[0] == '<') { // RFC-5424 line starts with '<'
        log_data.header.id = std::move(match[1]);
        log_data.header.time = std::move(match[2]);
        std::smatch smatches;
        std::regex_match(log_data.header.time, smatches, re_time_rfc5424_);
        log_data.header.tm_time.tm_year =
          std::move(std::stoi(smatches[1]) - 1900);
        log_data.header.tm_time.tm_mon = std::move(std::stoi(smatches[2]) - 1);
        log_data.header.tm_time.tm_mday = std::move(std::stoi(smatches[3]));
        log_data.header.tm_time.tm_hour = std::move(std::stoi(smatches[4]));
        log_data.header.tm_time.tm_min = std::move(std::stoi(smatches[5]));
        log_data.header.tm_time.tm_sec = std::move(std::stoi(smatches[6]));
        log_data.header.day = std::move(std::stoi(smatches[3]));
        log_data.header.month = std::move(std::stoi(smatches[2])); // real
        log_data.hostname = std::move(match[3]);
      } else { // RFC-3164
        if (isMonth(match[1])) {
          log_data.header.month = std::move(monthToNumber(match[1]));
        } else {
          setError(PFLError::PFL_ERR_PARSE_INVALID_LINE);
          return PFLError::PFL_ERR_PARSE_INVALID_LINE;
        }
        log_data.header.day = std::move(std::stoi(match[2]));
        log_data.header.tm_time.tm_mday = std::move(log_data.header.day);
        log_data.header.tm_time.tm_mon = std::move(monthToNumber(match[1]) - 1);
        log_data.header.tm_time.tm_year = bsd_year_ - 1900;
        log_data.header.time = std::move(match[3]);
        std::smatch smatches;
        std::regex_match(log_data.header.time, smatches, re_time_rfc3164_);
        log_data.header.tm_time.tm_hour = std::move(std::stoi(smatches[1]));
        log_data.header.tm_time.tm_min = std::move(std::stoi(smatches[2]));
        log_data.header.tm_time.tm_sec = std::move(std::stoi(smatches[3]));
        log_data.hostname = std::move(match[4]);
      }

#ifdef DEBUG_PARSER
      std::cout << "---> " << log_data.header.id << "\n";
      std::cout << "---> " << log_data.header.month << "\n";
      std::cout << "---> " << log_data.header.day << "\n";
      std::cout << "---> " << log_data.header.time << "\n";
      std::cout << "struct tm -->\n";
      std::cout << "        year " << log_data.header.tm_time.tm_year << "\n";
      std::cout << "        mon  " << log_data.header.tm_time.tm_mon << "\n";
      std::cout << "        day  " << log_data.header.tm_time.tm_mday << "\n";
      std::cout << "        hour " << log_data.header.tm_time.tm_hour << "\n";
      std::cout << "        min  " << log_data.header.tm_time.tm_min << "\n";
      std::cout << "        sec  " << log_data.header.tm_time.tm_sec << "\n";
      std::cout << "---> " << log_data.hostname << "\n";
#endif

      std::string tmp = std::move(match[match.size() - 1]);
      size_t pos = 0;
      if (log_fmt_ == LogFormat::LogBSD) {
        pos = std::string_view{ tmp }.find_first_of(": ");
      }
#ifdef DEBUG_PARSER
      std::cout << "\nPOS " << pos << "\n";
#endif
      if (pos != std::string::npos) {
        if (pos == 0) {
          tmp = std::string_view{ tmp }.substr(pos, tmp.length());
        } else {
          tmp = std::string_view{ tmp }.substr(pos + 1, tmp.length());
        }

#ifdef DEBUG_PARSER
        std::cout << "tmp = " << tmp << "\n";
#endif
        std::vector<std::string> v;
        v = split(tmp.c_str(), ',');

#ifdef DEBUG_PARSER
        for (size_t i = 0; i < v.size(); i++) {
          std::cout << ">> " << i << ": " << v.at(i) << std::endl;
        }
#endif

        int inc = 0;
        if (v[0] == " ") {
          setError(PFLError::PFL_ERR_PARSE_INVALID_RULENUM);
          return PFLError::PFL_ERR_PARSE_INVALID_LINE;
        }

        log_data.rule_number = std::stol(std::move(v[inc]));
        ++inc;
        log_data.sub_rule_number =
          (v[inc].length() == 0) ? 0 : std::stol(std::move(v[inc]));
        log_data.anchor = std::move(v[++inc]);
        ++inc;
        log_data.tracker =
          (v[inc].length() == 0) ? 0 : std::stol(std::move(v[inc]));
        log_data.real_iface = std::move(v[++inc]);
        log_data.reason = std::move(v[++inc]);
        log_data.action = std::move(v[++inc]);
        log_data.direction = std::move(v[++inc]);
        ++inc;
        if (v[inc] == "4" || v[inc] == "6") {
          log_data.ip_version = std::stoi(std::move(v[inc]));
          if (log_data.ip_version == 4) {
            log_data.ipv4_data.tos = std::move(v[++inc]);
            log_data.ipv4_data.ecn = std::move(v[++inc]);
            log_data.ipv4_data.ttl = std::move(std::stoi(v[++inc]));
            log_data.ipv4_data.packet_id = std::move(std::stoi(v[++inc]));
            log_data.ipv4_data.offset = std::move(std::stoi(v[++inc]));
            log_data.ipv4_data.flags = std::move(v[++inc]);
            log_data.proto_id = std::move(std::stoi(v[++inc]));
            log_data.proto_text = std::move(v[++inc]);
          } else {
            log_data.ipv6_data.class_data = std::move(v[++inc]);
            log_data.ipv6_data.flow_label = std::move(v[++inc]);
            log_data.ipv6_data.hop_limit = std::move(std::stoi(v[++inc]));
            log_data.proto_text = std::move(v[++inc]);
            log_data.proto_id = std::move(std::stoi(v[++inc]));
          }

          log_data.length_data = std::move(std::stoi(v[++inc]));
          log_data.ip_src_addr = std::move(v[++inc]);
          log_data.ip_dst_addr = std::move(v[++inc]);

          uniq_ip_src.insert(log_data.ip_src_addr);
          uniq_ip_dst.insert(log_data.ip_dst_addr);

          if (log_data.proto_id == ProtoID::ProtoTCP ||
              log_data.proto_id == ProtoID::ProtoUDP) {
            log_data.src_port = std::move(std::stoi(v[++inc]));
            log_data.dst_port = std::move(std::stoi(v[++inc]));
            log_data.data_len = std::move(std::stol(v[++inc]));
            if (log_data.proto_id == ProtoID::ProtoTCP) {
              log_data.tcp.flags = std::move(v[++inc]);
              ++inc; // seq
              if (v[inc].find(":") != std::string::npos) {
                log_data.tcp.seq_s = std::move(v[inc]);
              } else {
                log_data.tcp.seq =
                  (v[inc].length() == 0 ? 0 : std::stol(v[inc]));
              }
              ++inc; // ack
              log_data.tcp.ack =
                (v[inc].length() == 0 ? 0 : std::move(std::stol(v[inc])));
              ++inc; // win
              log_data.tcp.window =
                (v[inc].length() == 0 ? 0 : std::move(std::stol(v[inc])));
              ++inc; // urg
              log_data.tcp.urg =
                (v[inc].length() == 0 ? 0 : std::move(std::stol(v[inc])));
              log_data.tcp.options = v[++inc];
            }
          } else if ((log_data.proto_id == ProtoID::ICMPv4 ||
                      log_data.proto_id == ProtoID::ICMPv6)) {
            log_data.icmp.src_addr = log_data.ip_src_addr;
            log_data.icmp.dst_addr = log_data.ip_dst_addr;
            log_data.icmp.type = std::move(v[++inc]);

            if (std::map<const std::string_view, ICMPType>::const_iterator it =
                  icmp_m.find(log_data.icmp.type);
                it == icmp_m.end()) { // found
              switch (it->second) {
                case ICMPType::Request:
                  [[fallthrough]];
                case ICMPType::Reply:
                  log_data.icmp.id = std::move(std::stoi(v[++inc]));
                  log_data.icmp.seq = std::move(std::stoi(v[++inc]));
                  break;
                case ICMPType::UnReachProto:
                  log_data.icmp.dst_addr = std::move(v[++inc]);
                  log_data.icmp.proto_id = std::move(std::stoi(v[++inc]));
                  break;
                case ICMPType::UnReachPort:
                  log_data.icmp.dst_addr = std::move(v[++inc]);
                  log_data.icmp.proto_id = std::move(std::stoi(v[++inc]));
                  log_data.icmp.port = std::move(std::stoi(v[++inc]));
                  break;
                case ICMPType::UnReach:
                  [[fallthrough]];
                case ICMPType::TimeExceed:
                  [[fallthrough]];
                case ICMPType::ParamProb:
                  [[fallthrough]];
                case ICMPType::Redirect:
                  [[fallthrough]];
                case ICMPType::MaskReply:
                  log_data.icmp.descr = std::move(v[++inc]);
                  break;
                case ICMPType::NeedFrag:
                  log_data.icmp.dst_addr = std::move(v[++inc]);
                  log_data.icmp.mtu = std::move(std::stoi(v[++inc]));
                  break;
                case ICMPType::TStamp:
                  log_data.icmp.id = std::move(std::stoi(v[++inc]));
                  log_data.icmp.seq = std::move(std::stoi(v[++inc]));
                case ICMPType::TStampReply:
                  log_data.icmp.id = std::move(std::stoi(v[++inc]));
                  log_data.icmp.seq = std::move(std::stoi(v[++inc]));
                  log_data.icmp.otime = std::move(std::stoul(v[++inc]));
                  log_data.icmp.rtime = std::move(std::stoul(v[++inc]));
                  log_data.icmp.ttime = std::move(std::stoul(v[++inc]));
                default:
                  log_data.icmp.descr = std::move(v[++inc]);
              } // switch

            } else if (log_data.proto_id == ProtoID::ProtoIGMP) {
              log_data.igmp.src = log_data.ip_src_addr;
              log_data.igmp.dst = log_data.ip_dst_addr;
            } else if (log_data.proto_id == ProtoID::ProtoCARP) {
              log_data.carp.type = std::move(v[++inc]);
              log_data.carp.ttl = std::move(std::stoi(v[++inc]));
              log_data.carp.vhid = std::move(std::stoi(v[++inc]));
              log_data.carp.version = std::move(std::stoi(v[++inc]));
              log_data.carp.advbase = std::move(std::stoi(v[++inc]));
              log_data.carp.advskew = std::move(std::stoi(v[++inc]));
            }
          }

          (log_data.proto_id == ProtoID::ProtoTCP && log_data.ip_version == 4)
            ? acc_t.accTCP4++
            : 0;
          (log_data.proto_id == ProtoID::ProtoTCP && log_data.ip_version == 6)
            ? acc_t.accTCP6++
            : 0;
          (log_data.proto_id == ProtoID::ProtoHOPOPT &&
           log_data.ip_version == 6)
            ? acc_t.accHopOpt++
            : 0;
          (log_data.proto_id == ProtoID::ProtoUDP) ? acc_t.accUDP++ : 0;
          (log_data.proto_id == ProtoID::ProtoIGMP) ? acc_t.accIGMP++ : 0;
          (log_data.proto_id == ProtoID::ProtoCARP) ? acc_t.accCARP++ : 0;
          (log_data.proto_id == ProtoID::ICMPv4) ? acc_t.accICMP4++ : 0;
          (log_data.proto_id == ProtoID::ICMPv6) ? acc_t.accICMP6++ : 0;

        } else {
          setError(PFLError::PFL_ERR_PARSE_INVALID_PROTOCOL);
          return PFLError::PFL_ERR_PARSE_INVALID_LINE;
        }
#ifdef DEBUG_PARSER
        std::cout << "tos " << log_data.ipv4_data.tos << "\n"
                  << "ecn " << log_data.ipv4_data.ecn << "\n"
                  << "ttl " << log_data.ipv4_data.ttl << "\n"
                  << "packet_id " << log_data.ipv4_data.packet_id << "\n"
                  << "offset " << log_data.ipv4_data.offset << "\n"
                  << "flags " << log_data.ipv4_data.flags << "\n"
                  << "\n-------\nIPV6\n"
                  << "v6 class_data " << log_data.ipv6_data.class_data << "\n"
                  << "v6 flow_label " << log_data.ipv6_data.flow_label << "\n"
                  << "v6 hop_limit " << log_data.ipv6_data.hop_limit
                  << "\n\nProtos\n"
                  << "proto_text" << log_data.proto_text << "\n"
                  << "proto_id " << log_data.proto_id << "\n------\n\n"
                  << "length_data " << log_data.length_data << "\n"
                  << "src " << log_data.ip_src_addr << "\n"
                  << "dst " << log_data.ip_dst_addr << "\n"
                  << "srcp " << log_data.src_port << "\n"
                  << "dstp " << log_data.dst_port << "\n"
                  << "len " << log_data.data_len << "\n----------\nICMP\n"
                  << "id " << log_data.icmp.id << "\n"
                  << "seq " << log_data.icmp.seq << "\n"
                  << "type " << log_data.icmp.type << "\n"
                  << "echo_type " << log_data.icmp.echo_type << "\n"
                  << "proto_id " << log_data.icmp.proto_id << "\n"
                  << "port " << log_data.icmp.port << "\n"
                  << "descr " << log_data.icmp.descr << "\n"
                  << "mtu " << log_data.icmp.mtu << "\n"
                  << "otime " << log_data.icmp.otime << "\n"
                  << "rtime " << log_data.icmp.rtime << "\n"
                  << "ttime " << log_data.icmp.ttime << "\n"
                  << "src_addr " << log_data.icmp.src_addr << "\n"
                  << "dst_addr " << log_data.icmp.dst_addr
                  << "\n----------\nIGMP\n"
                  << "src_addr " << log_data.igmp.src << "\n"
                  << "dst_addr " << log_data.igmp.dst << "\n----------\nCARP\n"
                  << "type " << log_data.carp.type << "\n"
                  << "ttl " << log_data.carp.ttl << "\n"
                  << "vhid " << log_data.carp.vhid << "\n"
                  << "version " << log_data.carp.version << "\n"
                  << "advbase " << log_data.carp.advbase << "\n"
                  << "advskew " << log_data.carp.advskew << "\n";
#endif
      } // npos

    } catch (std::regex_error& e_) {
      std::cout << "Parser PFLogentry regex error = " << e_.what() << "\n";
      setError(PFLError::PFL_ERR_PARSER_FAILED);
      return PFLError::PFL_ERR_PARSER_FAILED;
    } catch (const std::exception& e) {
      std::cout << "[" << __LINE__ << "] "
                << __FILE__ ": An exception occurred: " << e.what() << "\n";
    };
  } else {
    setError(PFLError::PFL_ERR_PARSE_INVALID_LINE);
    return PFLError::PFL_ERR_PARSE_INVALID_LINE;
  } // isValidEntry
  return PFLError::PFL_SUCCESS;
}

/*!
 * \internal
 * \brief Checks if the date is in ISO format.
 * \param d_ Valid format ISO yyyy-mm-dd
 * \return bool true|false
 */
bool
PFLogentry::isValidDate(const std::string d_) const
{
  if (!d_.empty()) {
    std::regex re_date_("^([0-9]{4})-([0-9]{2})-([0-9]{2})$");
    std::smatch smatches_;
    if (std::regex_match(d_, smatches_, re_date_)) {
      auto [y_, m_, d_] = std::tuple(std::stoi(smatches_[1]),
                                     std::stoi(smatches_[2]),
                                     std::stoi(smatches_[3]));
      if ((y_ > 1900 && y_ <= 2038) && (m_ >= 1 && m_ <= 12) &&
          (d_ >= 1 && d_ <= 31)) {
        return true;
      }
    }
  }
  return false;
}

/*!
 * \internal
 * \brief Checks if the time is in hh:mm:ss format.
 * \param t_
 * \return bool true|false
 */
bool
PFLogentry::isValidTime(const std::string t_) const
{
  if (!t_.empty()) {
    std::regex re_time_("^([0-9]{2}):([0-9]{2}):([0-9]{2})$");
    std::smatch smatches_;
    if (std::regex_match(t_, smatches_, re_time_)) {
      auto [h_, m_, s_] = std::tuple(std::stoi(smatches_[1]),
                                     std::stoi(smatches_[2]),
                                     std::stoi(smatches_[3]));
      if ((h_ >= 0 && h_ <= 23) && (m_ >= 0 && m_ <= 59) &&
          (s_ >= 0 && s_ <= 59)) {
        return true;
      }
    }
  }
  return false;
}

/*!
 * \internal
 * \brief Parses date and time strings and save the values inside std::tm.
 * \param d_ Date (yyyy-mm-dd)
 * \param t_ Time (hh:mm:ss)
 * \return std::tm
 */
std::tm
PFLogentry::mkTime(const std::string d_, const std::string t_) const
{
  struct std::tm tm_tmp = {};
  if (isValidDate(d_) && isValidTime(t_)) {
    tm_tmp.tm_year = std::move(std::stoi(d_.substr(0, 4))) - 1900;
    tm_tmp.tm_mon = std::move(std::stoi(d_.substr(5, 2))) - 1;
    tm_tmp.tm_mday = std::move(std::stoi(d_.substr(8, 2)));
    tm_tmp.tm_hour = std::move(std::stoi(t_.substr(0, 2)));
    tm_tmp.tm_min = std::move(std::stoi(t_.substr(3, 2)));
    tm_tmp.tm_sec = std::move(std::stoi(t_.substr(6, 2)));
  }
  return tm_tmp;
}

/*!
 * \internal
 * \brief Computes difference between two date/time.
 * \param tm_end Date/time read from log entry.
 * \param tm_beginning Date/time informed by the user for comparison.
 * \return integer (-1 | 0 | 1)
 * \code{.cc}
 * // rfc-3164
 * int i = compareDT("10:00:00", "10:01:00");
 * //or
 * // rfc-5424
 * int ii = compareDT("2021-08-31T08:13:00.576185-03:00",
 *                    "2021-09-01T09:13:00.772202-03:00");
 * \endcode
 */
int
PFLogentry::compareDT(const std::string tm_end_,
                      const std::string tm_beginning_) const
{
  std::time_t tm_lhs = {};
  std::time_t tm_rhs = {};
  struct tm tm1 = {};
  struct tm tm2 = {};

  if (log_fmt_ == LogFormat::LogBSD) {
    ::strptime(tm_end_.c_str(), "%H:%M:%S", &tm1);
    ::strptime(tm_beginning_.c_str(), "%H:%M:%S", &tm2);
  } else {
    ::strptime(tm_end_.c_str(), "%Y-%m-%dT%H:%M:%S", &tm1);
    ::strptime(tm_beginning_.c_str(), "%Y-%m-%dT%H:%M:%S", &tm2);
  }
  tm_lhs = std::mktime(&tm1);
  tm_rhs = std::mktime(&tm2);

  float diff = std::difftime(tm_lhs, tm_rhs);
  if (diff == 0) { // end == begining
    return 0;
  } else if (diff < 0) { // end < begining
    return -1;
  }
  return 1; // end > begining
}

/*!
 * \internal
 * \brief Compute the logic: BETWEEN val_min AND|OR val_max. Where val_min is
 * the beginning date/time and val_max is the end date/time.
 * \param data The data value stored in the log entry.
 * \param tm_min Beginning date.
 * \param tm_max End date
 * \param Comp Compare::BTWAND or Compare::BTWOR
 * \return true|false
 */
bool
PFLogentry::compareDT1(const std::string data_,
                       const std::string tm_min_,
                       const std::string tm_max_,
                       Compare Comp_) const
{
  std::time_t tm_data = {};
  std::time_t tm_b = {};
  std::time_t tm_e = {};
  struct tm tm1 = {};
  struct tm tm2 = {};
  struct tm tm3 = {};

  switch (log_fmt_) {
    case LogFormat::LogBSD: {
      ::strptime(data_.c_str(), "%H:%M:%S", &tm1);
      ::strptime(tm_min_.c_str(), "%H:%M:%S", &tm2);
      ::strptime(tm_max_.c_str(), "%H:%M:%S", &tm3);
      break;
    }
    default: {
      ::strptime(data_.c_str(), "%Y-%m-%dT%H:%M:%S", &tm1);
      ::strptime(tm_min_.c_str(), "%Y-%m-%dT%H:%M:%S", &tm2);
      ::strptime(tm_max_.c_str(), "%Y-%m-%dT%H:%M:%S", &tm3);
    }
  }

  tm_data = std::mktime(&tm1);
  tm_b = std::mktime(&tm2);
  tm_e = std::mktime(&tm3);

  return decision(tm_data, tm_b, tm_e, Comp_);
}

/*!
 * \internal
 * \brief This template function implements the logical AND and OR operations
 * for functions like "between A AND B" or "between A OR B".
 *
 * \param data_ The data to be compared with its limits.
 * \param min_ Lower value.
 * \param max_ Highest value.
 * \param cmp_ Type of logical operation: BTWAND | BTWOR
 *
 */
template<typename TVarD, typename TMin, typename TMax, typename TCompare>
bool
PFLogentry::decision(TVarD&& data_,
                     TMin&& min_,
                     TMax&& max_,
                     TCompare&& cmp_) const
{
  switch (cmp_) {
    case Compare::BTWAND: {
      return ((data_ >= min_) && (data_ <= max_));
    }
    case Compare::BTWOR: {
      return ((data_ >= min_) || (data_ <= max_));
    }
    default: {
      return false;
    }
  }
};

/*!
 * \internal
 * \brief Overloaded: This template function implements the logical
 * operations:
 * == < > <= >= !=
 * \param lhs_ Argument 1
 * \param rhs_ Argument 2
 * \param cmp_ Type of logical operation. EQ, LT, GT, LE, GE, NE
 */
template<typename TVarS, typename TVarD, typename TCompare>
bool
PFLogentry::decision(TVarS&& lhs_, TVarD&& rhs_, TCompare&& cmp_) const
{
  switch (cmp_) {
    case Compare::EQ: {
      return lhs_ == rhs_;
    }
    case Compare::LT: {
      return lhs_ < rhs_;
    }
    case Compare::GT: {
      return lhs_ > rhs_;
    }
    case Compare::LE: {
      return lhs_ <= rhs_;
    }
    case Compare::GE: {
      return lhs_ >= rhs_;
    }
    case Compare::NE: {
      return lhs_ != rhs_;
    }
    default: {
      return false;
    }
  }
};

/*!
 *  \internal
 */
template<typename Ta, typename Tb>
float
PFLogentry::percent(Ta lhs_, Tb rhs_) const
{
  return (static_cast<float>(lhs_) / static_cast<float>(rhs_)) * 100;
}

/*!
 * \internal
 * \brief Returns the value of integer fields
 * \param f_ Field Id
 * \param d_ Data
 * \return int
 */
constexpr int
PFLogentry::intFields(Fields f_, const LogData& d_) const
{
  switch (f_) {
    case Fields::HdrMonth:
      return d_.header.month;
    case Fields::HdrDay:
      return d_.header.day;
    case Fields::IpVersion:
      return d_.ip_version;
    case Fields::Ipv4DataTTL:
      return d_.ipv4_data.ttl;
    case Fields::Ipv4DataPKTID:
      return d_.ipv4_data.packet_id;
    case Fields::Ipv4DataOFFSET:
      return d_.ipv4_data.offset;
    case Fields::Ipv6DataHOPLIM:
      return d_.ipv6_data.hop_limit;
    case Fields::ProtoId:
      return d_.proto_id;
    case Fields::Length:
      return d_.length_data;
    case Fields::SrcPort:
      return d_.src_port;
    case Fields::DstPort:
      return d_.dst_port;
    case Fields::IcmpProtoId:
      return d_.icmp.id;
    case Fields::IcmpPort:
      return d_.icmp.port;
    case Fields::IcmpMTU:
      return d_.icmp.mtu;
    case Fields::CarpTTL:
      return d_.carp.ttl;
    case Fields::CarpVHID:
      return d_.carp.vhid;
    case Fields::CarpVersion:
      return d_.carp.version;
    case Fields::CarpAdvBase:
      return d_.carp.advbase;
    case Fields::CarpAdvSkew:
      return d_.carp.advskew;
    default:
      return 0;
  }
}

/*!
 * \internal
 * \brief Returns the value of long integer fields
 * \param f_ Field Id
 * \param d_ Data
 * \return long
 */
constexpr long
PFLogentry::longFields(Fields f_, const LogData& d_) const
{
  switch (f_) {
    case Fields::RuleNumber:
      return d_.rule_number;
    case Fields::SubRuleNumber:
      return d_.sub_rule_number;
    case Fields::Tracker:
      return d_.tracker;
    case Fields::IcmpSEQ:
      return d_.icmp.seq;
    case Fields::TcpSEQ:
      return d_.tcp.seq;
    case Fields::TcpACK:
      return d_.tcp.ack;
    case Fields::TcpWIN:
      return d_.tcp.window;
    case Fields::TcpURG:
      return d_.tcp.urg;
    case Fields::DataLen:
      return d_.data_len;
    default:
      return 0;
  }
}

/*!
 * \internal
 * \brief Returns the value of uint32_t fields
 * \param f_ Field Id
 * \param d_ Data
 * \return uint32_t
 */
constexpr uint32_t
PFLogentry::uint32Fields(Fields f_, const LogData& d_) const
{
  switch (f_) {
    case Fields::IcmpOTime:
      return d_.icmp.otime;
    case Fields::IcmpRTime:
      return d_.icmp.rtime;
    case Fields::IcmpTTime:
      return d_.icmp.ttime;
    default:
      return 0;
  }
}

/*!
 * \internal
 * \brief Returns the value of string fields
 * \param f_ Field Id
 * \param d_ Data
 * \return std::string
 */
std::string
PFLogentry::strFields(Fields f_, const LogData& d_) const
{
  switch (f_) {
    case Fields::HdrTimeStamp:
      return std::string();
    case Fields::HostName:
      return d_.hostname;
    case Fields::Anchor:
      return d_.anchor;
    case Fields::RealIFace:
      return d_.real_iface;
    case Fields::Reason:
      return d_.reason;
    case Fields::Action:
      return d_.action;
    case Fields::Direction:
      return d_.direction;
    case Fields::Ipv4DataTOS:
      return d_.ipv4_data.tos;
    case Fields::Ipv4DataECN:
      return d_.ipv4_data.ecn;
    case Fields::Ipv4DataFLAGS:
      return d_.ipv4_data.flags;
    case Fields::Ipv6DataCLASS:
      return d_.ipv6_data.class_data;
    case Fields::Ipv6DataFLOWLABEL:
      return d_.ipv6_data.flow_label;
    case Fields::ProtoText:
      return d_.proto_text;
    case Fields::IpSrcAddr:
      return d_.ip_src_addr;
    case Fields::IpDstAddr:
      return d_.ip_dst_addr;
    case Fields::TcpFLAGS:
      return d_.tcp.flags;
    case Fields::TcpOPTS:
      return d_.tcp.options;
    case Fields::IcmpType:
      return d_.icmp.type;
    case Fields::IcmpEchoType:
      return d_.icmp.echo_type;
    case Fields::IcmpSrcAddr:
      return d_.icmp.src_addr;
    case Fields::IcmpDstAddr:
      return d_.icmp.dst_addr;
    case Fields::IcmpDescr:
      return d_.icmp.descr;
    case Fields::IgmpSrc:
      return d_.igmp.src;
    case Fields::IgmpDst:
      return d_.igmp.dst;
    case Fields::CarpType:
      return d_.carp.type;
    default:
      return std::string();
  }
}

/* PFCounter ---------------------------------------------------------------
 */

/*!
 * \brief Constructs a PFCounter object (default).
 */
PFCounter::PFCounter() {}

/*!
 * \brief Constructs a PFCounter object.
 * \param pf_ Object pointer.
 */
PFCounter::PFCounter(PFLogentry* pf_)
  : PFLogentry(*pf_)
{}

/*!
 * \brief Constructs a PFCounter object.
 * \param pf_ Object pointer.
 * \param fld_ Field ID.
 */
PFCounter::PFCounter(PFLogentry* pf_, Fields fld_)
  : PFLogentry(*pf_)
  , fld_f(fld_)
{}

/*!
 * \brief Defines which field the counter will apply to.
 * \param fld_ Field ID.
 */
PFCounter&
PFCounter::count(Fields fld_)
{
  fld = fld_;
  return *this;
};

/*!
 * \brief Equals to ...
 * \param t_
 * \return size_t Total count of elements found that meet the criteria.
 */
size_t
PFCounter::eq(var_t&& t_) const
{
  return compute(t_, Compare::EQ);
}

/*!
 * \brief Less than to ...
 * \param t_
 * \return size_t Total count of elements found that meet the criteria.
 */
size_t
PFCounter::lt(var_t&& t_) const
{
  return compute(t_, Compare::LT);
}

/*!
 * \brief Greater than to ...
 * \param t_
 * \return size_t Total count of elements found that meet the criteria.
 */
size_t
PFCounter::gt(var_t&& t_) const
{
  return compute(t_, Compare::GT);
}

/*!
 * \brief Less than or equal to ...
 * \param t_
 * \return size_t Total count of elements found that meet the criteria.
 */
size_t
PFCounter::le(var_t&& t_) const
{
  return compute(t_, Compare::LE);
}

/*!
 * \brief Greater than or equal to ...
 * \param t_
 * \return size_t Total count of elements found that meet the criteria.
 */
size_t
PFCounter::ge(var_t&& t_) const
{
  return compute(t_, Compare::GE);
}

/*!
 * \brief Not equal to ...
 * \param t_
 * \return size_t Total count of elements found that meet the criteria.
 */
size_t
PFCounter::ne(var_t&& t_) const
{
  return compute(t_, Compare::NE);
}

/*!
 * \brief The \b betweenAND operator selects values in a given range. It can
 * be numbers, text or dates \param t_min Minor value. \param t_max Maximum
 * value. \return size_t Total count of elements found that meet the criteria.
 *
 * \note value = 100:  100 >= min AND 100 <= max
 *
 */
size_t
PFCounter::betweenAND(var_t&& t_min, var_t&& t_max) const
{
  return compute(t_min, t_max, Compare::BTWAND);
}

/*!
 * \brief The \b betweenOR operator selects values in a given range. It can be
 * numbers, text or dates
 * \param t_min Minor value.
 * \param t_max Maximum value.
 * \return size_t Total count of elements found that meet the criteria.
 *
 * \note value = 100:  100 >= min OR 100 <= max
 *
 */
size_t
PFCounter::betweenOR(var_t&& t_min, var_t&& t_max) const
{
  return compute(t_min, t_max, Compare::BTWOR);
}

/*!
 * \brief Returns the number of log entries read.
 * \return size_t  Is an unsigned integral type.
 */
size_t
PFCounter::size() const
{
  return filter_m.size();
}

/*!
 * \internal
 * \brief Calculates the count of entries, based on the type of data and the
 * logical operator entered. Is used in the logical operations: eq(), lt(),
 * gt() le() and ge().
 * \param t_ Data value.
 * \param comp_ Operator.
 * \return size_t Count of log entries.
 */
size_t
PFCounter::compute(var_t t_, Compare comp_) const
{
  Visitor::TypeVar typevar = varType(t_);

  auto ibegin_m = filter_m.cbegin();
  auto iend_m = filter_m.cend();

  switch (typevar) {
    case TypeVar::TInt: {
      return std::count_if(
        ibegin_m, iend_m, [&t_, &comp_, *this](const filter_pair_& d_) {
          return this->decision(
            intFields(fld, d_.second), std::get<int>(t_), comp_);
        });
    }
    case TypeVar::TLong: {
      return std::count_if(
        ibegin_m, iend_m, [&t_, &comp_, *this](const filter_pair_& d_) {
          return this->decision(
            longFields(fld, d_.second), std::get<long>(t_), comp_);
        });
    }
    case TypeVar::TUint: {
      return std::count_if(
        ibegin_m, iend_m, [&t_, &comp_, *this](const filter_pair_& d_) {
          return this->decision(
            uint32Fields(fld, d_.second), std::get<uint32_t>(t_), comp_);
        });
    }
    case TypeVar::TString: {
      if (fld == Fields::HdrTimeStamp) {
        return std::count_if(
          ibegin_m, iend_m, [&t_, &comp_, this](const filter_pair_& d_) {
            switch (comp_) {
              case EQ:
                return this->compareDT(d_.second.header.time,
                                       std::get<std::string>(t_)) == 0;
              case LT:
                return this->compareDT(d_.second.header.time,
                                       std::get<std::string>(t_)) == -1;
              case GT:
                return this->compareDT(d_.second.header.time,
                                       std::get<std::string>(t_)) == 1;
            }
            return false;
          });
      } else {
        return std::count_if(
          ibegin_m, iend_m, [&t_, &comp_, this](const filter_pair_& d_) {
            return this->decision(
              strFields(fld, d_.second), std::get<std::string>(t_), comp_);
          });
      }
    }
    default: {
      return 0;
    }
  }
}

/*!
 * \internal
 * \brief Calculates the count of entries, based on the type of data and the
 * logical operator entered. Is used in the logical operations: betweenAND()
 * and betweenOR().
 * \param t_min Lowest value.
 * \param t_max Highest value.
 * \param comp_ Can be: BTWAND or BTWOR.
 * \return size_t Count of log entries.
 */
size_t
PFCounter::compute(var_t t_min, var_t t_max, Compare comp_) const
{

  Visitor::TypeVar tmin = varType(t_min);
  [[maybe_unused]] Visitor::TypeVar tmax = varType(t_max);

  auto ibegin_m = filter_m.cbegin();
  auto iend_m = filter_m.cend();

  switch (tmin) {
    case TypeVar::TInt: {
      return std::count_if(
        ibegin_m,
        iend_m,
        [&t_min, &t_max, &comp_, this](const filter_pair_& d_) {
          return this->decision(intFields(fld, d_.second),
                                std::get<int>(t_min),
                                std::get<int>(t_max),
                                comp_);
        });
    }
    case TypeVar::TLong: {
      return std::count_if(
        ibegin_m,
        iend_m,
        [&t_min, &t_max, &comp_, this](const filter_pair_& d_) {
          return this->decision(longFields(fld, d_.second),
                                std::get<long>(t_min),
                                std::get<long>(t_max),
                                comp_);
        });
    }
    case TypeVar::TUint: {
      return std::count_if(
        ibegin_m,
        iend_m,
        [&t_min, &t_max, &comp_, this](const filter_pair_& d_) {
          return this->decision(uint32Fields(fld, d_.second),
                                std::get<uint32_t>(t_min),
                                std::get<uint32_t>(t_max),
                                comp_);
        });
    }
    case TypeVar::TString: {
      if (fld == Fields::HdrTimeStamp) {
        return std::count_if(
          ibegin_m,
          iend_m,
          [&t_min, &t_max, &comp_, this](const filter_pair_& d_) {
            return this->compareDT1(d_.second.header.time,
                                    std::get<std::string>(t_min),
                                    std::get<std::string>(t_max),
                                    comp_);
          });
      }
      default: {
        return 0;
      }
    }
  }
}

/* PFQuery
 * -----------------------------------------------------------------
 */
/*!
 * \brief Constructs a PFQuery object (default).
 */
PFQuery::PFQuery()
  : pflError(PFLError::PFL_SUCCESS)
  , log_data_v_({})
{}

/*!
 * \brief Constructs a PFQuary object.
 * \param pf_ Object pointer
 */
PFQuery::PFQuery(PFLogentry* pf_)
  : PFLogentry(*pf_)
  , pflError(PFLError::PFL_SUCCESS)
  , log_data_v_({})
{}

/*!
 * \brief Sets the desired date/time range for selection operations
 * \param d0_ Begin date.
 * \param t0_ Begin time.
 * \param d1_ End date.
 * \param t1_ End time.
 */
PFQuery&
PFQuery::select(const std::string&& d0_,
                const std::string&& t0_,
                const std::string&& d1_,
                const std::string&& t1_)
{

  if ((!d0_.empty() && !t0_.empty()) && (d1_.empty() && t1_.empty())) { // a,b
    if (isValidDate(d0_) && isValidTime(t0_)) {
      info_t.tm_begin = mkTime(d0_, t0_);
      info_t.tm_end = {};
      info_t.flag = true;
    } else {
      setError(PFLError::PFL_ERR_INVALID_DATE_TIME_FORMAT);
    }
  } else if ((!d0_.empty() && !t0_.empty()) &&
             (!d1_.empty() && !t1_.empty())) { // a,b, a1, b1
    if (isValidDate(d0_) && isValidTime(t0_) && isValidDate(d1_) &&
        isValidTime(t1_)) {

      info_t.tm_begin = {};
      info_t.tm_end = {};
      info_t.tm_begin = mkTime(d0_, t0_);
      info_t.tm_end = mkTime(d1_, t1_);
      if (std::mktime(&info_t.tm_begin) > std::mktime(&info_t.tm_end)) {
        setError(PFLError::PFL_ERR_ARG1_GT_ARG2);
      }
      info_t.flag = false;
    } else {
      setError(PFLError::PFL_ERR_INVALID_DATE_TIME_FORMAT);
    }
  } else {
    setError(PFLError::PFL_ERR_INCOMPLETE_NUM_ARGS);
  }

  return *this;
}

/*!
 * \brief Returns the result of the query.
 * 1) Control Options: Field, Comparison and Value
 * 2) Execute the query operations
 * 3) Save the results inside a temporary vector
 * ------------------------------------------------------
 * \param fld_ Field id.
 * \param cmp_ Compare id operations.
 * \param t_ Value.
 */
void
PFQuery::field(Fields fld_, Compare cmp_, Visitor::var_t&& t_)
{
  log_data_v_.clear();
  Visitor::TypeVar typevar_ = varType(t_);

  if (info_t.flag) {
    std::pair<range_mmap_it, range_mmap_it> range_p_;
    range_p_ = filter_m.equal_range(std::move(std::mktime(&info_t.tm_begin)));
    if (range_p_.first != range_p_.second) {
      for (auto& it_ = range_p_.first; it_ != range_p_.second; ++it_) {
        switch (typevar_) {
          case TypeVar::TInt: {
            if (decision(
                  intFields(fld_, it_->second), std::get<int>(t_), cmp_)) {
              log_data_v_.push_back(it_->second);
            }
            break;
          }
          case TypeVar::TLong: {
            if (decision(
                  longFields(fld_, it_->second), std::get<long>(t_), cmp_)) {
              log_data_v_.push_back(it_->second);
            }
            break;
          }
          case TypeVar::TUint: {
            if (decision(uint32Fields(fld_, it_->second),
                         std::get<uint32_t>(t_),
                         cmp_)) {
              log_data_v_.push_back(it_->second);
            }
            break;
          }
          case TypeVar::TString: {
            if (decision(strFields(fld_, it_->second),
                         std::get<std::string>(t_),
                         cmp_)) {
              log_data_v_.push_back(it_->second);
            }
            break;
          }
        } // switch
      }   // range_p equal zero
    }
  } else {
    auto lower_ =
      filter_m.lower_bound(std::move(std::mktime(&info_t.tm_begin)));
    auto upper_ = filter_m.upper_bound(std::move(std::mktime(&info_t.tm_end)));

    if ((lower_ == filter_m.end()) || (upper_ == filter_m.end())) {
      return;
    }

    std::multimap<int, LogData>::const_iterator it_;
    for (it_ = lower_; it_ != upper_; ++it_) {
      switch (typevar_) {
        case TypeVar::TInt: {
          if (decision(intFields(fld_, it_->second), std::get<int>(t_), cmp_)) {
            log_data_v_.push_back(it_->second);
          }
          break;
        }
        case TypeVar::TLong: {
          if (decision(
                longFields(fld_, it_->second), std::get<long>(t_), cmp_)) {
            log_data_v_.push_back(it_->second);
          }
          break;
        }
        case TypeVar::TUint: {
          if (decision(uint32Fields(fld_, it_->second),
                       std::get<uint32_t>(t_),
                       cmp_)) {
            log_data_v_.push_back(it_->second);
          }
          break;
        }
        case TypeVar::TString: {
          if (decision(strFields(fld_, it_->second),
                       std::get<std::string>(t_),
                       cmp_)) {
            log_data_v_.push_back(it_->second);
          }
          break;
        }
      } // switch
    }
  }
}

/*!
 * \brief Returns the value of the integer type field.
 * \param idx_ Index for accessing data in the vector.
 * \param fld_ Field Id
 * \return field value or INT_MAX in case of error.
 * \note Macro INT_MAX is defined in <climits>.
 */
int
PFQuery::getInt(size_t idx_, Fields fld_) const
{
  return (size() > 0 ? (idx_ > (size() - 1))
                         ? INT_MAX
                         : intFields(fld_, log_data_v_[idx_])
                     : 0);
}

/*!
 * \brief Returns the value of the long integer type field.
 * \param idx_ Index for accessing data in the vector.
 * \param fld_ Field Id
 * \return field value or LONG_MAX in case of error.
 * \note Macro LONG_MAX is defined in <climits>.
 */
long
PFQuery::getLong(size_t idx_, Fields fld_) const
{
  return (size() > 0 ? (idx_ > (size() - 1))
                         ? LONG_MAX
                         : longFields(fld_, log_data_v_[idx_])
                     : 0L);
}

/*!
 * \brief Returns the value of the unsigned int 32bits type field.
 * \param idx_ Index for accessing data in the vector.
 * \param fld_ Field Id
 * \return field value or UINT32_MAX in case of error.
 * \note Macro UINT32_MAX is defined in <climits>.
 */
uint32_t
PFQuery::getUint(size_t idx_, Fields fld_) const
{
  return (size() > 0 ? (idx_ > (size() - 1))
                         ? UINT32_MAX
                         : uint32Fields(fld_, log_data_v_[idx_])
                     : 0);
}

/*!
 * \brief Returns the text contained in the string type field.
 * \param idx_ Index for accessing data in the vector.
 * \param fld_ Field Id
 * \return field value or constant PFLogentry::invalidText in case of
 * error. \note
 */
std::string
PFQuery::getText(size_t idx_, Fields fld_) const
{
  return (size() > 0 ? (idx_ > (size() - 1))
                         ? invalidText.data()
                         : strFields(fld_, log_data_v_[idx_])
                     : std::string());
}

/*!
 * \brief Returns the data vector size.
 * \return size_t
 */
size_t
PFQuery::size() const
{
  return log_data_v_.size();
}

/*!
 * \brief Clear all data.
 */
void
PFQuery::clear()
{
  log_data_v_.clear();
  info_t = {};
  pflError = PFLError::PFL_SUCCESS;
}

/*!
 * \brief  Returns true if the query specified by Field-type exists;
 * otherwise returns false. \param fld_ Field id. \param comp_ Compara Id.
 * \param t_ Value to compare.
 * \return true | false
 */
bool
PFQuery::exists(Fields fld_, Compare comp_, Visitor::var_t&& t_)
{
  Visitor::TypeVar typevar = varType(t_);

  auto ibegin_m = filter_m.cbegin();
  auto iend_m = filter_m.cend();

  auto result_ = iend_m;

  switch (typevar) {
    case TypeVar::TInt: {
      result_ = std::find_if(
        ibegin_m, iend_m, [&fld_, &comp_, &t_, *this](const filter_pair_& d_) {
          return this->decision(
            intFields(fld_, d_.second), std::get<int>(t_), comp_);
        });
    }
    case TypeVar::TLong: {
      result_ = std::find_if(
        ibegin_m, iend_m, [&fld_, &comp_, &t_, *this](const filter_pair_& d_) {
          return this->decision(
            longFields(fld_, d_.second), std::get<long>(t_), comp_);
        });
    }
    case TypeVar::TUint: {
      result_ = std::find_if(
        ibegin_m, iend_m, [&fld_, &comp_, &t_, *this](const filter_pair_& d_) {
          return this->decision(
            uint32Fields(fld_, d_.second), std::get<uint32_t>(t_), comp_);
        });
    }
    case TypeVar::TString: {
      if (fld_ == Fields::HdrTimeStamp) {
        result_ = std::find_if(
          ibegin_m, iend_m, [&comp_, &t_, *this](const filter_pair_& d_) {
            switch (comp_) {
              case EQ:
                if (this->compareDT(d_.second.header.time,
                                    std::get<std::string>(t_)) == 0)
                  return true;
                break;
              case LT:
                if (this->compareDT(d_.second.header.time,
                                    std::get<std::string>(t_)) == -1)
                  return true;
                break;
              case GT:
                if (this->compareDT(d_.second.header.time,
                                    std::get<std::string>(t_)) == 1)
                  return true;
            }
            return false;
          });
      } else {
        result_ =
          std::find_if(ibegin_m,
                       iend_m,
                       [&fld_, &comp_, &t_, *this](const filter_pair_& d_) {
                         return this->decision(strFields(fld_, d_.second),
                                               std::get<std::string>(t_),
                                               comp_);
                       });
      }
    }
    default: {
      return false;
    }
  }

  return (result_ != iend_m) ? true : false;
};

/* PFSummary
 * ---------------------------------------------------------------
 */
/*!
 * \brief PFSummary::PFSummary
 * \param pf_
 */
PFSummary::PFSummary(PFLogentry* pf_)
  : PFLogentry(*pf_)
  , pflError(PFLError::PFL_SUCCESS)
  , lines_per_page_(50 - lines_header)
  , info_t({})
{}

/*!
 * \brief Sets the desired date/time range for summarization operations
 * \param d0_ Begin date.
 * \param t0_ Begin time.
 * \param d1_ End date.
 * \param t1_ End time.
 * \return PFLError Returns the appropriate error code if start date is
 * greater than end date or if arguments are missing.
 */
PFLogentry::PFLError
PFSummary::setDateTime(const std::string&& d0_,
                       const std::string&& t0_,
                       const std::string&& d1_,
                       const std::string&& t1_)
{

  pflError = PFLError::PFL_SUCCESS;

  if ((!d0_.empty() && !t0_.empty()) && (d1_.empty() && t1_.empty())) { // a,b
    if (isValidDate(d0_) && isValidTime(t0_)) {
      info_t.tm_begin = mkTime(d0_, t0_);
      info_t.tm_end = {};
      info_t.flag = true;
    } else {
      setError(PFLError::PFL_ERR_INVALID_DATE_TIME_FORMAT);
    }
  } else if ((!d0_.empty() && !t0_.empty()) &&
             (!d1_.empty() && !t1_.empty())) { // a,b, a1, b1
    if (isValidDate(d0_) && isValidTime(t0_) && isValidDate(d1_) &&
        isValidTime(t1_)) {
      info_t.tm_begin = {};
      info_t.tm_end = {};
      info_t.tm_begin = mkTime(d0_, t0_);
      info_t.tm_end = mkTime(d1_, t1_);
      if (std::mktime(&info_t.tm_begin) > std::mktime(&info_t.tm_end)) {
        setError(PFLError::PFL_ERR_ARG1_GT_ARG2);
        return PFLError::PFL_ERR_ARG1_GT_ARG2;
      }
      info_t.flag = false;
    } else {
      setError(PFLError::PFL_ERR_INVALID_DATE_TIME_FORMAT);
    }
  } else {
    setError(PFLError::PFL_ERR_INCOMPLETE_NUM_ARGS);
    return PFLError::PFL_ERR_INCOMPLETE_NUM_ARGS;
  }

  return PFLError::PFL_SUCCESS;
}

/*!
 * \brief If you enter the hostname, operations will only be done for this
 * particular host.
 * \param hn_ (String) Host-name.
 */
void
PFSummary::setHostName(const std::string&& hn_)
{
  info_t.hostname = hn_;
}

/*!
 * \brief If you enter the real interface name, operations will only be
 * done for this particular interface. \param ifname_ (String) Interface
 * name.
 */
void
PFSummary::setIfName(const std::string&& ifname_)
{
  info_t.ifname = ifname_;
}

/*!
 * \brief Defines the number of lines per page.
 * \param lp_ Numeber of lines. Default: 50
 * \note Subtracts the number of lines occupied by the default header.
 */
void
PFSummary::setLinesPage(const int lp_)
{
  lines_per_page_ = (lp_ - lines_header);
}

/*!
 * \brief Processes summarization by protocol.
 * \param id_ Protocol id.
 * \param ipver_ Protocol version.
 */
void
PFSummary::protocol(ProtoID id_, IPVersion ipver_)
{
  if (pflError == PFLError::PFL_SUCCESS) {
    std::pair<range_mmap_it, range_mmap_it> range_a;

    std::memset(mat_in_, 0, sizeof(mat_in_));
    std::memset(mat_out_, 0, sizeof(mat_out_));
    results_t.accTcp4 = 0;
    results_t.accTcp6 = 0;

    if (info_t.flag) { // equal (d,t)
      range_a = filter_m.equal_range(std::move(std::mktime(&info_t.tm_begin)));
      compute(range_a, id_, ipver_);
      heading();
      printTabReasonByAction(id_, ipver_);
    } else { // range (d0,t0, d1, t1)
      auto lower_ =
        filter_m.lower_bound(std::move(std::mktime(&info_t.tm_begin)));
      auto upper_ =
        filter_m.upper_bound(std::move(std::mktime(&info_t.tm_end)));
      std::multimap<int, LogData>::iterator it_;
      compute(lower_, upper_, id_, ipver_);
      heading();
      printTabReasonByAction(id_, ipver_);
    }
  }
}

/*!
 * \brief PFSummary::getGrandTotals
 */
void
PFSummary::getGrandTotals()
{
  printGrandTotals();
}

/*!
 * \internal
 * \brief Generates matrix for Reason X Action table.
 * \param direction_ in | out
 * \param reason_ match | other
 * \param action_ pass | block | unkn(%u)
 */
void
PFSummary::countReasonByAction(const std::string direction_,
                               const std::string reason_,
                               const std::string action_)
{
  if (direction_ == "in") {
    if (reason_ == "match") {
      mat_in_[0][0]++;
      mat_in_[0][1] += (action_ == "pass") ? 1 : 0;
      mat_in_[0][2] += (action_ == "block") ? 1 : 0;
      mat_in_[0][3] += (action_ == "unkn(%u)") ? 1 : 0;
    } else { // other
      mat_in_[1][0]++;
      mat_in_[1][1] += (action_ == "pass") ? 1 : 0;
      mat_in_[1][2] += (action_ == "block") ? 1 : 0;
      mat_in_[1][3] += (action_ == "unkn(%u)") ? 1 : 0;
    }
  } else { // out
    if (reason_ == "match") {
      mat_out_[0][0]++;
      mat_out_[0][1] += (action_ == "pass") ? 1 : 0;
      mat_out_[0][2] += (action_ == "block") ? 1 : 0;
      mat_out_[0][3] += (action_ == "unkn(%u)") ? 1 : 0;
    } else { // other
      mat_out_[1][0]++;
      mat_out_[1][1] += (action_ == "pass") ? 1 : 0;
      mat_out_[1][2] += (action_ == "block") ? 1 : 0;
      mat_out_[1][3] += (action_ == "unkn(%u)") ? 1 : 0;
    }
  }
}

/*!
 * \internal
 * \brief Default heading to summaries.
 */
void
PFSummary::heading()
{
  char buf_[20] = {};

  std::cout << "Summary: ";
  std::strftime(buf_, 20, "%Y-%m-%d %T", &info_t.tm_begin);
  std::cout << "Range from: " << buf_ << " ";
  if ((info_t.tm_end.tm_year + 1900) > 1900) {
    std::strftime(buf_, 20, "%Y-%m-%d %T", &info_t.tm_end);
  }
  std::cout << "to: " << buf_ << "\n";
}

/*!
 * \internal
 * \brief Header to grand totals.
 */
void
PFSummary::printGrandTotals()
{
  heading();

  std::cout << "\nGRAND TOTALS\n";
  std::cout << "Total log entries processed: " << filter_m.size() << "\n";
  std::cout << std::setw(20) << std::left << "Total TCPv4:" << std::setw(10)
            << std::right << acc_t.accTCP4 << std::setw(7) << std::right
            << std::fixed << std::setprecision(2)
            << percent(acc_t.accTCP4, filter_m.size()) << "%\n";
  std::cout << std::setw(20) << std::left << "Total TCPv6:" << std::setw(10)
            << std::right << acc_t.accTCP6 << std::setw(7) << std::right
            << std::fixed << std::setprecision(2)
            << percent(acc_t.accTCP6, filter_m.size()) << "%\n";
  std::cout << std::setw(20) << std::left << "Total UDPv4:" << std::setw(10)
            << std::right << acc_t.accUDP << std::setw(7) << std::right
            << std::fixed << std::setprecision(2)
            << percent(acc_t.accUDP, filter_m.size()) << "%\n";
  std::cout << std::setw(20) << std::left << "Total ICMPv4:" << std::setw(10)
            << std::right << acc_t.accICMP4 << std::setw(7) << std::right
            << std::fixed << std::setprecision(2)
            << percent(acc_t.accICMP4, filter_m.size()) << "%\n";
  std::cout << std::setw(20) << std::left << "Total ICMPv6:" << std::setw(10)
            << std::right << acc_t.accICMP6 << std::setw(7) << std::right
            << std::fixed << std::setprecision(2)
            << percent(acc_t.accICMP6, filter_m.size()) << "%\n";
  std::cout << std::setw(20) << std::left << "Total IGMP:" << std::setw(10)
            << std::right << acc_t.accIGMP << std::setw(7) << std::right
            << std::fixed << std::setprecision(2)
            << percent(acc_t.accIGMP, filter_m.size()) << "%\n";
  std::cout << std::setw(20) << std::left << "Total CARP:" << std::setw(10)
            << std::right << acc_t.accCARP << std::setw(7) << std::right
            << std::fixed << std::setprecision(2)
            << percent(acc_t.accCARP, filter_m.size()) << "%\n";

  const std::string sep(80, '-');

  std::cout << std::setw(20) << std::left
            << "Total IPv6 HopOpt:" << std::setw(10) << std::right
            << acc_t.accHopOpt << std::setw(7) << std::right << std::fixed
            << std::setprecision(2) << percent(acc_t.accHopOpt, filter_m.size())
            << "%\n"
            << sep << "\n";
}

/*!
 * \internal
 * \brief Prints the Reason X Action table.
 * \param id_ Protocol id.
 * \param ipver_ Ip version.
 */
void
PFSummary::printTabReasonByAction(ProtoID id_, IPVersion ipver_)
{
  const std::string sep(80, '=');
  std::cout << "Hostname: ["
            << (info_t.hostname.empty() ? "All" : info_t.hostname) << "]\n";
  std::cout << "IP Version: [" << static_cast<int>(ipver_) << "] Protocol: ["
            << (id_ == ProtoID::ProtoTCP    ? "TCP"
                : id_ == ProtoID::ProtoUDP  ? "UDP"
                : id_ == ProtoID::ProtoIGMP ? "IGMP"
                : id_ == ProtoID::ProtoCARP ? "CARP"
                : id_ == ProtoID::ICMPv4    ? "ICMP v4"
                : id_ == ProtoID::ICMPv6    ? "ICMP v6"
                                            : "")
            << "]\n";
  std::cout << "Total Unique Ip Addresses - Source: " << uniq_ip_src.size()
            << " Destination: " << uniq_ip_dst.size() << "\n";
  std::cout << "Total in Range: ";
  if (id_ == ProtoID::ProtoTCP) {
    std::cout << (ipver_ == IPVersion::IPv4 ? results_t.accTcp4
                                            : results_t.accTcp6)
              << "\n\n";
  } else if (id_ == ProtoID::ProtoUDP) {
    std::cout << (ipver_ == IPVersion::IPv4 ? results_t.accUdp4
                                            : results_t.accUdp6)
              << "\n";
    std::cout << "Acc. Data Length: " << results_t.accUdpDataLen << "\n\n";
  }
  std::cout << "Real Interface: ["
            << (info_t.ifname.empty() ? "All" : info_t.ifname) << "] "
            << "Direction: ["
            << "in"
            << "]\n";
  std::cout << std::setw(10) << std::left << std::setfill('_') << "Reason"
            << std::setw(10) << std::left << std::setfill('_') << " Total"
            << std::setw(10) << std::left << std::setfill('_') << " Pass"
            << std::setw(10) << std::left << std::setfill('_') << " Block"
            << std::setw(10) << std::left << std::setfill('_') << " Unkn(%u)"
            << "\n";

  std::cout << std::setw(10) << std::left << std::setfill('_') << "Match"
            << std::setfill(' ');
  for (int j = 0; j <= 3; ++j) {
    std::cout << std::setw(10) << std::right << mat_in_[0][j];
  }
  std::cout << "\n";
  std::cout << std::setw(10) << std::left << std::setfill('_') << "Other"
            << std::setfill(' ');
  for (int j = 0; j <= 3; ++j) {
    std::cout << std::setw(10) << std::right << mat_in_[1][j];
  }

  std::cout << "\n\nReal Interface: ["
            << (info_t.ifname.empty() ? "All" : info_t.ifname) << "] "
            << "Direction: ["
            << "out"
            << "]\n";
  std::cout << std::setw(10) << std::left << std::setfill('_') << "Reason"
            << std::setw(10) << std::left << std::setfill('_') << " Total"
            << std::setw(10) << std::left << std::setfill('_') << " Pass"
            << std::setw(10) << std::left << std::setfill('_') << " Block"
            << std::setw(10) << std::left << std::setfill('_') << " Unkn(%u)"
            << "\n";

  std::cout << std::setw(10) << std::left << std::setfill('_') << "Match"
            << std::setfill(' ');
  for (int j = 0; j <= 3; ++j) {
    std::cout << std::setw(10) << std::right << mat_out_[0][j];
  }
  std::cout << "\n";
  std::cout << std::setw(10) << std::left << std::setfill('_') << "Other"
            << std::setfill(' ');
  for (int j = 0; j <= 3; ++j) {
    std::cout << std::setw(10) << std::right << mat_out_[1][j];
  }

  std::cout << "\n" << sep << "\n";
}

/*!
 * \internal
 * \brief Processes the necessary calculations for the summaries.
 */
template<typename ForwardIt>
void
PFSummary::compute(ForwardIt iter_, enum ProtoID id_, IPVersion ipver_)
{
  for (auto& it_ = iter_.first; it_ != iter_.second; ++it_) {
    if (static_cast<IPVersion>(it_->second.ip_version) == ipver_ &&
        it_->second.proto_id == id_) {
      if (info_t.hostname.empty()) { // all
        (ipver_ == IPVersion::IPv4) ? results_t.accUdp4++ : results_t.accUdp6++;
        results_t.accUdpDataLen += it_->second.data_len;

        if (info_t.ifname.empty()) {
          countReasonByAction(
            it_->second.direction, it_->second.reason, it_->second.action);
        } else {
          if (info_t.ifname == it_->second.real_iface) {
            countReasonByAction(
              it_->second.direction, it_->second.reason, it_->second.action);
          }
        }

      } else if (info_t.hostname == it_->second.hostname) { // hostname only
        (ipver_ == IPVersion::IPv4) ? results_t.accUdp4++ : results_t.accUdp6++;
        results_t.accUdpDataLen += it_->second.data_len;

        if (info_t.ifname.empty()) {
          countReasonByAction(
            it_->second.direction, it_->second.reason, it_->second.action);
        } else {
          if (info_t.ifname == it_->second.real_iface) {
            countReasonByAction(
              it_->second.direction, it_->second.reason, it_->second.action);
          }
        }
      }
    }
  } // for it_
}

/*!
 * \internal
 * \brief Processes the necessary calculations for the summaries.
 */
template<typename ForwardIt>
void
PFSummary::compute(ForwardIt lower_,
                   ForwardIt upper_,
                   enum ProtoID id_,
                   IPVersion ipver_)
{
  std::multimap<int, LogData>::iterator it_;
  for (it_ = lower_; it_ != upper_; ++it_) {
    if (it_->second.ip_version == static_cast<int>(ipver_) &&
        it_->second.proto_id == id_) {
      if (info_t.hostname.empty()) { // all
        (ipver_ == IPVersion::IPv4) ? results_t.accUdp4++ : results_t.accUdp6++;
        results_t.accUdpDataLen += it_->second.data_len;

        if (info_t.ifname.empty()) {
          countReasonByAction(
            it_->second.direction, it_->second.reason, it_->second.action);
        } else {
          if (info_t.ifname == it_->second.real_iface) {
            countReasonByAction(
              it_->second.direction, it_->second.reason, it_->second.action);
          }
        }

      } else if (info_t.hostname == it_->second.hostname) { // only hostname
        (ipver_ == IPVersion::IPv4) ? results_t.accUdp4++ : results_t.accUdp6++;
        results_t.accUdpDataLen += it_->second.data_len;

        if (info_t.ifname.empty()) {
          countReasonByAction(
            it_->second.direction, it_->second.reason, it_->second.action);
        } else {
          if (info_t.ifname == it_->second.real_iface) {
            countReasonByAction(
              it_->second.direction, it_->second.reason, it_->second.action);
          }
        }
      }
    }
  } // for it_
}

/*!
 * \brief User interface for generating reports
 * \param id_ Protocol ID
 * \param ipver_ Protocol Version
 */
void
PFSummary::report(ProtoID id_, IPVersion ipver_)
{
  if (pflError == PFLError::PFL_SUCCESS) {
    info_t.proto_id = id_;
    info_t.ip_version = ipver_;

    reportHeader();
    reportDetails();
  }
}

/*!
 * \brief User interface for generating reports
 * \param uniq_ Type of report: Resume | Details
 * \param id_ Protocol ID
 * \param ipver_ Protocol Version
 */
void
PFSummary::reportUnique(UniqueType uniq_, ProtoID id_, IPVersion ipver_)
{
  if (pflError == PFLError::PFL_SUCCESS) {
    uniqType = uniq_;
    info_t.proto_id = id_;
    info_t.ip_version = ipver_;

    reportHeader();

    if (info_t.flag) { // equal (d,t)
      std::pair<range_mmap_it, range_mmap_it> range_;
      range_ = filter_m.equal_range(std::move(std::mktime(&info_t.tm_begin)));
      printUnique(uniq_ip_src, range_.first, range_.second);
    } else {
      auto lower_ =
        filter_m.lower_bound(std::move(std::mktime(&info_t.tm_begin)));
      auto upper_ =
        filter_m.upper_bound(std::move(std::mktime(&info_t.tm_end)));
      printUnique(uniq_ip_src, lower_, upper_);
    }
  }
}

/*!
 * \internal
 * \brief Default report header.
 */
void
PFSummary::reportHeader()
{
  char buf0_[20] = {};
  char buf1_[20] = {};
  std::strftime(buf0_, 20, "%Y-%m-%d %T", &info_t.tm_begin);
  if (info_t.flag) {
    std::memcpy(buf1_, buf0_, sizeof(buf0_));
  } else {
    std::strftime(buf1_, 20, "%Y-%m-%d %T", &info_t.tm_end);
  }

  const std::string sep(80, '=');
  std::cout << "PFLogentry\n\n";

  std::cout << "Range from: [" << std::setw(19) << buf0_ << "] To: ["
            << std::setw(19) << buf1_ << "]\n";
  std::cout << "Host Name: [" << std::setw(67) << std::left
            << (info_t.hostname.empty() ? "All" : info_t.hostname) << "]\n";
  std::cout << "Real Ifname: [" << std::setw(10) << std::left
            << (info_t.ifname.empty() ? "All" : info_t.ifname)
            << "] Protocol/Version: [" << std::setw(7) << std::left
            << (info_t.proto_id == ProtoID::ProtoTCP    ? "TCP"
                : info_t.proto_id == ProtoID::ProtoUDP  ? "UDP"
                : info_t.proto_id == ProtoID::ProtoIGMP ? "IGMP"
                : info_t.proto_id == ProtoID::ProtoCARP ? "CARP"
                : info_t.proto_id == ProtoID::ICMPv4    ? "ICMP v4"
                : info_t.proto_id == ProtoID::ICMPv6    ? "ICMP v6"
                                                        : "")
            << "]/[" << std::setw(1) << std::left
            << static_cast<int>(info_t.ip_version) << "]\n"
            << sep << "\n\n";
}

/*!
 * \internal
 * \brief Helper function to print the correct header for the chosen
 * report type.
 */
void
PFSummary::reportHdrDetails()
{
  const std::string sep(50, '-');

  std::cout.width(20);
  std::cout << "Time Stamp";
  if (info_t.ip_version == IPVersion::IPv4) {
    std::cout.width(22);
    std::cout << "Source:Port";
    std::cout.width(28);
    std::cout << "Destination:Port";
    std::cout << "R D\n";
    std::cout << "------------------- "
              << "--------------------- "
              << "--------------------------- "
              << "- ---\n";
  } else {
    std::cout.width(51);
    std::cout << "Address:Port";
    std::cout << "R D\n";
    std::cout << "------------------- " << sep << " - ---\n";
  }
}

/*!
 * \internal
 * \brief Helper function responsible for processing report details.
 */
void
PFSummary::reportDetails()
{
  int acc_lines = 0;
  results_t.accUdp4 = 0;
  results_t.accUdp6 = 0;
  results_t.accUdpDataLen = 0;

  std::pair<range_mmap_it, range_mmap_it> range_a;

  std::memset(mat_in_, 0, sizeof(mat_in_));
  std::memset(mat_out_, 0, sizeof(mat_out_));

  if (info_t.flag) { // equal (d,t)
    range_a = filter_m.equal_range(std::move(std::mktime(&info_t.tm_begin)));

    reportHdrDetails();
    int lin = 0;
    for (auto it_ = range_a.first; it_ != range_a.second; ++it_) {
      if (static_cast<IPVersion>(it_->second.ip_version) == info_t.ip_version &&
          it_->second.proto_id == info_t.proto_id) {
        if (info_t.hostname.empty()) {
          lin = print(it_);
        } else if (info_t.hostname == it_->second.hostname) {
          lin = print(it_);
        }
        acc_lines += lin;
        if (acc_lines >= lines_per_page_) {
          reportHeader();
          reportHdrDetails();
          acc_lines = 0;
        }
      } // for it_
    }
  } else { // range (d0,t0, d1, t1)
    auto lower_ =
      filter_m.lower_bound(std::move(std::mktime(&info_t.tm_begin)));
    auto upper_ = filter_m.upper_bound(std::move(std::mktime(&info_t.tm_end)));
    std::multimap<int, LogData>::iterator it_;

    reportHdrDetails();
    int lin = 0;
    for (it_ = lower_; it_ != upper_; ++it_) {
      if (static_cast<IPVersion>(it_->second.ip_version) == info_t.ip_version &&
          it_->second.proto_id == info_t.proto_id) {
        if (info_t.hostname.empty()) {
          lin = print(it_);
        } else if (info_t.hostname == it_->second.hostname) {
          lin = print(it_);
        }
        acc_lines += lin;
        if (acc_lines >= lines_per_page_) {
          reportHeader();
          reportHdrDetails();
          acc_lines = 0;
        }
      } // for it_
    }
  }
}

/*!
 * \internal
 * \brief printUnique
 * \param set_ A std::set collection of unique IP addresses.
 * \param min_ Begin Iterator.
 * \param max_ End Iterator.
 */
template<typename TSet, typename TMin, typename TMax>
void
PFSummary::printUnique(TSet set_, TMin min_, TMax max_)
{
  switch (uniqType) {
    case UniqueType::Overview: {
      std::cout << "Total: [" << std::right << std::setw(10)
                << std::setfill(' ') << uniq_ip_src.size() << "]\n";
      std::cout << "Source                                  In         Out\n";
      std::cout << "--------------------------------------- ---------- "
                   "----------\n";

      for (const auto& ip_ : set_) {
        int cntIn_ = 0;
        int cntOut_ = 0;
        [[maybe_unused]] const int i = std::count_if(
          min_, max_, [&ip_, &cntIn_, &cntOut_, this](const filter_pair_& d_) {
            if ((ip_ == d_.second.ip_src_addr) &&
                (this->info_t.proto_id == d_.second.proto_id) &&
                (this->info_t.ip_version ==
                 static_cast<IPVersion>(d_.second.ip_version))) {
              if (this->info_t.ifname.empty()) {
                if (this->info_t.hostname.empty()) {
                  (d_.second.direction == "in" ? ++cntIn_ : ++cntOut_);
                  return true;
                } else if ((this->info_t.hostname == d_.second.hostname)) {
                  (d_.second.direction == "in" ? ++cntIn_ : ++cntOut_);
                  return true;
                }
              } else if (this->info_t.ifname == d_.second.real_iface) {
                if (this->info_t.hostname.empty()) {
                  (d_.second.direction == "in" ? ++cntIn_ : ++cntOut_);
                  return true;
                } else if ((this->info_t.hostname == d_.second.hostname)) {
                  (d_.second.direction == "in" ? ++cntIn_ : ++cntOut_);
                  return true;
                }
              }
            }
            return false;
          });

        if (cntIn_ > 0 || cntOut_ > 0) {
          std::cout.width(39);
          std::cout << std::left << ip_;
          std::cout.width(11);
          if (cntIn_ > 0) {
            std::cout << std::right << cntIn_;
          } else {
            std::cout << std::right << " ";
          }
          std::cout.width(11);
          if (cntOut_ > 0) {
            std::cout << std::right << cntOut_;
          } else {
            std::cout << std::right << " ";
          }
          std::cout << "\n";
        }
      }
      break;
    }
    case UniqueType::Details: {
      // get unique source ports by ip
      std::set<int> s_port = {};
      for (const auto& ip_ : set_) {
        for (auto it_ = min_; it_ != max_; ++it_) {
          if ((ip_ == it_->second.ip_src_addr) &&
              (info_t.proto_id == it_->second.proto_id) &&
              (info_t.ip_version ==
               static_cast<IPVersion>(it_->second.ip_version))) {
            if (info_t.ifname.empty()) {
              if (info_t.hostname.empty()) {
                s_port.insert(it_->second.src_port);
              } else if ((info_t.hostname == it_->second.hostname)) {
                s_port.insert(it_->second.src_port);
              }
            } else if (info_t.ifname == it_->second.real_iface) {
              if (info_t.hostname.empty()) {
                s_port.insert(it_->second.src_port);
              } else if ((info_t.hostname == it_->second.hostname)) {
                s_port.insert(it_->second.src_port);
              }
            }
          }
        }

        std::cout << "Source Address: " << ip_ << "\n";
        [[maybe_unused]] int i_ = 0;
        for (const auto& port_ : s_port) {
          std::stringstream line_ = {};
          const int cnt_ = std::count_if(
            min_, max_, [&ip_, &port_, &line_](const filter_pair_& d_) {
              if (ip_ == d_.second.ip_src_addr && port_ == d_.second.src_port) {
                line_ << "\n\t\tDir: [" << d_.second.direction << "] ";
                line_ << (d_.second.ip_version == 6
                            ? "Dest: [" + d_.second.ip_dst_addr +
                                "]:" + std::to_string(d_.second.dst_port)
                            : "Dest: [" + d_.second.ip_dst_addr + ":" +
                                std::to_string(d_.second.dst_port) + "]");
                return true;
              }
              return false;
            });

          if (!line_.str().empty()) {
            std::cout << "\tPort: " << port_ << " Score: " << cnt_ << "\t"
                      << line_.str() << "\n";
          }
        }

        s_port.clear();
      } // for
      break;
    }
  }
}

/*!
 * \internal
 * \brief Prints the collected data in the correct format for the chosen
 * report.
 * \tparam ForwardIt
 * \return line count
 */
template<typename ForwardIt>
int
PFSummary::print(ForwardIt it_)
{
  int lin = 0;
  const std::string sep(80, '.');

  char buf_[20] = {};
  std::strftime(buf_, 20, "%Y-%m-%d %T", &it_->second.header.tm_time);
  std::cout << buf_ << " ";

  if (info_t.ip_version == IPVersion::IPv4) {
    std::cout.width(22);
    std::cout << (it_->second.ip_src_addr);
    std::cout.width(27);
    std::cout << (it_->second.ip_dst_addr) << " ";
    std::string s;
    s[0] = std::toupper(it_->second.action[0]);
    std::cout << s[0] << " " << it_->second.direction << "\n";
    lin++;
  } else if (info_t.ip_version == IPVersion::IPv6) {
    std::cout << "Src: ";
    std::cout.width(46);
    std::cout << std::left << "[" + it_->second.ip_src_addr + "]";
    std::string s;
    s[0] = std::toupper(it_->second.action[0]);
    std::cout << s[0] << " " << it_->second.direction << "\n";
    std::cout << "                    Dst: [" << std::setfill(' ')
              << std::setw(44) << it_->second.ip_dst_addr + "]\n";
    lin++;
  }

  switch (info_t.proto_id) {
    case ProtoID::ProtoHOPOPT:
      [[fallthrough]];
    case ProtoID::ProtoUDP:
      [[fallthrough]];
    case ProtoID::ProtoTCP: {
      if (info_t.ip_version == IPVersion::IPv4) {
        if (info_t.proto_id == ProtoID::ProtoUDP) {
          std::cout << "                    Data Length: [" << std::setw(10)
                    << std::right << it_->second.data_len << "]\n";
          lin++;
        }
      } else if (info_t.ip_version == IPVersion::IPv6) {
        if (info_t.proto_id == ProtoID::ProtoUDP) {
          std::cout << "                    Data Length: [" << std::setw(10)
                    << std::right << it_->second.data_len << "]\n";
          lin++;
        }
      }
      break;
    }
    case ProtoID::ICMPv4: {
      std::cout.width(32);
      std::cout << "Type";
      std::cout << " Echo-type\n";
      std::cout.width(0);
      std::cout << "-------------------------------- "
                   "--------------------------------\n";
      std::cout << it_->second.icmp.type
                << std::setw(it_->second.icmp.type.length() +
                             (31 - it_->second.icmp.type.length()))
                << std::setfill(' ') << it_->second.icmp.echo_type << "\n";
      lin++;
      std::cout << "ID         : " << std::setw(15) << it_->second.icmp.id
                << std::setfill(' ') << " Seq: " << it_->second.icmp.seq
                << "\n";
      lin++;
      std::cout << "Description: " << it_->second.icmp.descr << "\n";
      lin++;
      std::cout << "Timestamps : Originate            Received             "
                   "Transmit\n";
      std::cout << "             -------------------- -------------------- "
                   "--------------------\n";
      lin++;
      std::cout << "             " << std::setw(21) << std::setfill(' ')
                << it_->second.icmp.otime << std::setw(21) << std::setfill(' ')
                << it_->second.icmp.rtime << it_->second.icmp.ttime << "\n";
      lin++;
      std::cout << sep << "\n";
      lin++;
      break;
    }
    case ProtoID::ProtoIGMP:
      break;
    case ProtoID::ProtoCARP: {
      std::cout << "Type    : " << std::setw(10) << std::setfill(' ')
                << it_->second.carp.type << " TTL: " << std::setw(10)
                << std::setfill(' ') << it_->second.carp.ttl
                << " VHID: " << std::setw(10) << std::setfill(' ')
                << it_->second.carp.vhid << " Version: " << std::setw(10)
                << std::setfill(' ') << it_->second.carp.version << "\n";
      lin++;
      std::cout << "Advbase : " << std::setw(10) << std::setfill(' ')
                << it_->second.carp.advbase
                << "(secs) Advskew : " << std::setw(10) << std::setfill(' ')
                << it_->second.carp.advskew << "\n";
      lin++;
      std::cout << sep << "\n";
      lin++;
    }
  }
  return lin;
};

/* PFRawToXML----------------------------------------------------------------*/
/*!
 * \internal
 * \brief Constructs a PFRawToXML object (default).
 */
PFRawToXML::PFRawToXML() {}

/*!
 * \internal
 * \brief Constructs a PFRawToXML object.
 * \param log_data_t
 */
PFRawToXML::PFRawToXML(LogFormat fmt_)
  : log_fmt_(fmt_)
{}

/*!
 * \internal
 * \brief Auxiliary member that return a formatted localtime.
 * \return Formatted string with a date and time.
 */
std::string
PFRawToXML::dateTime() const
{
  std::time_t now_t =
    std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  char tm_buf[80] = {};
  std::strftime(tm_buf, sizeof(tm_buf), "%F;%T", std::localtime(&now_t));
  return tm_buf;
}

/*!
 * \internal
 * \brief Auxiliary member that provides the '.xml' extension to the
 * filename if the user does not inform.
 * \param fn_ File name
 * \return PFLError
 * \return Normalized file name by reference name with .xml extension.
 * \note 1. Basically for a name to be considered inconsistent, it must
 * have more than one dot '.' in its formation. \note 2. If there're
 * spaces in the filename they will be replaced by '_'.
 */
PFLogentry::PFLError
PFRawToXML::normFn(std::string& fn_)
{
  std::string fn_s = fn_;
  int c = 0;
  for (auto& a : fn_) {
    if (a == '.') {
      ++c;
    }
  }

  if (c <= 1) {
    std::replace(fn_.begin(), fn_.end(), ' ', '_');
    std::transform(fn_.cbegin(), fn_.cend(), fn_.begin(), ::tolower);
    if (size_t f = std::string_view{ fn_ }.rfind("."); f != std::string::npos) {
      if (std::string s_ = fn_.substr(f + 1, fn_.size()); s_ != "xml") {
        fn_.replace(f + 1, fn_.size(), "xml");
      }
      return PFLError::PFL_SUCCESS;
    } else {
      fn_ += ".xml";
      return PFLError::PFL_SUCCESS;
    }
  }

  return PFLError::PFL_ERR_XML_FILE_NAME_INCONSISTENT;
};

/*!
 * \internal
 * \brief Save the XML to disk.
 * \return PFLError code.
 */
PFLogentry::PFLError
PFRawToXML::close()
{
  return (doc.SaveFile(fname_.c_str()) == XMLError::XML_SUCCESS)
           ? PFLError::PFL_SUCCESS
           : PFLError::PFL_ERR_XML_FILE_NOT_SAVE;
}

/*!
 * \internal
 * \brief Appends the raw_ log entry onto the end of XML file.
 * \param log_data_t
 */
PFRawToXML&
PFRawToXML::append(LogData& log_data_t)
{
  log_data = std::move(log_data_t);
  writePart();
  return *this;
}

/*!
 * \internal
 * \brief Save the raw_ log entry to an XML file. It should only be used
 * for a single entry.
 * \param fn_
 * \return PFLErro code.
 * \code{.cc}
 * PFRawToXML xml( raw_entry );
 * PFLError err = xml.save("unique_entry.xml");
 * \endcode
 */
PFLogentry::PFLError
PFRawToXML::save(const std::string fn_)
{
  std::string s_ = fn_;
  PFLError err = normFn(s_);
  if (err == PFLError::PFL_SUCCESS) {
    fname_ = fn_;

    decl = doc.NewDeclaration();
    doc.LinkEndChild(decl);

    root = doc.NewElement("PFLogentry");
    doc.LinkEndChild(root);

    XMLElement* hdr_ = doc.NewElement("generated");
    hdr_->SetText("libPFLogentry");
    root->InsertFirstChild(hdr_);

    hdr_ = doc.NewElement("created");
    hdr_->SetText(dateTime().c_str());
    root->InsertEndChild(hdr_);

    hdr_ = doc.NewElement("filename");
    hdr_->SetText(fname_.c_str());
    root->InsertEndChild(hdr_);

    root_node = doc.NewElement("logentries");
    root_node->SetAttribute(
      "type", (log_fmt_ == LogFormat::LogBSD ? "rfc-3164" : "rfc-5424"));
    root->InsertEndChild(root_node);
    return close();
  }
  return err;
}

/*!
 * \internal
 * \brief Private member that creates the data structure in XML format
 * that will be written to the file.
 */
void
PFRawToXML::writePart()
{

  XMLElement* elem0 = doc.NewElement("entry");
  root_node->InsertEndChild(elem0);

  XMLElement* hdr = doc.NewElement("header");
  elem0->InsertEndChild(hdr);

  XMLElement* hdr_child = doc.NewElement("id");
  hdr_child->SetText(log_data.header.id.c_str());
  hdr->InsertEndChild(hdr_child);

  hdr_child = doc.NewElement("month");
  hdr_child->SetText(log_data.header.month);
  hdr->InsertEndChild(hdr_child);

  hdr_child = doc.NewElement("day");
  hdr_child->SetText(log_data.header.day);
  hdr->InsertEndChild(hdr_child);

  hdr_child = doc.NewElement("time");
  hdr_child->SetText(log_data.header.time.c_str());
  hdr->InsertEndChild(hdr_child);

  hdr_child = doc.NewElement("hostname");
  hdr_child->SetText(log_data.hostname.c_str());
  hdr->InsertEndChild(hdr_child);

  XMLElement* data = doc.NewElement("rule_number");
  data->SetText(log_data.rule_number);
  elem0->InsertEndChild(data);

  data = doc.NewElement("subrule_number");
  data->SetText(log_data.sub_rule_number);
  elem0->InsertEndChild(data);

  data = doc.NewElement("anchor");
  data->SetText(log_data.anchor.c_str());
  elem0->InsertEndChild(data);

  data = doc.NewElement("tracker");
  data->SetText(log_data.tracker);
  elem0->InsertEndChild(data);

  data = doc.NewElement("real_iface");
  data->SetText(log_data.real_iface.c_str());
  elem0->InsertEndChild(data);

  data = doc.NewElement("reason");
  data->SetText(log_data.reason.c_str());
  elem0->InsertEndChild(data);

  data = doc.NewElement("direction");
  data->SetText(log_data.direction.c_str());
  elem0->InsertEndChild(data);

  data = doc.NewElement("ip_version");
  data->SetText(log_data.ip_version);
  elem0->InsertEndChild(data);

  data = doc.NewElement("proto_id");
  data->SetText(log_data.proto_id);
  elem0->InsertEndChild(data);

  data = doc.NewElement("proto_text");
  data->SetText(log_data.proto_text.c_str());
  elem0->InsertEndChild(data);

  data = doc.NewElement("length_data");
  data->SetText(log_data.length_data);
  elem0->InsertEndChild(data);

  data = doc.NewElement("ip_src_addr");
  data->SetText(log_data.ip_src_addr.c_str());
  elem0->InsertEndChild(data);

  data = doc.NewElement("ip_dst_addr");
  data->SetText(log_data.ip_dst_addr.c_str());
  elem0->InsertEndChild(data);

  data = doc.NewElement("src_port");
  data->SetText(log_data.src_port);
  elem0->InsertEndChild(data);

  data = doc.NewElement("dst_port");
  data->SetText(log_data.dst_port);
  elem0->InsertEndChild(data);

  data = doc.NewElement("data_len");
  data->SetText(log_data.data_len);
  elem0->InsertEndChild(data);

  // ipv4_data
  XMLElement* ipv4 = doc.NewElement("ipv4_data");
  elem0->InsertEndChild(ipv4);
  XMLElement* ipv4_data = doc.NewElement("tos");
  ipv4_data->SetText(log_data.ipv4_data.tos.c_str());
  ipv4->InsertEndChild(ipv4_data);

  ipv4_data = doc.NewElement("ecn");
  ipv4_data->SetText(log_data.ipv4_data.ecn.c_str());
  ipv4->InsertEndChild(ipv4_data);

  ipv4_data = doc.NewElement("ttl");
  ipv4_data->SetText(log_data.ipv4_data.ttl);
  ipv4->InsertEndChild(ipv4_data);

  ipv4_data = doc.NewElement("packet_id");
  ipv4_data->SetText(log_data.ipv4_data.packet_id);
  ipv4->InsertEndChild(ipv4_data);

  ipv4_data = doc.NewElement("offset");
  ipv4_data->SetText(log_data.ipv4_data.offset);
  ipv4->InsertEndChild(ipv4_data);

  ipv4_data = doc.NewElement("flags");
  ipv4_data->SetText(log_data.ipv4_data.flags.c_str());
  ipv4->InsertEndChild(ipv4_data);

  // ipv6_data
  XMLElement* ipv6 = doc.NewElement("ipv6_data");
  elem0->InsertEndChild(ipv6);
  XMLElement* ipv6_data = doc.NewElement("class_data");
  ipv6_data->SetText(log_data.ipv6_data.class_data.c_str());
  ipv6->InsertEndChild(ipv6_data);

  ipv6_data = doc.NewElement("flow_label");
  ipv6_data->SetText(log_data.ipv6_data.flow_label.c_str());
  ipv6->InsertEndChild(ipv6_data);

  // protocol TCP
  XMLElement* proto_tcp = doc.NewElement("proto_tcp");
  elem0->InsertEndChild(proto_tcp);
  XMLElement* ptcp_data = doc.NewElement("flags");
  ptcp_data->SetText(log_data.tcp.flags.c_str());
  proto_tcp->InsertEndChild(ptcp_data);

  ptcp_data = doc.NewElement("seq");
  if (!log_data.tcp.seq_s.empty()) {
    ptcp_data->SetText(log_data.tcp.seq_s.c_str());
  } else {
    ptcp_data->SetText(log_data.tcp.seq);
  }
  proto_tcp->InsertEndChild(ptcp_data);

  ptcp_data = doc.NewElement("ack");
  ptcp_data->SetText(log_data.tcp.ack);
  proto_tcp->InsertEndChild(ptcp_data);

  ptcp_data = doc.NewElement("window");
  ptcp_data->SetText(log_data.tcp.window);
  proto_tcp->InsertEndChild(ptcp_data);

  ptcp_data = doc.NewElement("urg");
  ptcp_data->SetText(log_data.tcp.urg);
  proto_tcp->InsertEndChild(ptcp_data);

  ptcp_data = doc.NewElement("options");
  ptcp_data->SetText(log_data.tcp.options.c_str());
  proto_tcp->InsertEndChild(ptcp_data);

  // protocol ICMP
  XMLElement* proto_icmp = doc.NewElement("proto_icmp");
  elem0->InsertEndChild(proto_icmp);
  XMLElement* picmp_data = doc.NewElement("type");
  picmp_data->SetText(log_data.icmp.type.c_str());
  proto_icmp->InsertEndChild(picmp_data);

  picmp_data = doc.NewElement("echo_type");
  picmp_data->SetText(log_data.icmp.echo_type.c_str());
  proto_icmp->InsertEndChild(picmp_data);

  picmp_data = doc.NewElement("id");
  picmp_data->SetText(log_data.icmp.id);
  proto_icmp->InsertEndChild(picmp_data);

  picmp_data = doc.NewElement("seq");
  picmp_data->SetText(log_data.icmp.seq);
  proto_icmp->InsertEndChild(picmp_data);

  picmp_data = doc.NewElement("src_addr");
  picmp_data->SetText(log_data.icmp.src_addr.c_str());
  proto_icmp->InsertEndChild(picmp_data);

  picmp_data = doc.NewElement("dst_addr");
  picmp_data->SetText(log_data.icmp.dst_addr.c_str());
  proto_icmp->InsertEndChild(picmp_data);

  picmp_data = doc.NewElement("proto_id");
  picmp_data->SetText(log_data.icmp.proto_id);
  proto_icmp->InsertEndChild(picmp_data);

  picmp_data = doc.NewElement("descr");
  picmp_data->SetText(log_data.icmp.descr.c_str());
  proto_icmp->InsertEndChild(picmp_data);

  picmp_data = doc.NewElement("mtu");
  picmp_data->SetText(log_data.icmp.mtu);
  proto_icmp->InsertEndChild(picmp_data);

  picmp_data = doc.NewElement("otime");
  picmp_data->SetText(log_data.icmp.otime);
  proto_icmp->InsertEndChild(picmp_data);

  picmp_data = doc.NewElement("rtime");
  picmp_data->SetText(log_data.icmp.rtime);
  proto_icmp->InsertEndChild(picmp_data);

  picmp_data = doc.NewElement("ttime");
  picmp_data->SetText(log_data.icmp.ttime);
  proto_icmp->InsertEndChild(picmp_data);

  // protocol IGMP
  XMLElement* proto_igmp = doc.NewElement("proto_igmp");
  elem0->InsertEndChild(proto_igmp);
  XMLElement* pigmp_data = doc.NewElement("src");
  pigmp_data->SetText(log_data.igmp.src.c_str());
  proto_igmp->InsertEndChild(pigmp_data);

  pigmp_data = doc.NewElement("dst");
  pigmp_data->SetText(log_data.igmp.dst.c_str());
  proto_igmp->InsertEndChild(pigmp_data);

  // protocol CARP
  XMLElement* proto_carp = doc.NewElement("proto_carp");
  elem0->InsertEndChild(proto_carp);
  XMLElement* pcarp_data = doc.NewElement("type");
  pcarp_data->SetText(log_data.carp.type.c_str());
  proto_carp->InsertEndChild(pcarp_data);

  pcarp_data = doc.NewElement("ttl");
  pcarp_data->SetText(log_data.carp.ttl);
  proto_carp->InsertEndChild(pcarp_data);

  pcarp_data = doc.NewElement("vhid");
  pcarp_data->SetText(log_data.carp.vhid);
  proto_carp->InsertEndChild(pcarp_data);

  pcarp_data = doc.NewElement("version");
  pcarp_data->SetText(log_data.carp.version);
  proto_carp->InsertEndChild(pcarp_data);

  pcarp_data = doc.NewElement("advbase");
  pcarp_data->SetText(log_data.carp.advbase);
  proto_carp->InsertEndChild(pcarp_data);

  pcarp_data = doc.NewElement("advskew");
  pcarp_data->SetText(log_data.carp.advskew);
  proto_carp->InsertEndChild(pcarp_data);
}

} // namespace pflogentry
