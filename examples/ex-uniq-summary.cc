#include <iostream>

#include <pflogentry.h>  // Mandatory
using namespace pflogentry; // Mandatory

/*
 * Compile:
 * g++ -Wall -O2 -std=c++17 -lpflogentry -ltinyxml2 -pthread ex-summary.cc -o
 * ex-summary
 * Usage: cat filter.log | ./ex-summary
 */

int
main()
{
  using PFLError = PFLogentry::PFLError;
  using LogFormat = PFLogentry::LogFormat;

  std::string raw_log{};

  /* When using the BSD log format (RFC-3164), we must enter the year as this
   * format does not include this information in the log line.
   * For the SysLog format (RFC-5424) this is not necessary. */

  PFLogentry *pfl = new PFLogentry(LogFormat::LogSyslog);
  //PFLogentry* pfl = new PFLogentry(LogFormat::LogBSD, 2021);
  while (std::getline(std::cin, raw_log)) {
    pfl->append(raw_log);
    if (pfl->errorNum() != PFLError::PFL_SUCCESS) {
      std::cout << ">>> " << pfl->getErrorText() << "\n";
      exit(255);
    }
  }

  PFLError err;
  PFSummary* s = new PFSummary(pfl);

  // Select all records that match the date and time informed.
  //err = s->setDateTime("2021-07-07", "10:10:00");
  // Select all records that match the date/time range informed.

  // rfc-BSD
  //err = s->setDateTime("2021-07-08","10:00:00","2021-07-08","18:00:00");

  // rfc-5424
  err = s->setDateTime("2021-11-29","00:00:00","2021-11-29","18:00:00");


  if (err != PFLError::PFL_SUCCESS) {
    std::cout << static_cast<int>(s->errorNum()) << " :  " << s->getErrorText() << "\n";
    return 1;
  }

  /* void setHostName(const std::string = std::string());
   *
   * e.g: s->setHostName();  // Clear hostname
   *      s->setHostName("pfsense-1");
   */
  //s->setHostName("pfsense-1.server1.com"); // RFC-5424
  //s->setHostName("pfsense-1");  // RFC-3164

  /* void setIfName(const std::string = std::string());
   *
   * e.g: s->setIfName();  // Clear hostname
   *      s->setIfName("re0) // must be real interface name
   */
  //s->setIfName();
  //s->setIfName("pppoe0");
  //s->setIfName("ovpns1");

  /*
   * Unique
   * void reportUnique(UniqueType uniq_ = UniqueType::Resume,
   *                 ProtoID id_ = ProtoID::ProtoTCP,
   *                IPVersion ipver_ = IPVersion::IPv4);
   */
  s->reportUnique();
  //s->reportUnique(PFSummary::UniqueType::Resume, PFLogentry::ProtoID::ProtoUDP);
  //s->reportUnique(PFSummary::UniqueType::Details);
  //s->reportUnique(PFSummary::UniqueType::Details, PFLogentry::ProtoID::ProtoUDP);

  delete s;
  delete pfl;

  return 0;
}
