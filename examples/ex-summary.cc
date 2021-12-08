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
   * For the SysLog format (RFC-5424) this is not necessary. 
   */

  // PFLogentry *pfl = new PFLogentry(LogFormat::LogSyslog);
  PFLogentry* pfl = new PFLogentry(LogFormat::LogBSD, 2021);
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
  err = s->setDateTime("2021-07-08", "10:10:08");
  // Select all records that match the date/time range informed.
  // err = s->setDateTime("2021-07-08","10:10:00","2021-07-08","10:58:58");
  if (err != PFLError::PFL_SUCCESS) {
    std::cout << static_cast<int>(s->errorNum()) << " :  " << s->getErrorText() << "\n";
    return 1;
  }

  /* void setHostName(const std::string = std::string());
   *
   * e.g: s->setHostName();  // Clear hostname
   *      s->setHostName("pfsense-1");
   */
  // s->setHostName();

  /* void setIfName(const std::string = std::string());
   *
   * e.g: s->setIfName();  // Clear hostname
   *      s->setIfName("re0) // must be real interface name
   */
  // s->setIfName();

  /*
   * void getGrandTotals();
   */
   s->getGrandTotals();

  /*  void protocol(ProtoID id_ = ProtoID::ProtoTCP,
   *            IPVersion ipver_ = IPVersion::IPv4);
   *
   * e.g:
   * s->protocol(); // TCP (defualt) & IPv4 (default).
   * s->Protocol(IPVersion::IPv6); // TCP (defualt) & IPv6.
   * or
   * s->protocol(ProtoUDP); // UDP & IPv4 (default)
   * s->protocol(ProtoUDP,IPVersion::IPv6); // UDP & IPv6.
   * or
   */
  s->protocol();

  /* Report Generator
   *
   * void setLinesPage(const int lp_ = 50);
   * e.g: s->setLinesPage();  // reset value
   * or
   * For instance: If you set the value to 64 and use Libreoffice Writer with
   * the following page layout, the report has the right page break:
   * Format: A4; Font: Libaration Mono - 10pt.
   * Margins: L/R/T/B: 0.79"
   * s->setLinesPage(64);
   *
   * void report(ProtoID id_ = ProtoID::ProtoTCP,
   *             IPVersion ipver_ = IPVersion::IPv4);
   * e.g: s->report();
   * or
   * s->report(ProtoID::ProtoTCP, IPVersion::IPv6);
   * or
   * s->report(ProtoID::ProtoUDP); // IPv4
   * or
   * s->report(ProtoID::ProtoTCP, IPVersion::IPv6);
   */
  // s->report();

  delete s;
  delete pfl;

  return 0;
}
