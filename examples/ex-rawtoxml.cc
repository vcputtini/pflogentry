#include <iostream>

#include <pflogentry.h>  // Mandatory
using namespace pflogentry; // Mandatory

/*
 * Compile:
 * g++ -Wall -O2 -std=c++17 -lpflogentry -ltinyxml2 -pthread ex-rawtoxml.cc -o
 * ex-rawtoxml
 * Usage: cat filter.log | ./ex-rawtoxml
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


/*
 * LOG_FORMAT == 0  -> LogSyslog
 * LOG_FORMAT == 1  -> Logbsd
 */ 
#define LOG_FORMAT 0
  
  std::cout << "Loading ...\n";
  PFLogentry::PFLError err;
  
#if LOG_FORMAT   
  PFLogentry* pfl = new PFLogentry(LogFormat::LogBSD, 2021);
#else  
  PFLogentry *pfl = new PFLogentry(LogFormat::LogSyslog);
#endif  
  
  while (std::getline(std::cin, raw_log)) {
    pfl->append(raw_log);
    if (pfl->errorNum() != PFLError::PFL_SUCCESS) {
      std::cout << ">>> " << pfl->getErrorText() << "\n";
      exit(255);
    }
  }

  std::cout << "Load size = " << pfl->size() << "\n";
  
  /*
   * PFLError toXML(const std::string&& fn_,
                  const std::string&& d0_,
                  const std::string&& t0_,
                  const std::string&& d1_,
                  const std::string&& t1_);
   */
  // Warning: all data in memory is erased after this operation.
  std::cout << "Converting ... \n";
  
  // All log entries:
  err = pfl->toXML("filter-log.xml");
  
  // Possible operations:
  // err = pfl->toXML("filter-log.xml","yyyy-mm-dd","hh:mm:ss","yyyy-mm-dd","hh:mm:ss");
  // All day:
  // err = pfl->toXML("filter-log.xml","2022-01-25","00:00:00","2022-01-25","23:59:59");
  // Time range:
  // err = pfl->toXML("filter-log.xml","2022-01-25","01:00:00","2022-01-25","02:30:00");
  
  if (err != PFLError::PFL_SUCCESS) {
    std::cout << static_cast<int>(pfl->errorNum()) << " :  "
    << pfl->getErrorText() << "\n";
    exit(255);
  }

  delete pfl;

  return 0;
}
