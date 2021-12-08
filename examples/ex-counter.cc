#include <iostream>

#include <pflogentry.h>  // Mandatory
using namespace pflogentry; // Mandatory

/*
 * Compile:
 * g++ -Wall -O2 -std=c++17 -lpflogentry -ltinyxml2 -pthread ex-counter.cc -o
 * ex-counter
 * Usage: cat filter.log | ./ex-counter
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

  // PFLogentry *pfl = new PFLogentry(PFLogentry::LogSyslog);
  PFLogentry* pfl = new PFLogentry(LogFormat::LogBSD, 2021);
  while (std::getline(std::cin, raw_log)) {
    pfl->append(raw_log);
    if (pfl->errorNum() != PFLError::PFL_SUCCESS) {
      std::cout << ">>> " << pfl->getErrorText() << "\n";
      exit(255);
    }
  }

  PFLogentry::PFLError err;

  /*
   * There are two possible ways to initialize the counter, as follows:
   *
   * All counting operations are applied only to the entered field.
   * PFCounter *cnt = new PFCounter(p, PFLogentry::Fields::HostName);
   * or
   * Counting operations are applied to all read inputs.
   * PFCounter *cnt = new PFCounter(pfl);
   */
  // PFCounter *cnt = new PFCounter(p, PFLogentry::Fields::HostName);
  PFCounter* cnt = new PFCounter(pfl);

  // Returns the total number of valid entries read.
  std::cout << "Size == " << cnt->size() << "\n";

  // Returns the count of entries valid on the chosen date/time.
  std::cout << "Equal == "
            << cnt->count(PFLogentry::HdrTimeStamp).eq("2021-10-22T07:05:26")
            << "\n";

  // Returns the count of entries valid on the chosen day of month.
  std::cout << "Equal == " << cnt->count(PFLogentry::HdrDay).eq(8) << "\n";

  // Returns the count of entries valid on the chosen month.
  std::cout << "Equal == " << cnt->count(PFLogentry::HdrMonth).eq(7) << "\n";

  // Returns the count of valid entries for a specific host.
  std::cout << "HostName == "
            << cnt->count(PFLogentry::HostName).eq("pfSense-1") << "\n";

  // Returns the count of valid entries for a given range.
  std::cout << "Between 8 AND 10 == "
            << cnt->count(PFLogentry::HdrDay).betweenAND(8, 10) << "\n";
  std::cout << "Between 8 OR 10 == "
            << cnt->count(PFLogentry::HdrDay).betweenOR(8, 10) << "\n";

  // Returns the count of valid entries greater than the field value.
  std::cout << "Grater than 20 " << cnt->count(PFLogentry::HdrDay).gt(20)
            << "\n";
  std::cout << "Greater than 09 " << cnt->count(PFLogentry::HdrMonth).gt(9)
            << "\n";

  // Returns the count of valid entries less than the field value.
  std::cout << "Less than 22 " << cnt->count(PFLogentry::HdrDay).lt(22) << "\n";
  std::cout << "Less than 10 " << cnt->count(PFLogentry::HdrMonth).lt(10)
            << "\n";

  delete cnt;
  delete pfl;

  return 0;
}
