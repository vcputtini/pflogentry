#include <iostream>

#include <pflogentry.h>  // Mandatory
using namespace pflogentry; // Mandatory

/*
 * Compile:
 * g++ -Wall -O2 -std=c++17 -lpflogentry -ltinyxml2 -pthread ex-query.cc -o
 * ex-query
 * Usage: cat filter.log | ./ex-query
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

  PFQuery* q = new PFQuery(pfl);

  // Given a condition, test its validity.
  // e.g:
  // q->exists(PFLogentry::IpSrcAdd, PFLogentry::EQ, "172.16.50.0") ? 1 : 0;
  // q->exists(PFLogentry::RuleNumber, PFLogentry::EQ, 101015) ? 1 : 0;
  // q->exists(PFLogentry::HdrMonth, PFLogentry::LT, 10) ? 1 : 0;
  if (q->exists(PFLogentry::HostName, PFLogentry::EQ, "pfsense-1")) {
    std::cout << "Exists\n";
  } else {
    std::cout << "Not Exists\n";
  }

  //
  q->select("2021-07-08", "10:10:00")
    .field(PFLogentry::IpSrcAddr, PFLogentry::EQ, "10.0.16.20");

  // Returns the total number of valid entries read.
  // Only returns some value if used after a select().
  std::cout << "Qty selected entries  = " << q->size() << "\n";

  q->select("2021-07-08", "10:10:00", "2021-07-08", "10:10:10")
    .field(PFLogentry::IpSrcAddr, PFLogentry::EQ, "10.0.16.20");
  std::cout << "Qty selected entries  = " << q->size() << "\n";

  // Viewing data fields

  /*
   All field data retrieval functions have two arguments, as follows:

   Index:
     Since the select() function returns an array in which each element is a
     complete entry, each of them can be accessed by its index. The index value
     starts at 0 and goes up to the value returned by the size()-1 function.
     If only one registry entry is selected, the value of size() will be
     equal to 1, but its index will be 0.
     In case of error in the information of the vector index an error value
     will be informed.
     In the case of numerical values, the maximum value for this data type
     defined in <climits> will be returned. In the case of text fields the
     constant PFLogentry::invalidText will be returned.

   Field ID:
  */
  int ii = q->getInt(0, PFLogentry::SrcPort);
  if( q->isValidResult(ii) ) {
    std::cout << "Index Out of range\n";
  } else {
    std::cout << ii << "\n";
  }


  long ll = q->getLong(0, PFLogentry::RuleNumber);
  if( q->isValidResult(ll) ) {
    std::cout << "Index Out of range\n";
  } else {
    std::cout << ll << "\n";
  }

  uint32_t ui = q->getUint(0, PFLogentry::IcmpOTime);
  if( q->isValidResult(ui) ) {
    std::cout << "Index Out of range\n";
  } else {
    std::cout << ui << "\n";
  }

  std::string str = q->getText(0, PFLogentry::RealIFace);
  if( q->isValidResult(str) ) {
    std::cout << "Index Out of range\n";
  } else {
    std::cout << str << "\n";
  }

  std::cout << "Report\n";
  for(size_t i = 0; i != q->size(); i++) {
      int ii = q->getInt(i, PFLogentry::SrcPort);
      if (ii == INT_MAX) { // defined in <climits>
        std::cout << "Index Out of range\n";
      } else {
        std::cout << "Source Port = " << ii; // << "\n";
      }
      std::string str = q->getText(i, PFLogentry::RealIFace);
      if (str == PFLogentry::invalidText) {
        std::cout << "Index Out of range\n";
      } else {
        std::cout << " Real InterFace = " << str << "\n";
      }
  }

  delete q;
  delete pfl;

  return 0;
}
