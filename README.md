## PFLogentry
Instead of creating a complete program to analyze the PFSense(tm) log files I found it more convenient for my needs to create a small library of objects able to interpret the log entries and from there allow the manipulation of this data.
This is not a generic library and has not been tested in environments other than the one used in its development.

<b>PFLogentry</b> was coded entirely in C++.<br>
As I consider QtCreator(tm) to be an excellent development environment,<br>
I use it for my projects, even if these don't directly involve using the Qt(tm) tools.

### Dependencies for Compilation:
- g++ which meets the c++17.<br>
- tinyxml2-7.0.1

### My Environment
- Fedora 35<br>
- gcc (GCC) 11.2.1 20210728 (Red Hat 11.2.1-1)<br>
(Under Oracle Linux 8 install gcc-devtool-10 or 8.5 install gcc-devtool-11)<br>
- cmake version 3.22.0<br>
- QtCreator 6.0.x (Code Style: clang-format -style=Mozilla)

### Basic Operations

- Loads entire log file into memory;
- Check that the log entries are with the correct format;
- Allows counting of log entries given a condition.<br>
For example:<br> cnt->count(PFLogentry::HdrDay).betweenAND(20,30);<br>
Returns the total of entries read that are between the 20th and the 30th inclusive.
- Allows query of log entries given a condition.<br>
- Allows the summarization of information from log entries generating reports.<br>
- Allows export of log entries to a XML file format.<br>
