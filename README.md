# Hydra 0.1.8
[![Total alerts](https://img.shields.io/lgtm/alerts/g/shrugly/hydra-0.1.8.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/shrugly/hydra-0.1.8/alerts/)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/shrugly/hydra-0.1.8.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/shrugly/hydra-0.1.8/context:cpp)
[![Build Status](https://travis-ci.org/shrugly/hydra-0.1.8.svg?branch=master)](https://travis-ci.org/shrugly/hydra-0.1.8)

[Hydra](http://hydra.hellug.gr/) is a lightweight, multithreaded HTTP(S) server based on [Boa](https://github.com/shrugly/boa-0.94.13) which is occasionally still found in embedded firmware images for serving CGI scripts, files, and more. 0.1.8 is the last stable version, and was released [in 2006](http://hydra.hellug.gr/download/).

## Known Vulnerabilities

### Fixed
- [CVE-2019-17502](https://www.cvedetails.com/cve/CVE-2019-17502/) - Discovered by [Felix Blanco](https://github.com/fxb6476): Hydra through 0.1.8 has a NULL pointer dereference & daemon crash when processing POST requests that lack a 'Content-Length' header. Links: [disclosure](https://gist.github.com/fxb6476/0b9883a88ff2ca40de46a8469834e16c). Notes: a CWE for this was issued by `flawfinder` but other SAST tooling did not detect it.

## Changes

This repository contains Hydra 0.1.8. It should not be considered meaningfully enhanced from the original source.

### Code

2020-05-09 - Fixed CVE-2019-17502, ref: [PR#1](https://github.com/shrugly/hydra-0.1.8/pull/1); clang-formatted messy source files, ref: [PR#2](https://github.com/shrugly/hydra-0.1.8/pull/2).

### Integrations

- [LGTM](https://lgtm.com/) - performs QL-based quality and security checks on the main repository as well as any PRs to help identify & track security hotspots.
- [Travis CI](https://travis-ci.org/) - builds Hydra on Linux and macOS with GCC & Clang to ensure that changes don't immediately introduce quality issues.

### security/*.txt

Some SAST tools are run manually on the latest version of this software to identify potential hotspots. Listed in increasing order of complexity, they are:
* [flawfinder](https://dwheeler.com/flawfinder/) - scans for potentially insecure functions being used in C programs.
* [cppcheck](http://cppcheck.sourceforge.net/) - performs flow sensitive analysis to check C/C++ code for undefined behavior.
* [infer](https://fbinfer.com/) - a modular verification and analysis engine that checks Java/C/Obj-C code for null pointer dereferences and resource or memory leaks.

Summary 2020-05-09: Hydra does not conform to modern, secure coding practices - which is expected - and has a number of potentially severe issues to investigate.

## SHRuG Creed

We apply security tools & processes to assist developers in determining if legacy software is the right choice for their application. Where reasonable we will attempt to upgrade the security, reliability, and quality of legacy software.

However, we are not volunteering to be new maintainers for this software. We will not develop new features or substantially change its functionality. Please report bugs that result in security problems to us using the [Issues](https://github.com/shrugly/hydra-0.1.8/issues) tab and we will look into fixing them. Other bugs, feature requests, usability issues, etc. will be largely ignored or closed without warning.

### Warranty & Liability

This work is licensed under the GNU GPLv2. This includes modifications by the SHRuG working group. In particular, we'd like to remind you of the "NO WARRANTY" section, as follows:

11. BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

12. IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.