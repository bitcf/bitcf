Emercoin integration/staging tree
================================

http://emercoin.com

Copyright (c) 2009-2013 Bitcoin Developers
Copyright (c) 2013-2014 Emercoin Developers

What is Emercoin?
----------------

Emercoin is an experimental new digital currency that enables instant payments to
anyone, anywhere in the world. Emercoin uses peer-to-peer technology to operate
with no central authority: managing transactions and issuing money are carried
out collectively by the network. Emercoin is also the name of the open source
software which enables the use of this currency.

For more information, as well as an immediately useable, binary version of
the Emercoin client software, see http://emercoin.com.

License
-------

Emercoin is released under the terms of the MIT license AND GPL3 license. See `COPYING` for more
information or see http://www.gnu.org/licenses/gpl.html.

Development process
-------------------

Developers work in their own trees, then submit pull requests when they think
their feature or bug fix is ready.

The patch will be accepted if there is broad consensus that it is a good thing.
Developers should expect to rework and resubmit patches if the code doesn't
match the project's coding conventions (see `doc/coding.md`) or are
controversial.

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/EvgenijM86/emercoin/tags) are created
regularly to indicate new official, stable release versions of Emercoin.

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test. Please be patient and help out, and
remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write unit tests for new code, and to
submit new unit tests for old code.

Unit tests can be compiled and run (assuming they weren't disabled in configure) with:
  make check

### Manual Quality Assurance (QA) Testing

Large changes should have a test plan, and should be tested by somebody other
than the developer who wrote the code.

See https://github.com/bitcoin/QA/ for how to create a test plan.