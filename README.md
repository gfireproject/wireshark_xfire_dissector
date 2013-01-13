wireshark_xfire_dissector
=========================

Xfire dissector plugin for the Wireshark network traffic analyzer.

How to use it:

1. Copy the xfire directory into the plugins directory of the wireshark source (src)
2. Add "xfire" to the list of subdirectories in the (src)/plugins/Makefile.am
3. Add "plugins/xfire/Makefile" to the configure.ac in (src) (at AC_CONFIG_FILES; right after the other plugin Makefiles)
4. run autogen.sh in (src)
5. run configure with the required prefix and libdir (the ones of your current wireshark installation)
6. cd into (src)/plugins/xfire
7. run make
8. run sudo make install

Have fun with the Xfire protocol dissector plugin :)
