nbesort.rb
==========

nbesort.rb is a simple tool designed to sort Nessus findings by finding, rather
than by IP. It is a simple *nix utility (tested on Linux, BSD, and OS X) that
will parse through an NBE file and spit the results out to stdout. This has been
very helpful for us during client engagements.

A typical use of nbesort.rb looks something like this:

`ruby nbesort.rb client.nbe > client_findings.txt`

From here, it is very easy to simply go through the .txt output to find which
findings may be relevant, and which are not. Many security professionals are not
huge fans of the new-ish Flash/FLEX interface of Nessus, so this has been a
welcome tool for much of the community.

Thanks for your interest!
