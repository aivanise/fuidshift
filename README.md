yet another version of fuidshift

the only reason why this exists is that it was faster 
to GPT^H^H^Hwrite it myself than to chase where did fuidshift binary go

it was/is used to fix botched id mapping in LXD, e.g.

https://discourse.ubuntu.com/t/botched-containers-after-experimenting-with-security-idmap-isolated/73057

run without parameters to see the syntax

./fuidshift.py 
Usage: [export DEBUG=yes]; ./fuidshift.py <directory> <offset>
  Example (LXD shift down): sudo ./fuidshift.py /var/lib/lxd/containers/mycontainer/rootfs -1000000
