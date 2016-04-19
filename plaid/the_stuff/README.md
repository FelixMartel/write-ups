You start with `the_stuff.pcapng`.

```
$ files the_stuff.pcapng
the_stuff.pcapng: pcap-ng capture file - version 1.0
```

Look, it's a packet capture file. You could (and probably should) use a fancy software to read it but instead you do

```
$ sudo tcpdump -qns 0 -A -r the_stuff.pcapng > the_stuff.pcap
$ cat the_stuff.pcap | grep -A 270 flag > flag.base64
```

and use some find and replace file editor magic to obtain `flag.base64`

Success?

```
$ cat flag.base64 | base64 --decode > flag.zip
$ unzip flag.zip
Archive:  flag.zip
[flag.zip] flag.jpg password: 
```

Nope. Time to look again in the packet capture file

```
$ grep password the_stuff.pcap
Yo, you'll need this too: super_password1
```

Cool beans.

![flag](flag.jpg)
