## Exe infector

# Overview

x86_64 pe infector, it will infect a pe executable with another pe executable.  
It will compress it and add it in the infected executable (in a new section along with a decompression payload)  
When launched, the infected executable will decompress it, then write it on disk and do a CreateProcess on it.  
Then the original executable will run itself.  

# Build

example:

```sh
  $ make
  $ ./bin/x86_64/injector.exe
  Usage: <path_to_inject> <exe_to_inject>
```

# Credits

credits to zlite:
https://github.com/torinkwok/zlite

# TODO

- x86
