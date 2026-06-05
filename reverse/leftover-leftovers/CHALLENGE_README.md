# What to do?

1. Go inside the handout folder
2. Run `./exec.sh leftovers2.jar cache.aot my-jdk` (where `outer-cache.aot` is expected next to `cache.aot`)
3. Have fun :)    (required)

## Alternatively
1. Build the JDK
   ```
   git clone https://github.com/openjdk/jdk/
   cd jdk
   git checkout 35b0de3d4d4e8212227af5462fafbd464103f058
   bash configure --with-debug-level=fastdebug --with-extra-cflags="-Wno-discarded-qualifiers"
   make images CONF=linux-x86_64-server-fastdebug
   ```
2. Same as above, but use `jdk/build/linux-x86_64-server-fastdebug/images/jdk` as jdk
