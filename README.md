yum install fuse-devel
gcc -Wall fuse_mmap.c pkg-config fuse --cflags --libs -o fuse_mmap
mkdir /tmp/fuse
./fuse_mmap /tmp/fuse
