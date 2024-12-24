/************************************ ***********************************
    > File Name: fuse_mmap.c
    > Author: sprookie
    > Created Time: 2024年12月23日 星期一 11时04分44秒
 ************************************************************************/

#define FUSE_USE_VERSION 26

#include <limits.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include "list.h"

#define PAGE_SIZE 4096
#define AK_MMAP_LEN (10 * 1024 * PAGE_SIZE)

struct file_node {
    mode_t mode;
    size_t size;
    struct list_head list;
    char name[NAME_MAX + 1];
    void *mapped;  
};

LIST_HEAD(fuse_files);

static int hello_getattr(const char *path, struct stat *stbuf)
{
    struct file_node *node;
    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = 0755 | S_IFDIR;
        stbuf->st_nlink = 2;
 
        list_for_each_entry (node, &fuse_files, list) {
            ++stbuf->st_nlink;
        }
 
        return 0;
    }
 
    list_for_each_entry (node, &fuse_files, list) {
        if (strcmp(path + 1, node->name) == 0) {
            stbuf->st_mode = node->mode;
            stbuf->st_nlink = 1;
	    stbuf->st_size = node->size;
            return 0;
        }
    }
 
    return -ENOENT;
}

static int hello_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
             off_t offset, struct fuse_file_info *fi)
{
    struct file_node *node;
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    
    list_for_each_entry(node, &fuse_files, list) {
        filler(buf, node->name, NULL, 0);
    }

    return 0;
}

static int hello_create(const char* path, mode_t mode, struct fuse_file_info* fi)
{
    struct file_node *node;
 
    if (strlen(path + 1) > NAME_MAX)
        return -ENAMETOOLONG;
 
    list_for_each_entry (node, &fuse_files, list) {
        if (strcmp(path + 1, node->name) == 0)
            return -EEXIST;
    }
 
    node = malloc(sizeof(*node));
    if (node == NULL) {
        return -ENOMEM;
    }
    
    node->mapped = mmap(NULL, AK_MMAP_LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (node->mapped == MAP_FAILED) {
        free(node);
        return -ENOMEM;
    }
    
    strcpy(node->name, path + 1);
    node->mode = mode;
    node->size = 1;
    list_add(&node->list, &fuse_files);

    return 0;
}

static int hello_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct file_node *node;
    list_for_each_entry(node, &fuse_files, list) {
        if (strcmp(node->name, path + 1) == 0) {
            if (offset < node->size) {
	        if (offset + size > node->size)
		    size = node->size - offset;
		memcpy(buf, node->mapped + offset, size);
	    } else {
		size = 0;
	    }
	}
    }
    
    return size;
}

static int hello_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct file_node *node;
    list_for_each_entry(node, &fuse_files, list) {
        if (strcmp(node->name, path + 1) == 0) {
            if (offset + size > node->size)
	        node->size = offset + size;
	    memcpy(node->mapped + offset, buf, size);
        }
    }

    return size;
}

static int hello_truncate(const char *path, off_t size) {
    struct file_node *node;
    list_for_each_entry(node, &fuse_files, list) {
        if (strcmp(node->name, path + 1) == 0) {
            if (size < node->size) {
                memset(node->mapped + size, 0, node->size - size);
            }
            node->size = size;
            return 0;
        }
    }
    
    return -ENOENT;
}

static int hello_unlink(const char *path) {
    struct file_node *node;
    list_for_each_entry(node, &fuse_files, list) {
        if (strcmp(node->name, path + 1) == 0) {
            list_del(&node->list);
            munmap(node->mapped, AK_MMAP_LEN);
            free(node);
            return 0;
        }
    }

    return -ENOENT;
}

static struct fuse_operations hello_oper = {
    .getattr    = hello_getattr,
    .readdir    = hello_readdir,
    .read       = hello_read,
    .create     = hello_create,
    .write      = hello_write,
    .truncate   = hello_truncate,
    .unlink     = hello_unlink,
};

int main(int argc, char *argv[])
{
    return fuse_main(argc, argv, &hello_oper, NULL);
}

