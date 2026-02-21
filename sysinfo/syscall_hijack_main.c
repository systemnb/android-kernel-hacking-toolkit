#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <string.h>

#define IOC_MAGIC 'I'
#define SET_FAKE_SYSINFO _IOW(IOC_MAGIC, 1, struct sysinfo)

int main(int argc, char *argv[])
{
    int fd;
    struct sysinfo info;

    /* Construct a fake system info structure */
    memset(&info, 0, sizeof(info));
    info.uptime = 999999;           // uptime 999999 seconds
    info.totalram = 999ULL * 1024 * 1024 * 1024; // 999GB
    info.freeram = 800ULL * 1024 * 1024 * 1024;   // 800GB
    info.procs = 12345;               // number of processes

    fd = open("/dev/syscall_hijack_sysinfo", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    if (ioctl(fd, SET_FAKE_SYSINFO, &info) < 0) {
        perror("ioctl");
        close(fd);
        return 1;
    }

    printf("Fake sysinfo set. Try running a program that calls sysinfo() (e.g., free -m).\n");
    close(fd);
    return 0;
}