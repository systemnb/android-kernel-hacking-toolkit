#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#define HIDEPROC_IOC_MAGIC 'H'
#define HIDEPROC_SETPID _IOW(HIDEPROC_IOC_MAGIC, 1, pid_t)

int main(int argc, char *argv[])
{
    int fd;
    pid_t pid;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid_to_protect>\n", argv[0]);
        return 1;
    }

    pid = atoi(argv[1]);

    fd = open("/dev/hideproc", O_RDWR);
    if (fd < 0) {
        perror("open /dev/hideproc");
        return 1;
    }

    if (ioctl(fd, HIDEPROC_SETPID, &pid) < 0) {
        perror("ioctl");
        close(fd);
        return 1;
    }

    printf("Protected PID %d set. The process is now hidden and protected.\n", pid);
    close(fd);
    return 0;
}