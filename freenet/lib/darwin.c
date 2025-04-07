#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/kern_event.h>
#include <sys/socket.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <ctype.h>
#include <fcntl.h>


#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#define UTUN_OPT_IFNAME 2

int open_tun_socket () {
  struct sockaddr_ctl addr;
  struct ctl_info info;
  char ifname[20];
  socklen_t ifname_len = sizeof(ifname);
  int fd = -1;
  int err = 0;

  fd = socket (PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
  if (fd < 0) return fd;

  bzero(&info, sizeof (info));
  strncpy(info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);

  err = ioctl(fd, CTLIOCGINFO, &info);
  if (err != 0) goto on_error;

  addr.sc_len = sizeof(addr);
  addr.sc_family = AF_SYSTEM;
  addr.ss_sysaddr = AF_SYS_CONTROL;
  addr.sc_id = info.ctl_id;
  addr.sc_unit = 0;

  err = connect(fd, (struct sockaddr *)&addr, sizeof (addr));
  if (err != 0) goto on_error;

  // TODO: forward ifname (we just expect it to be utun0 for now...)
  err = getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len);
  if (err != 0) goto on_error;

  printf("%s\r\n",ifname);

  // There is to close the socket,But in this case I don't need it.
  //err = fcntl(fd, F_SETFL, O_NONBLOCK);
  //if (err != 0) goto on_error;

  //fcntl(fd, F_SETFD, FD_CLOEXEC);
  //if (err != 0) goto on_error;

on_error:
  if (err != 0) {
    close(fd);
    return err;
  }

  return fd;
}