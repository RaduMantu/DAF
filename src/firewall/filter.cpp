#include <unistd.h>         /* read, close */
#include <sys/socket.h>     /* accept      */

#include "filter.h"
#include "util.h"

/* flt_handle_ctl - handles request by user's rule manager
 *  @us_csock_fd : unix connect socket
 *
 *  @return : 0 if everything went ok
 *
 * NOTE: not adding data socket to any epoll instance
 *       call to this function is blocking
 *
 * TODO: add client authentication
 */
int flt_handle_ctl(int32_t us_csock_fd)
{
    int32_t us_dsock_fd;    /* unix data socket      */
    uint8_t buff[512];      /* client request buffer */
    ssize_t rb, wb;         /* read / written bytes  */
    int32_t ans;            /* answer                */

    /* accept new connection */
    us_dsock_fd = accept(us_csock_fd, NULL, NULL);
    RET(us_dsock_fd == -1, -1, "unable to accept new connection (%s)",
        strerror(errno));
    
    /* read request from client */
    rb = read(us_dsock_fd, buff, sizeof(buff));

    /* TODO: implement ctl logic*/

    /* close data socket */
    close(us_dsock_fd);

    return 0;
}
