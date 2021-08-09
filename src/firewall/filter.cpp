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
    int32_t  us_dsock_fd;   /* unix data socket      */
    uint8_t  buff[512];     /* client request buffer */
    uint16_t ctl_flags;     /* controller request flags */ 
    ssize_t  rb, wb;        /* read / written bytes  */
    int32_t  ans;           /* answer                */

    /* accept new connection */
    us_dsock_fd = accept(us_csock_fd, NULL, NULL);
    RET(us_dsock_fd == -1, -1, "unable to accept new connection (%s)",
        strerror(errno));
    
    /* read request from client */
    rb = read(us_dsock_fd, buff, sizeof(buff));
    GOTO(rb == -1, clean_data_socket,
        "unable to read data from client (%s)", strerror(errno));

    /* extract ctl request flags and treat each case */
    ctl_flags = *((uint16_t *) buff);
    switch (ctl_flags) {
        case CTL_LIST:
            break;
        case CTL_INSERT:
            break;
        case CTL_APPEND:
            break;
        case CTL_DELETE:
            break;

        default:
            GOTO(1, clean_data_socket, "unkown client request code %04hx",
                ctl_flags);
    }

clean_data_socket:
    /* close data socket */
    ans = close(us_dsock_fd);
    ALERT(ans == -1, "failed to close ctl data socket (%s)", strerror(errno));

    return 0;
}
