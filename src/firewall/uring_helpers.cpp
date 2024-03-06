
#include "uring_helpers.h"
#include "util.h"

/******************************************************************************
 ************************** INTERNAL DATA STRUCTURES **************************
 ******************************************************************************/

static struct io_uring ring;    /* ring object */

/******************************************************************************
 ************************** PUBLIC API IMPLEMENTATION *************************
 ******************************************************************************/

/* uring_init - initialize an io_uring with kthread polling
 *  @entries     : queue depth
 *  @thread_idle : timeout interval for kthread [ms]
 *
 *  @return : ptr to the ring structure; NULL on error
 */
struct io_uring *
uring_init(uint32_t entries, uint32_t thread_idle)
{
    struct io_uring_params params;      /* uring creation parameters */
    int32_t                ans;         /* answer                    */

    /* prepare io_uring arguments */
    memset(&params, 0, sizeof(params));
    params.flags |= IORING_SETUP_SQPOLL;
    params.flags |= IORING_FEAT_SQPOLL_NONFIXED;
    params.sq_thread_idle = thread_idle;

    /* initialize io_uring parameters */
    ans = io_uring_queue_init_params(entries, &ring, &params);
    RET(ans, NULL, "unable to initialize io_uring (%s)", strerror(-ans));

    return &ring;
}

/* uring_deinit - cleanup function
 */
void
uring_deinit(void)
{
    io_uring_queue_exit(&ring);
}


/* uring_add_read_request - wrapper over read() syscall
 *  @marker : identifier matched in completion queue entry
 *  @fd     : file descriptor
 *  @buf    : destination buffer
 *  @nbytes : bytes to read
 *
 *  @return : >0 if everything went well, -errno otherwise
 */
int32_t
uring_add_read_request(uint64_t marker,
                       int32_t  fd,
                       void     *buf,
                       uint32_t nbytes)
{
    struct io_uring_sqe *sqe;   /* submission queue entry */

    /* try to get an entry in the submission queue */
    sqe = io_uring_get_sqe(&ring);
    RET(!sqe, -ENOBUFS, "unable to reserve SQE; increase ring size");

    /* prepare the read() operation */
    io_uring_prep_read(sqe, fd, buf, nbytes, 0);
    io_uring_sqe_set_data(sqe, (void *) marker);
    return io_uring_submit(&ring);
}

/* uring_add_write_request - wrapper over write() syscall
 *  @marker : identifier matched in completion queue entry
 *  @fd     : file descriptor
 *  @buf    : source buffer
 *  @nbytes : bytes to write
 *
 *  @return : >0 if everything went well, -errno otherwise
 */
int32_t
uring_add_write_request(uint64_t marker,
                       int32_t  fd,
                       void     *buf,
                       uint32_t nbytes)
{
    struct io_uring_sqe *sqe;   /* submission queue entry */

    /* try to get an entry in the submission queue */
    sqe = io_uring_get_sqe(&ring);
    RET(!sqe, -ENOBUFS, "unable to reserve SQE; increase ring size");

    /* prepare the write() operation */
    io_uring_prep_write(sqe, fd, buf, nbytes, 0);
    io_uring_sqe_set_data(sqe, (void *) marker);
    return io_uring_submit(&ring);
}

/* uring_add_poll_request - wrapper over poll() syscall
 *  @marker    : identifier matched in completion queue entry
 *  @fd        : file descriptor
 *  @poll_mask : poll event mask
 *
 *  @return : >0 if everything went well, -errno otherwise
 */
int32_t
uring_add_poll_request(uint64_t marker,
                       int32_t  fd,
                       uint32_t poll_mask)
{
    struct io_uring_sqe *sqe;   /* submission queue entry */

    /* try to get an entry in the submission queue */
    sqe = io_uring_get_sqe(&ring);
    RET(!sqe, -ENOBUFS, "unable to reserve SQE; increase ring size");

    /* prepare the poll() operation */
    io_uring_prep_poll_add(sqe, fd, poll_mask);
    io_uring_sqe_set_data(sqe, (void *) marker);
    return io_uring_submit(&ring);
}

/* uring_add_poll_request - wrapper over accept() syscall
 *  @marker          : identifier matched in completion queue entry
 *  @fd              : file descriptor
 *  @client_addr     : connecting client address destination buffer
 *  @client_addr_len : length of client information
 *
 *  @return : >0 if everything went well, -errno otherwise
 */
int32_t
uring_add_accept_request(uint64_t           marker,
                         int32_t            fd,
                         struct sockaddr_in *client_addr,
                         socklen_t          *client_addr_len)
{
    struct io_uring_sqe *sqe;   /* submission queue entry */

    /* try to get an entry in the submission queue */
    sqe = io_uring_get_sqe(&ring);
    RET(!sqe, -ENOBUFS, "unable to reserve SQE; increase ring size");

    /* prepare the accept() operation */
    io_uring_prep_accept(sqe, fd, (struct sockaddr *) client_addr,
                         client_addr_len, 0);
    io_uring_sqe_set_data(sqe, (void *) marker);
    return io_uring_submit(&ring);
}

/* uring_add_close_request - wrapper over close() syscall
 *  @marker : identifier matched in completion queue entry
 *  @fd     : file descriptor
 *
 *  @return : >0 if everything went well, -errno otherwise
 */
int32_t
uring_add_close_request(uint64_t marker,
                        int32_t  fd)
{
    struct io_uring_sqe *sqe;   /* submission queue entry */

    /* try to get an entry in the submission queue */
    sqe = io_uring_get_sqe(&ring);
    RET(!sqe, -ENOBUFS, "unable to reserve SQE; increase ring size");

    /* prepare the close() operation */
    io_uring_prep_close(sqe, fd);
    io_uring_sqe_set_data(sqe, (void *) marker);
    return io_uring_submit(&ring);
}

