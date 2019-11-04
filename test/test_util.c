/*
 * This file was heavily based by tests of mod_auth_openidc, which is licensed
 * using APL 2.0. See LICENSE_APL2.0.txt for the full license text. The original
 * file contained the following notice:
 *
 * Copyright (C) 2017-2019 ZmartZone IAM
 * Copyright (C) 2013-2017 Ping Identity Corporation
 * All rights reserved.
 *
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
 *
 * DISCLAIMER OF WARRANTIES:
 *
 * THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
 * ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
 * WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
 * WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
 * USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
 * YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
 * WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 *
 */

#include <stdio.h>
#include <errno.h>

#include "apr.h"
#include "apr_errno.h"
#include "apr_general.h"
#include "apr_time.h"
#include "apr_base64.h"

#include "auth_mellon.h"

extern module AP_MODULE_DECLARE_DATA auth_mellon_module;

static request_rec *test_setup(apr_pool_t *pool)
{
    am_dir_cfg_rec *dir = auth_mellon_dir_config(pool, NULL);

    auth_mellon_module.module_index = 0;

    request_rec *request = (request_rec *) apr_pcalloc(pool, sizeof(request_rec));

    request->pool = pool;

    request->headers_in = apr_table_make(request->pool, 0);
    request->headers_out = apr_table_make(request->pool, 0);
    request->err_headers_out = apr_table_make(request->pool, 0);

    request->server = apr_pcalloc(request->pool, sizeof(struct server_rec));
    request->server->process = apr_pcalloc(request->pool,
                                           sizeof(struct process_rec));
    request->server->process->pool = request->pool;
    request->connection = apr_pcalloc(request->pool,
                                      sizeof(struct conn_rec));
    request->connection->bucket_alloc = apr_bucket_alloc_create(request->pool);
    request->connection->local_addr = apr_pcalloc(request->pool,
                                                  sizeof(apr_sockaddr_t));

    request->server = apr_pcalloc(request->pool, sizeof(struct server_rec));
    request->server->server_hostname = "www.example.com";
    request->per_dir_config = apr_pcalloc(request->pool,
                                          sizeof(ap_conf_vector_t *) * 2);
    ap_set_module_config(request->per_dir_config, &auth_mellon_module, dir);

    request->unparsed_uri = apr_pstrdup(pool, "/bla?foo=bar&param1=value1");

    return request;
}

static int test_am_validate_redirect_url(apr_pool_t *pool,
                                         request_rec *request)
{
    int ret;

    /* Positive test: hostname matches [self] */
    ret = am_validate_redirect_url(request,
                                   "http://www.example.com/some/page.html");
    if (ret != OK) return ret;

    /* Negative test: hostname does not match */
    ret = am_validate_redirect_url(request,
                                   "http://www.otherhost.com/some/page.html");
    if (ret == OK) return ret;

    /* Negative test: bad scheme */
    ret = am_validate_redirect_url(request,
                                   "ftp://www.otherhost.com/some/page.html");
    if (ret == OK) return ret;

    /* Negative test: scheme and path only */
    ret = am_validate_redirect_url(request,
                                   "http:www.malicious.com");
    if (ret == OK) return ret;

    /* Negative test: Relative path must begin with a single slash */
    ret = am_validate_redirect_url(request,
                                   "myapp/logout.html");
    if (ret == OK) return ret;

    /* OTOH, a single slash can be allowed */
    ret = am_validate_redirect_url(request, "/");
    if (ret != OK) return ret;

    /* OTOH, a single slash can be allowed */
    ret = am_validate_redirect_url(request, "/myapp/logout.html");
    if (ret != OK) return ret;

    /* Negative test: Relative path must not begin with a double slash */
    ret = am_validate_redirect_url(request,
                                   "//myapp/logout.html");
    if (ret == OK) return ret;

    return APR_SUCCESS;
}

int main(int argc, char **argv)
{
    apr_status_t ret;
    apr_pool_t *pool = NULL;
    request_rec *r = NULL;

    ret = apr_app_initialize(&argc, (const char * const **) argv, NULL);
    if (ret != APR_SUCCESS) {
        printf("apr_app_initialize failed\n");
        return 1;
    }

    ret = apr_pool_create(&pool, NULL);
    if (ret != APR_SUCCESS) {
        printf("apr_pool_create failed\n");
        return 1;
    }

    r = test_setup(pool);
    if (r == NULL) {
        printf("test_setup failed\n");
        return 1;
    }

    ret = test_am_validate_redirect_url(pool, r);
    if (ret != APR_SUCCESS) {
        printf("test_am_validate_redirect_url failed\n");
        return 1;
    }

    apr_pool_destroy(pool);
    apr_terminate();
    return 0;
}
