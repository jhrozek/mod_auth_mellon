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

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <apr_global_mutex.h>
#include <apr_strings.h>
#include <apr_lib.h>
#include <http_log.h>

AP_DECLARE(apr_status_t) ap_unixd_set_global_mutex_perms(apr_global_mutex_t *gmutex)
{
    return 0;
}

AP_DECLARE(char *) ap_construct_url(apr_pool_t *p, const char *uri,
                                    request_rec *r)
{
    return apr_pstrcat(p, "https", "://", "www.example.com", uri, NULL);
}

AP_DECLARE(long) ap_get_client_block(request_rec * r, char * buffer,
                                     apr_size_t bufsiz)
{
    return 0;
}

AP_DECLARE(int) ap_setup_client_block(request_rec *r, int read_policy)
{
    return 0;
}

AP_DECLARE(int) ap_should_client_block(request_rec *r)
{
    return 0;
}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
AP_DECLARE(void) ap_log_error_(const char *file, int line, int module_index,
                               int level, apr_status_t status, const server_rec *s,
                               const char *fmt, ...)
{
#else
AP_DECLARE(void) ap_log_error(const char *file, int line, int level,
                              apr_status_t status, const server_rec *s,
                              const char *fmt, ...)
{
#endif
}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
AP_DECLARE(void) ap_log_rerror_(const char *file, int line, int module_index,
                                int level, apr_status_t status, const request_rec *r,
                                const char *fmt, ...)
{
#else
AP_DECLARE(void) ap_log_rerror(const char *file, int line, int level,
                               apr_status_t status, const request_rec *r,
                               const char *fmt, ...) {
#endif
    if (level < APLOG_DEBUG) {
        fprintf(stderr, "%s:%d [%d] [%d] ", file, line, level, status);
        va_list ap;
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fprintf(stderr, "\n");
    }
}

AP_DECLARE(const char *) ap_get_server_name(request_rec *r)
{
    return "www.example.com";
}

AP_DECLARE(void) ap_set_content_type(request_rec *r, const char *ct)
{
}

AP_DECLARE_NONSTD(const char *) ap_set_flag_slot(cmd_parms *cmd,
                                                 void *struct_ptr,
                                                 int arg)
{
    return "";
}

AP_DECLARE_NONSTD(const char *) ap_set_string_slot(cmd_parms *cmd,
                                                   void *struct_ptr,
                                                   const char *arg)
{
    return "";
}

AP_DECLARE_NONSTD(const char *) ap_set_int_slot(cmd_parms *cmd,
                                                void *struct_ptr,
                                                const char *arg)
{
    return "";
}

AP_DECLARE(char *) ap_strcasestr(const char *s1, const char *s2)
{
    return NULL;
}

AP_DECLARE(int) ap_regexec(const ap_regex_t *preg, const char *string,
                           apr_size_t nmatch, ap_regmatch_t *pmatch,
                           int eflags)
{
    return 0;
}

AP_DECLARE(ap_regex_t *) ap_pregcomp(apr_pool_t *p, const char *pattern,
                                     int cflags)
{
    return NULL;
}

AP_DECLARE(int) ap_unescape_url(char *url)
{
    return 0;
}

AP_DECLARE(int) ap_rwrite(const void *buf, int nbyte, request_rec *r)
{
    return 0;
}

AP_DECLARE(char *) ap_getword_conf(apr_pool_t *p, const char **line)
{
    return NULL;
}

AP_DECLARE_NONSTD(const char *) ap_set_file_slot(cmd_parms *cmd,
                                                 void *struct_ptr,
                                                 const char *arg)
{
    return NULL;
}

AP_DECLARE(char *) ap_server_root_relative(apr_pool_t *p, const char *file)
{
    return NULL;
}

AP_DECLARE(void) ap_hook_handler(int (*handler)(request_rec *r),
                                 const char * const *aszPre,
                                 const char * const *aszSucc,
                                 int nOrder)
{
}

AP_DECLARE(void) ap_hook_create_request(int (*handler)(request_rec *r),
                                        const char * const *aszPre,
                                        const char * const *aszSucc,
                                        int nOrder)
{
}

AP_DECLARE(void) ap_hook_child_init(ap_HOOK_child_init_t *pf, const char * const *aszPre, const char * const *aszSucc, int nOrder)
{
}

AP_DECLARE(void) ap_hook_post_config(ap_HOOK_post_config_t *pf,
                                     const char * const *aszPre,
                                     const char * const *aszSucc,
                                     int nOrder)
{
}

AP_DECLARE(void) ap_hook_check_user_id(int (*handler)(request_rec *r),
                                        const char * const *aszPre,
                                        const char * const *aszSucc,
                                        int nOrder)
{
}

AP_DECLARE(void) ap_hook_access_checker(int (*handler)(request_rec *r),
                                        const char * const *aszPre,
                                        const char * const *aszSucc,
                                        int nOrder)
{
}
