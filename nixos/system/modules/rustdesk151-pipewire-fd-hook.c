/* RustDesk 1.5.1: share a KDE ScreenCast grant, not the same PipeWire
 * socket between independent GStreamer pipelines. Keep AppRun's unsafe
 * execvp interposer disabled; intercept only GstPipeWireSrc.fd when enabled.
 * Exact behavior verified in the two-monitor capture probe on 2026-11-07.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef struct {unsigned long g_type;} MinimalGTypeClass;
typedef struct {const MinimalGTypeClass *g_class;} MinimalGTypeInstance;
typedef void (*SetProperty)(void*,const char*,const void*);
typedef const char* (*GetTypeName)(unsigned long);
static pthread_once_t once=PTHREAD_ONCE_INIT;
static SetProperty next_set=NULL;
static GetTypeName name_of=NULL;
static void resolve(void) {
    next_set=(SetProperty)dlsym(RTLD_NEXT,"g_object_set_property");
    name_of=(GetTypeName)dlsym(RTLD_DEFAULT,"g_type_name");
}
void g_object_set_property(void *object,const char *property,const void *value) {
    pthread_once(&once,resolve);
    const char *enabled=getenv("RUSTDESK_PIPEWIRE_SYSTEM_SOCKET");
    if(enabled && enabled[0]=='1' && enabled[1]=='\0' &&
       property && !strcmp(property,"fd") && object && name_of) {
        const MinimalGTypeInstance *o=(const MinimalGTypeInstance*)object;
        if(o->g_class) {
            const char *kind=name_of(o->g_class->g_type);
            if(kind && !strcmp(kind,"GstPipeWireSrc")) {
                static int notified=0;
                if(!__atomic_exchange_n(&notified,1,__ATOMIC_RELAXED)) {
                    static const char note[]="rustdesk-pipewire: independent session PipeWire connection enabled\\n";
                    (void)write(2,note,sizeof(note)-1);
                }
                return;
            }
        }
    }
    if(next_set)next_set(object,property,value);
}
