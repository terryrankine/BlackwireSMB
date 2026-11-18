/* SPDX-License-Identifier: GPL-3.0-or-later
 * Scriptable API: Send by title ID, settings-bound catalog reuse and
 * GET /api/log, through the actual backend handlers and workers. Discovery
 * and preparation are spies; the maintained Play fixture supplies the rest. */
#define main unused_preparation_fixture_main
#include "../dashboard/lifecycle/test_play_preparation_failure.c"
#undef main
#define TOKEN "0123456789abcdef0123456789abcdef"
#define PASSWORD "pw-never-logged-7d1f"
int bw_native_setup_config_valid(const struct bw_share_config *c){return c&&*c->server&&*c->share;}
static unsigned discovers,prepares,nonces;
static const struct bw_native_library *seen_reuse;
static char seen_only[10],prepared_source[1024],prepared_title[10];
static int with_image,second_folder;
static struct bw_setup_generation api_generation={.present=1};
static const char *api_server="192.0.2.1";
static int api_settings(void *p,struct bw_share_config *c,struct bw_setup_generation *g){
    CHECK(p==&owner);memset(c,0,sizeof *c);strcpy(c->server,api_server);strcpy(c->share,"games");strcpy(c->user,"player");strcpy(c->password,PASSWORD);
    *g=api_generation;return BW_SETUP_VALID;
}
static int api_nonce(void *p,char out[33]){CHECK(p==&owner);snprintf(out,33,"%032x",++nonces);return 0;}
static void row(struct bw_catalog_item *r,const char *source,const char *title,enum bw_catalog_state state){
    memset(r,0,sizeof *r);strcpy(r->source,source);strcpy(r->name,source);strcpy(r->title,source);strcpy(r->title_id,title);r->state=state;
    strcpy(r->source_share,"games");
}
static int api_discover(void *p,struct bw_share_config *c,struct bw_native_library *out){
    CHECK(p==&owner&&c&&!strcmp(c->password,PASSWORD));discovers++;seen_reuse=out->reuse;
    snprintf(seen_only,sizeof seen_only,"%s",out->only_title?out->only_title:"");
    size_t n=1+(with_image?1:0)+(second_folder?1:0);
    out->catalog.items=calloc(n,sizeof *out->catalog.items);out->covers=calloc(n,sizeof *out->covers);CHECK(out->catalog.items&&out->covers);
    out->catalog.count=out->catalog.capacity=out->cover_count=n;size_t i=0;
    row(out->catalog.items+i++,"Fixture Game","PPSA99999",BW_CATALOG_FOLDER);
    /* A targeted check leaves an unrelated image unverified. */
    if(with_image)row(out->catalog.items+i++,"PPSA22222.ffpfsc","",BW_CATALOG_CONTAINER);
    if(second_folder)row(out->catalog.items+i++,"Same Title Copy","PPSA99999",BW_CATALOG_FOLDER);
    out->reused=out->reuse?1:0;out->validated=out->reuse?0:1;out->deferred=with_image&&out->only_title?1:0;
    bw_share_clear(c);return 0;
}
static int api_prepare(void *p,struct bw_share_config *c,const struct bw_native_prepare_selection *s,int (*g)(void *),void *o,bw_source_observer_fn fn,void *fo,struct bw_native_prepared *out){
    (void)fn;(void)fo;(void)out;CHECK(p==&owner&&c&&s&&g&&o&&!strcmp(c->password,PASSWORD));prepares++;
    snprintf(prepared_source,sizeof prepared_source,"%s",s->identity.binding.source);snprintf(prepared_title,sizeof prepared_title,"%s",s->identity.binding.title);
    return -1;
}
static struct bw_native_response call(const char *method,const char *url,const char *body,const char *token){
    struct bw_native_response r={0};CHECK(!handle_core(&owner,NULL,method,url,body,body?strlen(body):0,token,&r));
    char *copy=calloc(1,r.size+1);CHECK(copy);memcpy(copy,r.bytes,r.size);free(r.bytes);r.bytes=copy;return r;
}
static void join(void){
    if(owner.joinable){CHECK(!pthread_join(owner.worker,NULL));owner.joinable=0;}CHECK(!owner.active);
}
static char *log_text(void){
    struct bw_native_response r=call("GET","/api/log",NULL,NULL);CHECK(r.status==200&&((char *)r.bytes)[0]=='{');
    /* No secret in any line or field. */
    CHECK(!strstr((char *)r.bytes,PASSWORD)&&!strstr((char *)r.bytes,TOKEN));return (char *)r.bytes;
}
static void api_case(void){
    begin_case();owner.active=0;owner.worker_kind=WORK_SCAN;owner.external_nonce[0]=0;allow_locked_settings=1;
    owner.ops.read_settings=api_settings;owner.ops.nonce=api_nonce;owner.ops.discover=api_discover;owner.ops.prepare=api_prepare;
    strcpy(owner.setup_token,TOKEN);owner.settings_known=0;owner.library.prepared[0]=(struct bw_native_prepared){0};
    discovers=prepares=0;seen_reuse=NULL;with_image=second_folder=0;settings_sync(&owner);
    owner.phase=BACKEND_READY;owner.stale=0;
}
static void api_end(void){
    join();CHECK(!bw_native_jobs_destroy(owner.jobs));bw_native_library_destroy(&owner.library);CHECK(!pthread_mutex_destroy(&owner.lock));cases++;
}
int main(void){
    struct bw_native_response r;char body[256],*text;
    /* Parser: titleId alone, exact form only. */
    struct bw_native_send_request q;
    CHECK(!bw_native_send_request_parse("{\"titleId\":\"PPSA03912\"}",23,&q)&&!strcmp(q.title_id,"PPSA03912")&&!*q.source);
    const char *bad[]={"{\"titleId\":\"PPSA0391\"}","{\"titleId\":\"CUSA03912\"}","{\"titleId\":\"PPSA0391x\"}","{\"titleId\":\"PPSA03912\",\"name\":\"x\"}",
        "{\"titleId\":\"PPSA03912\",\"titleId\":\"PPSA03912\"}","{\"titleId\":3912}","{}"};
    for(unsigned i=0;i<sizeof bad/sizeof *bad;i++)CHECK(bw_native_send_request_parse(bad[i],strlen(bad[i]),&q));
    const char *library_form="{\"name\":\"A\",\"libraryGeneration\":3,\"settingsRevision\":1}";
    CHECK(!bw_native_send_request_parse(library_form,strlen(library_form),&q)&&!*q.title_id);cases++;

    /* Ready library: Send by title ID uses it directly, with the same token rule. */
    api_case();
    r=call("POST","/api/send","{\"titleId\":\"PPSA99999\"}","ffffffffffffffffffffffffffffffff");CHECK(r.status==403);bw_native_response_clear(&r);
    r=call("POST","/api/send","{\"titleId\":\"PPSA9999\"}",TOKEN);CHECK(r.status==400);bw_native_response_clear(&r);
    r=call("POST","/api/send","{\"titleId\":\"PPSA99999\"}",TOKEN);CHECK(r.status==202&&strstr((char *)r.bytes,"\"jobId\":\"")&&!discovers);bw_native_response_clear(&r);
    join();CHECK(prepares==1&&!strcmp(prepared_source,"Fixture Game")&&!strcmp(prepared_title,"PPSA99999"));
    text=log_text();CHECK(strstr(text,"send PPSA99999: HTTP 202")&&strstr(text,"prepare ")&&strstr(text,"failed result="));free(text);
    /* The library form keeps working. */
    owner.library.prepared[0]=(struct bw_native_prepared){0};owner.preparation_blocked=0;
    snprintf(body,sizeof body,"{\"name\":\"Fixture Game\",\"libraryGeneration\":%llu,\"settingsRevision\":%u}",(unsigned long long)owner.generation,owner.settings_revision);
    r=call("POST","/api/send",body,TOKEN);CHECK(r.status==202&&prepares==1);bw_native_response_clear(&r);join();CHECK(prepares==2);
    api_end();

    /* Not ready: check just this title, then the scan worker starts preparation. */
    api_case();owner.phase=BACKEND_FAILED;owner.stale=1;with_image=1;
    r=call("POST","/api/send","{\"titleId\":\"PPSA99999\"}",TOKEN);CHECK(r.status==202&&strstr((char *)r.bytes,"\"titleId\":\"PPSA99999\""));bw_native_response_clear(&r);
    join();CHECK(discovers==1&&!seen_reuse&&!strcmp(seen_only,"PPSA99999")&&prepares==1&&!strcmp(prepared_source,"Fixture Game"));
    CHECK(owner.phase==BACKEND_READY&&!owner.stale&&owner.library_config_known&&owner.title_send.phase==TITLE_FAILED&&*owner.title_send.job);
    text=log_text();
    CHECK(strstr(text,"\"titleSend\":{\"titleId\":\"PPSA99999\",\"phase\":\"failed\"")&&strstr(text,"Preparation failed"));
    CHECK(strstr(text,"library scan for PPSA99999: ok phase=ready games=2")&&strstr(text,"deferred=1"));
    CHECK(strstr(text,"\"library\":{\"phase\":\"ready\"")&&strstr(text,"\"lastScan\":{\"success\":true"));free(text);
    /* Same settings: the next scan borrows the published rows. */
    r=call("POST","/api/refresh","{}",TOKEN);CHECK(r.status==202);bw_native_response_clear(&r);join();
    CHECK(discovers==2&&seen_reuse==&owner.library&&!*seen_only);
    /* Changed settings: nothing is borrowed. */
    api_server="192.0.2.2";api_generation.sha256[0]^=1;settings_sync(&owner);
    r=call("POST","/api/refresh","{}",TOKEN);CHECK(r.status==202);bw_native_response_clear(&r);join();
    CHECK(discovers==3&&!seen_reuse);api_server="192.0.2.1";api_generation.sha256[0]^=1;
    api_end();

    /* Unknown title: the check finishes and says why. Busy refuses. */
    api_case();owner.phase=BACKEND_INITIAL;
    r=call("POST","/api/send","{\"titleId\":\"PPSA11111\"}",TOKEN);CHECK(r.status==202);bw_native_response_clear(&r);join();
    CHECK(!prepares&&owner.title_send.phase==TITLE_FAILED&&strstr(owner.title_send.message,"No game with title ID PPSA11111"));
    owner.active=1;r=call("POST","/api/send","{\"titleId\":\"PPSA11111\"}",TOKEN);CHECK(r.status==409);bw_native_response_clear(&r);owner.active=0;
    /* Two sources with one title ID: refused, not guessed. */
    second_folder=1;r=call("POST","/api/refresh","{}",TOKEN);bw_native_response_clear(&r);join();
    r=call("POST","/api/send","{\"titleId\":\"PPSA99999\"}",TOKEN);CHECK(r.status==409&&strstr((char *)r.bytes,"more than one source")&&!prepares);bw_native_response_clear(&r);
    api_end();

    /* Ring: bounded, valid UTF-8, no control characters. */
    for(unsigned i=0;i<300;i++){char line[64];snprintf(line,sizeof line,"filler %u",i);bw_native_log(line);}
    char longline[400];memset(longline,'a',sizeof longline-1);longline[sizeof longline-1]=0;longline[189]=(char)0xc3;longline[190]=(char)0xa9;longline[3]='\n';
    bw_native_log(longline);bw_native_log("bad \xff utf8");
    api_case();text=log_text();
    unsigned lines=0;for(char *at=text;(at=strstr(at,"{\"seq\":"));at++)lines++;
    CHECK(lines==NATIVE_LOG_LINES&&strstr(text,"bad ? utf8")&&!strstr(text,"filler 0\"")&&strstr(text,"filler 299"));
    char *cut=strstr(text,"aaa aaa");CHECK(cut);/* Cut at 191 bytes on a character boundary: the two-byte character ends it. */
    char *end=strchr(cut,'"');CHECK(end&&end-cut==(long)NATIVE_LOG_BYTES-1&&(unsigned char)end[-2]==0xc3&&(unsigned char)end[-1]==0xa9);
    free(text);api_end();
    printf("{\"passed\":true,\"cases\":%u,\"checks\":%u,\"actualBackendHandlers\":true}\n",cases,checks);return 0;
}
