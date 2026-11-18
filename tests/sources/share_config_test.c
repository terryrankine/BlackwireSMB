#define _DEFAULT_SOURCE 1
#include "share-config-under-test.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks,cases;
#define C(value) do {checks++;if(!(value)){fprintf(stderr,"case %u line %u: %s\n",cases,__LINE__,#value);exit(1);}} while(0)
static void cleared(const void *raw,size_t size){const unsigned char *p=raw;for(size_t i=0;i<size;i++)C(!p[i]);}

/* Byte shapes written by earlier payloads. 37f9aed wrote the first form,
 * c76120f added share2 after path. Both must write back unchanged. */
static const char *const smb_files[]={
    "server=192.168.11.186\nshare=PS5Games\nuser=terry\npassword=fixture-only\npath=\n",
    "server=192.168.11.186\nshare=PS5Games\nuser=terry\npassword=fixture-only\npath=\nshare2=Compressed\n",
    "server=nas.local\nshare=Games With Spaces\nuser=DOMAIN\\terry\npassword=p@ss=word;with\"odd'chars\npath=\n",
    "server=10.0.0.5\nshare=a\nuser=\npassword=\npath=\n",
};
static void smb_round_trip(void){
    for(size_t i=0;i<sizeof smb_files/sizeof *smb_files;i++){
        cases++;struct bw_share_config c;char out[1024],handoff[1024];size_t n=0,h=0;
        C(!bw_share_parse(&c,smb_files[i],strlen(smb_files[i])));
        C(c.transport==BW_SHARE_SMB&&!*c.nfs_export&&!*c.nfs_path&&!*c.nfs_path2&&!c.nfs_has_path2&&!c.nfs_version&&!c.nfs_uid&&!c.nfs_gid);
        C(bw_native_setup_config_valid(&c));
        C(!bw_share_encode(&c,out,sizeof out,&n));C(n==strlen(smb_files[i])&&!memcmp(out,smb_files[i],n));
        /* Handoff: the selected share in the historical five-line form. */
        struct bw_share_config one;C(!bw_share_select_source(&one,&c,NULL));C(!ph_encode_share(&one,handoff,&h));
        char expected[1024];snprintf(expected,sizeof expected,"server=%s\nshare=%s\nuser=%s\npassword=%s\npath=\n",c.server,c.share,c.user,c.password);
        C(h==strlen(expected)&&!memcmp(handoff,expected,h));
        C(!ph_encode_share(&c,handoff,&h));C(h==strlen(expected)&&!memcmp(handoff,expected,h));
        C(!strcmp(bw_share_source_name(&c,0),c.share));C(*c.share2?!strcmp(bw_share_source_name(&c,1),c.share2):!bw_share_source_name(&c,1));
        bw_share_clear(&c);bw_share_clear(&one);
    }
}
/* Accepted by every payload but not in canonical form. These normalise. */
static void smb_tolerated(void){
    static const char *const files[]={
        "server=192.168.11.186\r\nshare=PS5Games\r\nuser=terry\r\npassword=x\r\npath=/\r\n",
        "# note\nunknown=1\nserver=192.168.11.186\nshare=PS5Games\nuser=terry\npassword=x\n",
        "transport=smb\nserver=192.168.11.186\nshare=PS5Games\nuser=terry\npassword=x\npath=\n",
    };
    const char *canonical="server=192.168.11.186\nshare=PS5Games\nuser=terry\npassword=x\npath=\n";
    for(size_t i=0;i<sizeof files/sizeof *files;i++){
        cases++;struct bw_share_config c;char out[1024];size_t n=0;
        C(!bw_share_parse(&c,files[i],strlen(files[i])));C(c.transport==BW_SHARE_SMB&&!*c.nfs_path);
        C(!bw_share_encode(&c,out,sizeof out,&n));C(n==strlen(canonical)&&!memcmp(out,canonical,n));bw_share_clear(&c);
    }
}
static void smb_refused(void){
    static const char *const tails[]={
        "export=/volume1\n","path2=x\n","nfs_version=3\n","uid=1000\n","gid=1000\n",
        "transport=SMB\n","transport=\n","transport=cifs\n","path=games\n",
    };
    const char *base="server=192.168.11.186\nshare=PS5Games\nuser=terry\npassword=x\n";
    for(size_t i=0;i<sizeof tails/sizeof *tails;i++){
        cases++;char text[512];snprintf(text,sizeof text,"%s%s",base,tails[i]);struct bw_share_config c;
        C(bw_share_parse(&c,text,strlen(text)));cleared(&c,sizeof c);
    }
}
static const char terry[]="transport=nfs\nserver=192.168.11.186\nexport=/volume1/public\npath=emulation/ps5/games/folders\n"
    "path2=emulation/ps5/games/images\nnfs_version=4\nuid=1000\ngid=1000\n";
static void nfs_parse(void){
    cases++;struct bw_share_config c,one,copy;char out[1024];size_t n=0;
    C(!bw_share_parse(&c,terry,strlen(terry)));
    C(c.transport==BW_SHARE_NFS&&!strcmp(c.server,"192.168.11.186")&&!strcmp(c.nfs_export,"/volume1/public"));
    C(!strcmp(c.nfs_path,"emulation/ps5/games/folders")&&!strcmp(c.nfs_path2,"emulation/ps5/games/images")&&c.nfs_has_path2==1);
    C(c.nfs_version==4&&c.nfs_uid==1000&&c.nfs_gid==1000&&!*c.share&&!*c.share2&&!*c.user&&!*c.password);
    C(bw_native_setup_config_valid(&c));
    C(!bw_share_encode(&c,out,sizeof out,&n));C(n==strlen(terry)&&!memcmp(out,terry,n));
    /* An older payload needs share= and user=, so it refuses this file. */
    C(!strstr(out,"\nshare=")&&!strstr(out,"\nuser=")&&strncmp(out,"share=",6)&&strncmp(out,"user=",5));
    cases++;C(bw_share_select(&one,&c,NULL));cleared(&one,sizeof one);
    cases++;C(!bw_share_select_source(&one,&c,NULL));C(!strcmp(one.nfs_path,"emulation/ps5/games/folders")&&!*one.nfs_path2&&!one.nfs_has_path2);
    C(!strcmp(one.nfs_export,c.nfs_export)&&one.nfs_version==4&&one.nfs_uid==1000&&one.nfs_gid==1000);
    C(!bw_share_select_source(&one,&c,"emulation/ps5/games/folders"));C(!strcmp(one.nfs_path,"emulation/ps5/games/folders"));
    C(!bw_share_select_source(&one,&c,"emulation/ps5/games/images"));C(!strcmp(one.nfs_path,"emulation/ps5/games/images")&&!one.nfs_has_path2);
    copy=c;C(!bw_share_select_source(&copy,&copy,copy.nfs_path2));C(!strcmp(copy.nfs_path,"emulation/ps5/games/images"));
    cases++;C(bw_share_select_source(&one,&c,"Emulation/ps5/games/images"));cleared(&one,sizeof one);
    C(bw_share_select_source(&one,&c,""));cleared(&one,sizeof one);
    cases++;C(!strcmp(bw_share_source_name(&c,0),c.nfs_path)&&!strcmp(bw_share_source_name(&c,1),c.nfs_path2)&&!bw_share_source_name(&c,2));
    /* Reader handoff: one source, no path2. */
    cases++;char handoff[1024];size_t h=0;C(!bw_share_select_source(&one,&c,c.nfs_path2));C(!ph_encode_share(&one,handoff,&h));
    const char *expected="transport=nfs\nserver=192.168.11.186\nexport=/volume1/public\npath=emulation/ps5/games/images\nnfs_version=4\nuid=1000\ngid=1000\n";
    C(h==strlen(expected)&&!memcmp(handoff,expected,h));
    C(!bw_share_parse(&copy,handoff,h));C(copy.transport==BW_SHARE_NFS&&!copy.nfs_has_path2&&!strcmp(copy.nfs_path,"emulation/ps5/games/images"));
    C(!ph_encode_share(&c,handoff,&h));C(!strstr(handoff,"path2="));
    bw_share_clear(&c);bw_share_clear(&one);bw_share_clear(&copy);
}
/* The real deployment: one image folder, no path2. */
static void nfs_single_source(void){
    static const char real[]="transport=nfs\nserver=192.168.11.186\nexport=/volume1/public\npath=emulation/ps5/games/images\nnfs_version=4\nuid=1000\ngid=1000\n";
    cases++;struct bw_share_config c,one;char out[1024],handoff[1024];size_t n=0,h=0;
    C(!bw_share_parse(&c,real,strlen(real)));C(c.transport==BW_SHARE_NFS&&!c.nfs_has_path2&&!*c.nfs_path2);
    C(!strcmp(c.nfs_path,"emulation/ps5/games/images")&&bw_native_setup_config_valid(&c));
    C(!bw_share_encode(&c,out,sizeof out,&n));C(n==strlen(real)&&!memcmp(out,real,n));
    C(!strcmp(bw_share_source_name(&c,0),"emulation/ps5/games/images")&&!bw_share_source_name(&c,1));
    cases++;C(!bw_share_select_source(&one,&c,NULL));C(!strcmp(one.nfs_path,c.nfs_path)&&!one.nfs_has_path2);
    C(!bw_share_select_source(&one,&c,"emulation/ps5/games/images"));
    cases++;C(bw_share_select_source(&one,&c,""));cleared(&one,sizeof one);
    C(bw_share_select_source(&one,&c,"emulation/ps5/games/folders"));cleared(&one,sizeof one);
    /* With no path2 the handoff is the settings file byte for byte. */
    cases++;C(!bw_share_select_source(&one,&c,NULL));C(!ph_encode_share(&one,handoff,&h));C(h==strlen(real)&&!memcmp(handoff,real,h));
    bw_share_clear(&c);bw_share_clear(&one);
}
static void nfs_accepted(void){
    static const char *const files[]={
        /* One source at the export root. */
        "transport=nfs\nserver=192.168.11.186\nexport=/volume1/public\npath=\nnfs_version=3\nuid=0\ngid=0\n",
        /* path is optional and means the export root. */
        "transport=nfs\nserver=192.168.11.186\nexport=/\nnfs_version=4\nuid=4294967294\ngid=100\n",
        /* Export root plus a subfolder, and case-distinct names. */
        "transport=nfs\nserver=192.168.11.186\nexport=/srv/nfs\npath=\npath2=Images\nnfs_version=3\nuid=1000\ngid=1000\n",
        "transport=nfs\nserver=192.168.11.186\nexport=/srv/nfs\npath=games\npath2=Games\nnfs_version=3\nuid=1000\ngid=1000\n",
        "transport=nfs\nserver=192.168.11.186\nexport=/srv/nfs\npath=games\npath2=\nnfs_version=3\nuid=1000\ngid=1000\n",
        "server=192.168.11.186\r\ntransport=nfs\r\ngid=7\r\nuid=8\r\nnfs_version=3\r\nexport=/a/.b/c..d\r\npath=x y/z\r\n",
    };
    for(size_t i=0;i<sizeof files/sizeof *files;i++){
        cases++;struct bw_share_config c,again;char out[1024];size_t n=0;
        C(!bw_share_parse(&c,files[i],strlen(files[i])));C(c.transport==BW_SHARE_NFS&&bw_native_setup_config_valid(&c));
        C(!bw_share_encode(&c,out,sizeof out,&n));C(!bw_share_parse(&again,out,n));
        C(!strcmp(c.nfs_export,again.nfs_export)&&!strcmp(c.nfs_path,again.nfs_path)&&c.nfs_has_path2==again.nfs_has_path2&&
          c.nfs_uid==again.nfs_uid&&c.nfs_gid==again.nfs_gid&&c.nfs_version==again.nfs_version);
        struct bw_share_config one;C(!bw_share_select_source(&one,&c,NULL));
        if(c.nfs_has_path2){C(!bw_share_select_source(&one,&c,c.nfs_path2));C(!strcmp(one.nfs_path,c.nfs_path2));}
        else C(!bw_share_source_name(&c,1));
        bw_share_clear(&c);bw_share_clear(&again);bw_share_clear(&one);
    }
}
static void nfs_refused(void){
    static const char *const files[]={
        "server=192.168.11.186\nexport=/v\nnfs_version=3\nuid=1\ngid=1\n",                     /* no transport: SMB without share */
        "transport=nfs\nexport=/v\nnfs_version=3\nuid=1\ngid=1\n",                            /* no server */
        "transport=nfs\nserver=\nexport=/v\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=a/b\nexport=/v\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nnfs_version=3\nuid=1\ngid=1\n",                             /* no export */
        "transport=nfs\nserver=s\nexport=\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=volume1\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/volume1/\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/a//b\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/a/../b\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/a/./b\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/..\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/a\\b\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/a:b\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/a\tb\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\npath=/games\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\npath=games/\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\npath=..\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\npath=a/../b\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\npath=.\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\npath=a\\b\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\npath=c:games\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\npath2=..\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\npath=games\npath2=games\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\npath2=\nnfs_version=3\nuid=1\ngid=1\n",       /* both root */
        "transport=nfs\nserver=s\nexport=/v\npath=a\npath=b\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\nuid=1\ngid=1\n",                                 /* no version */
        "transport=nfs\nserver=s\nexport=/v\nnfs_version=2\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\nnfs_version=4.1\nuid=1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\nnfs_version=3\ngid=1\n",                        /* no uid */
        "transport=nfs\nserver=s\nexport=/v\nnfs_version=3\nuid=1\n",                        /* no gid */
        "transport=nfs\nserver=s\nexport=/v\nnfs_version=3\nuid=-1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\nnfs_version=3\nuid=4294967295\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\nnfs_version=3\nuid=99999999999\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\nnfs_version=3\nuid=01\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\nnfs_version=3\nuid=\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\nnfs_version=3\nuid=+1\ngid=1\n",
        "transport=nfs\nserver=s\nexport=/v\nnfs_version=3\nuid=1\ngid=1\nshare=PS5\n",
        "transport=nfs\nserver=s\nexport=/v\nnfs_version=3\nuid=1\ngid=1\nuser=terry\n",
        "transport=nfs\nserver=s\nexport=/v\nnfs_version=3\nuid=1\ngid=1\npassword=\n",
        "transport=nfs\nserver=s\nexport=/v\nnfs_version=3\nuid=1\ngid=1\nshare2=x\n",
        "transport=nfs\ntransport=nfs\nserver=s\nexport=/v\nnfs_version=3\nuid=1\ngid=1\n",
        "transport=NFS\nserver=s\nexport=/v\nnfs_version=3\nuid=1\ngid=1\n",
    };
    for(size_t i=0;i<sizeof files/sizeof *files;i++){
        cases++;struct bw_share_config c;
        if(!bw_share_parse(&c,files[i],strlen(files[i]))){fprintf(stderr,"accepted refused file %zu\n",i);exit(1);}
        cleared(&c,sizeof c);
    }
    /* Structs built in code get the same checks before they are written. */
    struct bw_share_config c,one;char out[1024];size_t n=0;C(!bw_share_parse(&c,terry,strlen(terry)));
    struct bw_share_config bad=c;cases++;strcpy(bad.nfs_path2,bad.nfs_path);C(!bw_native_setup_config_valid(&bad));C(bw_share_encode(&bad,out,sizeof out,&n));
    bad=c;cases++;strcpy(bad.user,"terry");C(!bw_native_setup_config_valid(&bad));C(bw_share_encode(&bad,out,sizeof out,&n));
    bad=c;cases++;bad.nfs_version=2;C(!bw_native_setup_config_valid(&bad));C(bw_share_encode(&bad,out,sizeof out,&n));
    bad=c;cases++;bad.nfs_has_path2=0;C(!bw_native_setup_config_valid(&bad));C(bw_share_select_source(&one,&bad,NULL));
    bad=c;cases++;bad.transport=2;C(!bw_native_setup_config_valid(&bad));C(bw_share_encode(&bad,out,sizeof out,&n));C(!bw_share_source_name(&bad,0));
    bad=c;cases++;bad.transport=BW_SHARE_SMB;C(!bw_native_setup_config_valid(&bad));C(bw_share_encode(&bad,out,sizeof out,&n));
    bad=c;cases++;strcpy(bad.nfs_export,"/v\xff");C(!bw_native_setup_config_valid(&bad));
    bw_share_clear(&c);bw_share_clear(&bad);bw_share_clear(&one);
}
int main(void){
    smb_round_trip();smb_tolerated();smb_refused();nfs_parse();nfs_single_source();nfs_accepted();nfs_refused();
    printf("{\"cases\":%u,\"checks\":%u}\n",cases,checks);return 0;
}
