//
// Created by eitan.rab on 4/18/23.
//
#include "uthreads.h"
#include <iostream>
#include <queue>
#include <csetjmp>
#include <csignal>
#include <sys/time.h>
#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdbool.h>
#include <cstdlib>
#include <memory>
#include <algorithm>
#ifdef __x86_64__
/* code for 64 bit Intel arch */

typedef unsigned long address_t;
#define JB_SP 6
#define JB_PC 7

/* A translation is required when using an address of a variable.
   Use this as a black box in your code. */
address_t translate_address (address_t addr)
{
  address_t ret;
  asm volatile("xor    %%fs:0x30,%0\n"
               "rol    $0x11,%0\n"
  : "=g" (ret)
  : "0" (addr));
  return ret;
}

#else
/* code for 32 bit Intel arch */

typedef unsigned int address_t;
#define JB_SP 4
#define JB_PC 5


/* A translation is required when using an address of a variable.
   Use this as a black box in your code. */
address_t translate_address(address_t addr)
{
    address_t ret;
    asm volatile("xor    %%gs:0x18,%0\n"
                 "rol    $0x9,%0\n"
    : "=g" (ret)
    : "0" (addr));
    return ret;
}


#endif

template<typename T, typename... Args>
std::unique_ptr<T> make_unique (Args &&... args)
{
  return std::unique_ptr<T> (new T (std::forward<Args> (args)...));
}

enum ThreadState
{
  READY, RUNNING, BLOCKED, TERMINATED
};
static const char *const SYSCALL_ERR = "system error: ";
static const char *const THREAD_LIB_ERR = "thread library error: ";
static const int MAIN_TID = 0;

struct Thread
{
  int id;
  ThreadState state;
  sigjmp_buf env;
  char stack[STACK_SIZE];
  int quantum_life;
  int sleep_until;
};
int quantum_usecs_sys;
int total_quantums = 1;
int current_tid = 0;
std::vector<int> ready_queue;
std::unique_ptr<Thread> threads[MAX_THREAD_NUM];

struct sigaction sa {};
struct itimerval timer;

void set_timer ();
void free_memory ()
{
  for (auto &thread : threads)
  {
    thread . reset ();
  }
}

void block_signal ()
{
//  if (sigprocmask (SIG_BLOCK, &sa . sa_mask, nullptr))
//  {
//    std::cerr << SYSCALL_ERR << "sigprocmask failure. sys block error"
//              << std::endl;
//    free_memory ();
//    exit (1);
//  }
}

void unblock_signal ()
{
  if (sigprocmask (SIG_UNBLOCK, &sa . sa_mask, nullptr))
  {
    std::cerr << SYSCALL_ERR << "sigprocmask failure. sys unblock error"
              << std::endl;
    free_memory ();
    exit (1);
  }
}

void timer_handler (int sig, ThreadState state)
{
  block_signal ();
  if(sigsetjmp(threads[current_tid]->env, 1) != 0 ){
    unblock_signal();
    set_timer();
    unblock_signal();
    return;
  }

  auto curr_thread = threads[current_tid] . get ();
  curr_thread -> state = state;


  //if terminate, reset the thread
  if (curr_thread->state == TERMINATED){
    threads[current_tid]. reset ();
  }
  else if (curr_thread->state ==READY){
    ready_queue . insert (ready_queue . begin (), current_tid);
  }


  current_tid = ready_queue . back ();
  ready_queue . pop_back ();
  auto jumpto_thread = threads[current_tid] . get ();
  jumpto_thread -> state = RUNNING;
  jumpto_thread -> quantum_life++;
  total_quantums++;

  //wake up threads
  for (int i = 0; i < MAX_THREAD_NUM; i++)
  {
    if (threads[i]!= nullptr and threads[i] -> sleep_until == total_quantums)
    {
      threads[i] -> sleep_until = -1;
      if (threads[i] -> state == READY)
      {
        uthread_resume (i);
      }
    }
  }
  unblock_signal();
  set_timer ();

  siglongjmp (jumpto_thread -> env, 1);
}

void timer_handler (int sig)
{
  block_signal();
  timer_handler (sig, READY);
}

int uthread_init (int quantum_usecs)
{
  if (quantum_usecs <= 0)
  {
    std::cerr << "thread library error: received negative quantum time\n";
    return -1;
  }

  // Save quantum_usecs_sys for later use
  quantum_usecs_sys = quantum_usecs;

  ready_queue=std::vector<int>();
  // Set up main thread
  threads[0] = make_unique<Thread> ();
  threads[0] -> id = 0;
  threads[0] -> state = RUNNING;
  threads[0] -> sleep_until= -1;
  threads[0] -> quantum_life =1;
  total_quantums=1;

  if (sigsetjmp(threads[0] -> env, 1)!=0){
    unblock_signal();
    return 0;
  }
  // Install timer_handler as the signal handler for SIGALRM
  sa . sa_handler = &timer_handler;
  if (sigaction (SIGALRM, &sa, nullptr) < 0)
  {
    std::cerr << "system error: couldn't mask the signal SIGALRM\n";
    free_memory ();
    exit (1);
  }

  set_timer ();

//  unblock_signal();

  return 0;
}

void set_timer ()
{
  if (sigaction (SIGVTALRM, &sa, nullptr) < 0)
  {
    std::cerr << "system error: couldn't mask the signal SIGALRM\n";
    free_memory ();
    exit (1);
  }

  // Configure the timer to expire after quantum_usecs_sys
  timer . it_value . tv_sec = 0;        // first time interval, seconds part
  timer . it_value . tv_usec = quantum_usecs_sys;        // first time interval, microseconds part

  // configure the timer to expire every 3 sec after that.
  timer . it_interval . tv_sec = 0;    // following time intervals, seconds part
  timer . it_interval . tv_usec = quantum_usecs_sys;    // following time intervals, microseconds part

  // Start the timer
  if (setitimer (ITIMER_VIRTUAL, &timer, nullptr) < 0)
  {
    std::cerr << "system error: couldn't set the timer\n";
    free_memory ();
    exit (1);
  }
}

int get_min_index ()
{
  for (int i = 0; i < MAX_THREAD_NUM; i++)
  {
    if (!threads[i])
    {
      return i;
    }
  }
  return -1;
}

int uthread_spawn (thread_entry_point entry_point)
{
  block_signal ();
  if (entry_point == nullptr)
  {
    std::cerr
        << THREAD_LIB_ERR
        << "creating uthread_spawn with null pointer" << std::endl;
    return -1;
  }
  int tid = get_min_index ();
  if (tid == -1)
  {
    std::cerr << THREAD_LIB_ERR << "exceeded maximum number of threads"
              << std::endl;
    unblock_signal ();
    return -1;
  }
  threads[tid] = make_unique<Thread> ();
  // initializes env[tid] to use the right stack, and to run from the function 'entry_point', when we'll use
  // siglongjmp to jump into the thread.
  address_t sp =
      (address_t) threads[tid] -> stack + STACK_SIZE - sizeof (address_t);
  auto pc = (address_t) entry_point;
  if (sigsetjmp(threads[tid] -> env, 1))
  {
    std::cerr
        << SYSCALL_ERR
        << "sigsetjmp failue. saving the thread enviroment failed."
        << std::endl;
    free_memory ();
    unblock_signal ();
    exit (1);
  }
  (threads[tid] -> env -> __jmpbuf)[JB_SP] = translate_address (sp);
  (threads[tid] -> env -> __jmpbuf)[JB_PC] = translate_address (pc);
  if (sigemptyset (&threads[tid] -> env -> __saved_mask))
  {
    std::cerr << "system error: sigemptyset failue.\n";
    free_memory ();
    unblock_signal ();
    exit (1);
  }
  threads[tid] -> state = READY;
  threads[tid] -> id = tid;
  threads[tid] -> sleep_until= -1;
  ready_queue . insert (ready_queue . begin (), tid);
  unblock_signal ();
  return tid;
}

int uthread_terminate (int tid)
{
  block_signal ();
  if (threads[tid] == nullptr)
  {
    std::cerr << THREAD_LIB_ERR << "no thread with given id" << std::endl;
    unblock_signal ();
    return -1;
  }
  if (tid == MAIN_TID)
  {
    free_memory ();
    unblock_signal ();
    exit (0);
  }

  if (tid == current_tid)
  {
    timer_handler (SIGALRM, TERMINATED);
  }

  ready_queue . erase (std::remove (ready_queue . begin (),
                                    ready_queue . end (), tid),
                       ready_queue . end ());
  threads[tid] . reset ();
  unblock_signal ();
  return 0;
}

int uthread_block (int tid)
{
  block_signal ();
  if (threads[tid] == nullptr)
  {
    std::cerr << THREAD_LIB_ERR << "no thread with given id" << std::endl;
    unblock_signal ();
    return -1;
  }
  if (tid == MAIN_TID)
  {
    std::cerr << THREAD_LIB_ERR << "can't block main thread" << std::endl;
    unblock_signal ();
    return -1;
  }

  ready_queue . erase (std::remove (ready_queue . begin (),
                                    ready_queue . end (), tid),
                       ready_queue . end ());
  threads[tid] -> state = BLOCKED;

  if (tid == current_tid)
  {
    timer_handler (SIGALRM, BLOCKED);
  }
  unblock_signal ();
  return 0;
}

int uthread_resume (int tid)
{
  if (threads[tid] == nullptr)
  {
    std::cerr << THREAD_LIB_ERR << "no thread with given id" << std::endl;
    unblock_signal ();
    return -1;
  }
  threads[tid] -> state = threads[tid] -> state == RUNNING ? RUNNING : READY;
  if (threads[tid] -> sleep_until == -1 &&
  std::find(ready_queue.begin(), ready_queue.end(), tid) == ready_queue.end())
  {
    ready_queue . insert (ready_queue . begin (), tid);
  }
  return 0;
}

int uthread_sleep (int num_quantums)
{
  block_signal ();
  if (num_quantums < 0)//todo is this the condition
  {
    std::cerr << THREAD_LIB_ERR << "uthread_sleep negative number of qunatums"
              << std::endl;
    unblock_signal ();
    return -1;
  }
  if (current_tid == MAIN_TID)
  {
    std::cerr << THREAD_LIB_ERR << "main tid can't sleep" << std::endl;
    unblock_signal ();
    return -1;
  }
  threads[current_tid] -> sleep_until = total_quantums + num_quantums ; //todo should add 1?
  timer_handler (SIGALRM, BLOCKED);
  unblock_signal ();
  return 0;
}

int uthread_get_tid ()
{
  return current_tid;
}

int uthread_get_total_quantums ()
{
  return total_quantums;
}

int uthread_get_quantums (int tid)
{
  if (threads[tid] == nullptr)
  {
    std::cerr << THREAD_LIB_ERR << "no thread with given id" << std::endl;
    unblock_signal ();
    return -1;
  }
  return threads[tid]->quantum_life;
}

