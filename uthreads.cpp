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

typedef unsigned long address_t;
#define JB_SP 6
#define JB_PC 7


enum ThreadState {READY, RUNNING, BLOCKED, TERMINATED};

struct Thread {
    int id;
    ThreadState state;
    sigjmp_buf env;
    bool isSleeping;
    char stack[STACK_SIZE];
    int quantum_life;
};
static int quantum_usecs_sys;
static int total_quantums = 1;
static int current_tid = 0;
static std::queue<int> ready_queue;
static Thread* main_thread;
static Thread* threads[MAX_THREAD_NUM] = {nullptr};

void free_memory() {
    for (auto & thread : threads) {
        delete thread;
    }
    delete main_thread;
}

void timer_handler(int sig)
{
    if (sig != SIGALRM) return; //todo check what happens in this case
    total_quantums++;
    if (ready_queue.empty()) return;
    Thread* curr_thread = threads[current_tid];
    curr_thread->state = READY;
    curr_thread->quantum_life += 1;
    if (sigsetjmp(curr_thread->env, 1)) {
        std::cerr<<"system error: sigsetjmp failue. saving the thread enviroment failed.\n";
        free_memory();
        exit(1);
    }
    current_tid = ready_queue.front();
    ready_queue.pop();
    Thread* jumpto_thread = threads[current_tid];
    jumpto_thread->state = RUNNING;
    siglongjmp(jumpto_thread->env, 1);
}

int uthread_init(int quantum_usecs)
{
    if(quantum_usecs<=0){
        std::cerr<<"thread library error: received negative quantum time\n";
        return -1;
    }

    // Save quantum_usecs_sys for later use
    quantum_usecs_sys = quantum_usecs;

    // Set up main thread
    main_thread = new Thread();
    main_thread->id = 0;
    main_thread->state = RUNNING;

    // Set up timer
    struct sigaction sa{};
    struct itimerval timer{};

    // Install timer_handler as the signal handler for SIGALRM
    sa.sa_handler = &timer_handler;
    if (sigaction(SIGALRM, &sa, nullptr) < 0) {
        std::cerr<<"system error: couldn't mask the signal SIGALRM\n";
        free_memory();
        exit(1);
    }

    // Configure the timer to expire after quantum_usecs_sys
    timer.it_value.tv_sec = 1;        // first time interval, seconds part todo check
    timer.it_value.tv_usec = 0;        // first time interval, microseconds part

    // configure the timer to expire every 3 sec after that.
    timer.it_interval.tv_sec = quantum_usecs_sys;    // following time intervals, seconds part
    timer.it_interval.tv_usec = 0;    // following time intervals, microseconds part

    // Start the timer
    if (setitimer(ITIMER_REAL, &timer, nullptr) < 0) {
        std::cerr<<"system error: couldn't set the timer\n";
        free_memory();
        exit(1);
    }

    // Return success
    return 0;
}

int get_min_index() {
    for (int i = 0; i < MAX_THREAD_NUM; i++) {
        if (threads[i]) {
            return i;
        }
    }
    return -1;
}

address_t translate_address(address_t addr)
{
    address_t ret;
    asm volatile("xor    %%gs:0x18,%0\n"
                 "rol    $0x9,%0\n"
            : "=g" (ret)
            : "0" (addr));
    return ret;
}


int uthread_spawn(thread_entry_point entry_point) {
    if (entry_point == nullptr) {
        std::cerr<<"thread library error: creating uthread_spawn with null pointer\n";
        return -1;
    }
    int tid = get_min_index();
    if (tid == -1) {
        std::cerr<<"thread library error: exceeded maximum number of threads\n";
        return -1;
    }
    threads[tid] = new Thread;
    // initializes env[tid] to use the right stack, and to run from the function 'entry_point', when we'll use
    // siglongjmp to jump into the thread.
    address_t sp = (address_t) threads[tid]->stack + STACK_SIZE - sizeof(address_t);
    auto pc = (address_t) entry_point;
    if (sigsetjmp(threads[tid]->env, 1)) {
        std::cerr<<"system error: sigsetjmp failue. saving the thread enviroment failed.\n";
        free_memory();
        exit(1);
    }
    (threads[tid]->env->__jmpbuf)[JB_SP] = translate_address(sp);
    (threads[tid]->env->__jmpbuf)[JB_PC] = translate_address(pc);
    if (sigemptyset(&threads[tid]->env->__saved_mask)) {
        std::cerr<<"system error: sigemptyset failue.\n";
        free_memory();
        exit(1);
    }
    threads[tid]->state = READY;
    threads[tid]->id = tid;
    ready_queue.push(tid);
    return tid;
}

int uthread_terminate(int tid) {
    return 0;
}

int uthread_block(int tid) {
    return 0;
}

int uthread_resume(int tid) {
    return 0;
}

int uthread_sleep(int num_quantums) {
    return 0;
}

int uthread_get_tid() {
    return 0;
}

int uthread_get_total_quantums() {
    return 0;
}

int uthread_get_quantums(int tid) {
    return 0;
}

