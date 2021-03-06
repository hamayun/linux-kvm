/*      $NetBSD: queue.h,v 1.52 2009/04/20 09:56:08 mschuett Exp $ */

/*
 * KVM version: Copy from netbsd, removed debug code, removed some of
 * the implementations.  Left in lists, simple queues, tail queues and
 * circular queues.
 */

/*
 * Copyright (c) 1991, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)queue.h     8.5 (Berkeley) 8/20/94
 */

#ifndef KVM_SYS_QUEUE_H_
#define KVM_SYS_QUEUE_H_

/*
 * This file defines four types of data structures:
 * lists, simple queues, tail queues, and circular queues.
 *
 * A list is headed by a single forward pointer (or an array of forward
 * pointers for a hash table header). The elements are doubly linked
 * so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before
 * or after an existing element or at the head of the list. A list
 * may only be traversed in the forward direction.
 *
 * A simple queue is headed by a pair of pointers, one the head of the
 * list and the other to the tail of the list. The elements are singly
 * linked to save space, so elements can only be removed from the
 * head of the list. New elements can be added to the list after
 * an existing element, at the head of the list, or at the end of the
 * list. A simple queue may only be traversed in the forward direction.
 *
 * A tail queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are doubly
 * linked so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before or
 * after an existing element, at the head of the list, or at the end of
 * the list. A tail queue may be traversed in either direction.
 *
 * A circle queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are doubly
 * linked so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before or after
 * an existing element, at the head of the list, or at the end of the list.
 * A circle queue may be traversed in either direction, but has a more
 * complex end of list detection.
 *
 * For details on the use of these macros, see the queue(3) manual page.
 */

/* Compiler barrier */
#define barrier()   asm volatile("" ::: "memory")

/*
 * Because of the strongly ordered x86 storage model, wmb() is a nop
 * on x86(well, a compiler barrier only).  Well, at least as long as
 * qemu doesn't do accesses to write-combining memory or non-temporal
 * load/stores from C code.
 */
#define smp_wmb()   barrier()

/*
 * List definitions.
 */
#define KLIST_HEAD(name, type)                                          \
struct name {                                                           \
        struct type *lh_first;  /* first element */                     \
}

#define KLIST_HEAD_INITIALIZER(head)                                    \
        { NULL }

#define KLIST_ENTRY(type)                                               \
struct {                                                                \
        struct type *le_next;   /* next element */                      \
        struct type **le_prev;  /* address of previous next element */  \
}

/*
 * List functions.
 */
#define KLIST_INIT(head) do {                                           \
        (head)->lh_first = NULL;                                        \
} while (/*CONSTCOND*/0)

#define KLIST_INSERT_AFTER(listelm, elm, field) do {                    \
        if (((elm)->field.le_next = (listelm)->field.le_next) != NULL)  \
                (listelm)->field.le_next->field.le_prev =               \
                    &(elm)->field.le_next;                              \
        (listelm)->field.le_next = (elm);                               \
        (elm)->field.le_prev = &(listelm)->field.le_next;               \
} while (/*CONSTCOND*/0)

#define KLIST_INSERT_BEFORE(listelm, elm, field) do {                   \
        (elm)->field.le_prev = (listelm)->field.le_prev;                \
        (elm)->field.le_next = (listelm);                               \
        *(listelm)->field.le_prev = (elm);                              \
        (listelm)->field.le_prev = &(elm)->field.le_next;               \
} while (/*CONSTCOND*/0)

#define KLIST_INSERT_HEAD(head, elm, field) do {                        \
        if (((elm)->field.le_next = (head)->lh_first) != NULL)          \
                (head)->lh_first->field.le_prev = &(elm)->field.le_next;\
        (head)->lh_first = (elm);                                       \
        (elm)->field.le_prev = &(head)->lh_first;                       \
} while (/*CONSTCOND*/0)

#define KLIST_INSERT_HEAD_RCU(head, elm, field) do {                    \
        (elm)->field.le_prev = &(head)->lh_first;                       \
        (elm)->field.le_next = (head)->lh_first;                        \
        smp_wmb(); /* fill elm before linking it */                     \
        if ((head)->lh_first != NULL)  {                                \
            (head)->lh_first->field.le_prev = &(elm)->field.le_next;    \
        }                                                               \
        (head)->lh_first = (elm);                                       \
        smp_wmb();                                                      \
} while (/* CONSTCOND*/0)

#define KLIST_REMOVE(elm, field) do {                                   \
        if ((elm)->field.le_next != NULL)                               \
                (elm)->field.le_next->field.le_prev =                   \
                    (elm)->field.le_prev;                               \
        *(elm)->field.le_prev = (elm)->field.le_next;                   \
} while (/*CONSTCOND*/0)

#define KLIST_FOREACH(var, head, field)                                 \
        for ((var) = ((head)->lh_first);                                \
                (var);                                                  \
                (var) = ((var)->field.le_next))

#define KLIST_FOREACH_SAFE(var, head, field, next_var)                  \
        for ((var) = ((head)->lh_first);                                \
                (var) && ((next_var) = ((var)->field.le_next), 1);      \
                (var) = (next_var))

/*
 * List access methods.
 */
#define KLIST_EMPTY(head)                ((head)->lh_first == NULL)
#define KLIST_FIRST(head)                ((head)->lh_first)
#define KLIST_NEXT(elm, field)           ((elm)->field.le_next)


/*
 * Simple queue definitions.
 */
#define KSIMPLEQ_HEAD(name, type)                                       \
struct name {                                                           \
    struct type *sqh_first;    /* first element */                      \
    struct type **sqh_last;    /* addr of last next element */          \
}

#define KSIMPLEQ_HEAD_INITIALIZER(head)                                 \
    { NULL, &(head).sqh_first }

#define KSIMPLEQ_ENTRY(type)                                            \
struct {                                                                \
    struct type *sqe_next;    /* next element */                        \
}

/*
 * Simple queue functions.
 */
#define KSIMPLEQ_INIT(head) do {                                        \
    (head)->sqh_first = NULL;                                           \
    (head)->sqh_last = &(head)->sqh_first;                              \
} while (/*CONSTCOND*/0)

#define KSIMPLEQ_INSERT_HEAD(head, elm, field) do {                     \
    if (((elm)->field.sqe_next = (head)->sqh_first) == NULL)            \
        (head)->sqh_last = &(elm)->field.sqe_next;                      \
    (head)->sqh_first = (elm);                                          \
} while (/*CONSTCOND*/0)

#define KSIMPLEQ_INSERT_TAIL(head, elm, field) do {                     \
    (elm)->field.sqe_next = NULL;                                       \
    *(head)->sqh_last = (elm);                                          \
    (head)->sqh_last = &(elm)->field.sqe_next;                          \
} while (/*CONSTCOND*/0)

#define KSIMPLEQ_INSERT_AFTER(head, listelm, elm, field) do {           \
    if (((elm)->field.sqe_next = (listelm)->field.sqe_next) == NULL)    \
        (head)->sqh_last = &(elm)->field.sqe_next;                      \
    (listelm)->field.sqe_next = (elm);                                  \
} while (/*CONSTCOND*/0)

#define KSIMPLEQ_REMOVE_HEAD(head, field) do {                          \
    if (((head)->sqh_first = (head)->sqh_first->field.sqe_next) == NULL)\
        (head)->sqh_last = &(head)->sqh_first;                          \
} while (/*CONSTCOND*/0)

#define KSIMPLEQ_REMOVE(head, elm, type, field) do {                    \
    if ((head)->sqh_first == (elm)) {                                   \
        KSIMPLEQ_REMOVE_HEAD((head), field);                            \
    } else {                                                            \
        struct type *curelm = (head)->sqh_first;                        \
        while (curelm->field.sqe_next != (elm))                         \
            curelm = curelm->field.sqe_next;                            \
        if ((curelm->field.sqe_next =                                   \
            curelm->field.sqe_next->field.sqe_next) == NULL)            \
                (head)->sqh_last = &(curelm)->field.sqe_next;           \
    }                                                                   \
} while (/*CONSTCOND*/0)

#define KSIMPLEQ_FOREACH(var, head, field)                              \
    for ((var) = ((head)->sqh_first);                                   \
        (var);                                                          \
        (var) = ((var)->field.sqe_next))

#define KSIMPLEQ_FOREACH_SAFE(var, head, field, next)                   \
    for ((var) = ((head)->sqh_first);                                   \
        (var) && ((next = ((var)->field.sqe_next)), 1);                 \
        (var) = (next))

#define KSIMPLEQ_CONCAT(head1, head2) do {                              \
    if (!KSIMPLEQ_EMPTY((head2))) {                                     \
        *(head1)->sqh_last = (head2)->sqh_first;                        \
        (head1)->sqh_last = (head2)->sqh_last;                          \
        KSIMPLEQ_INIT((head2));                                         \
    }                                                                   \
} while (/*CONSTCOND*/0)

#define KSIMPLEQ_LAST(head, type, field)                                \
    (KSIMPLEQ_EMPTY((head)) ?                                           \
        NULL :                                                          \
            ((struct type *)(void *)                                    \
        ((char *)((head)->sqh_last) - offsetof(struct type, field))))

/*
 * Simple queue access methods.
 */
#define KSIMPLEQ_EMPTY(head)        ((head)->sqh_first == NULL)
#define KSIMPLEQ_FIRST(head)        ((head)->sqh_first)
#define KSIMPLEQ_NEXT(elm, field)   ((elm)->field.sqe_next)


/*
 * Tail queue definitions.
 */
#define K_TAILQ_HEAD(name, type, qual)                                  \
struct name {                                                           \
        qual type *tqh_first;           /* first element */             \
        qual type *qual *tqh_last;      /* addr of last next element */ \
}
#define KTAILQ_HEAD(name, type)  K_TAILQ_HEAD(name, struct type,)

#define KTAILQ_HEAD_INITIALIZER(head)                                   \
        { NULL, &(head).tqh_first }

#define K_TAILQ_ENTRY(type, qual)                                       \
struct {                                                                \
        qual type *tqe_next;            /* next element */              \
        qual type *qual *tqe_prev;      /* address of previous next element */\
}
#define KTAILQ_ENTRY(type)       K_TAILQ_ENTRY(struct type,)

/*
 * Tail queue functions.
 */
#define KTAILQ_INIT(head) do {                                          \
        (head)->tqh_first = NULL;                                       \
        (head)->tqh_last = &(head)->tqh_first;                          \
} while (/*CONSTCOND*/0)

#define KTAILQ_INSERT_HEAD(head, elm, field) do {                       \
        if (((elm)->field.tqe_next = (head)->tqh_first) != NULL)        \
                (head)->tqh_first->field.tqe_prev =                     \
                    &(elm)->field.tqe_next;                             \
        else                                                            \
                (head)->tqh_last = &(elm)->field.tqe_next;              \
        (head)->tqh_first = (elm);                                      \
        (elm)->field.tqe_prev = &(head)->tqh_first;                     \
} while (/*CONSTCOND*/0)

#define KTAILQ_INSERT_TAIL(head, elm, field) do {                       \
        (elm)->field.tqe_next = NULL;                                   \
        (elm)->field.tqe_prev = (head)->tqh_last;                       \
        *(head)->tqh_last = (elm);                                      \
        (head)->tqh_last = &(elm)->field.tqe_next;                      \
} while (/*CONSTCOND*/0)

#define KTAILQ_INSERT_AFTER(head, listelm, elm, field) do {             \
        if (((elm)->field.tqe_next = (listelm)->field.tqe_next) != NULL)\
                (elm)->field.tqe_next->field.tqe_prev =                 \
                    &(elm)->field.tqe_next;                             \
        else                                                            \
                (head)->tqh_last = &(elm)->field.tqe_next;              \
        (listelm)->field.tqe_next = (elm);                              \
        (elm)->field.tqe_prev = &(listelm)->field.tqe_next;             \
} while (/*CONSTCOND*/0)

#define KTAILQ_INSERT_BEFORE(listelm, elm, field) do {                  \
        (elm)->field.tqe_prev = (listelm)->field.tqe_prev;              \
        (elm)->field.tqe_next = (listelm);                              \
        *(listelm)->field.tqe_prev = (elm);                             \
        (listelm)->field.tqe_prev = &(elm)->field.tqe_next;             \
} while (/*CONSTCOND*/0)

#define KTAILQ_REMOVE(head, elm, field) do {                            \
        if (((elm)->field.tqe_next) != NULL)                            \
                (elm)->field.tqe_next->field.tqe_prev =                 \
                    (elm)->field.tqe_prev;                              \
        else                                                            \
                (head)->tqh_last = (elm)->field.tqe_prev;               \
        *(elm)->field.tqe_prev = (elm)->field.tqe_next;                 \
} while (/*CONSTCOND*/0)

#define KTAILQ_FOREACH(var, head, field)                                \
        for ((var) = ((head)->tqh_first);                               \
                (var);                                                  \
                (var) = ((var)->field.tqe_next))

#define KTAILQ_FOREACH_SAFE(var, head, field, next_var)                 \
        for ((var) = ((head)->tqh_first);                               \
                (var) && ((next_var) = ((var)->field.tqe_next), 1);     \
                (var) = (next_var))

#define KTAILQ_FOREACH_REVERSE(var, head, headname, field)              \
        for ((var) = (*(((struct headname *)((head)->tqh_last))->tqh_last));    \
                (var);                                                  \
                (var) = (*(((struct headname *)((var)->field.tqe_prev))->tqh_last)))

/*
 * Tail queue access methods.
 */
#define KTAILQ_EMPTY(head)               ((head)->tqh_first == NULL)
#define KTAILQ_FIRST(head)               ((head)->tqh_first)
#define KTAILQ_NEXT(elm, field)          ((elm)->field.tqe_next)

#define KTAILQ_LAST(head, headname) \
        (*(((struct headname *)((head)->tqh_last))->tqh_last))
#define KTAILQ_PREV(elm, headname, field) \
        (*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))


/*
 * Circular queue definitions.
 */
#define KCIRCLEQ_HEAD(name, type)                                       \
struct name {                                                           \
        struct type *cqh_first;         /* first element */             \
        struct type *cqh_last;          /* last element */              \
}

#define KCIRCLEQ_HEAD_INITIALIZER(head)                                 \
        { (void *)&head, (void *)&head }

#define KCIRCLEQ_ENTRY(type)                                            \
struct {                                                                \
        struct type *cqe_next;          /* next element */              \
        struct type *cqe_prev;          /* previous element */          \
}

/*
 * Circular queue functions.
 */
#define KCIRCLEQ_INIT(head) do {                                        \
        (head)->cqh_first = (void *)(head);                             \
        (head)->cqh_last = (void *)(head);                              \
} while (/*CONSTCOND*/0)

#define KCIRCLEQ_INSERT_AFTER(head, listelm, elm, field) do {           \
        (elm)->field.cqe_next = (listelm)->field.cqe_next;              \
        (elm)->field.cqe_prev = (listelm);                              \
        if ((listelm)->field.cqe_next == (void *)(head))                \
                (head)->cqh_last = (elm);                               \
        else                                                            \
                (listelm)->field.cqe_next->field.cqe_prev = (elm);      \
        (listelm)->field.cqe_next = (elm);                              \
} while (/*CONSTCOND*/0)

#define KCIRCLEQ_INSERT_BEFORE(head, listelm, elm, field) do {          \
        (elm)->field.cqe_next = (listelm);                              \
        (elm)->field.cqe_prev = (listelm)->field.cqe_prev;              \
        if ((listelm)->field.cqe_prev == (void *)(head))                \
                (head)->cqh_first = (elm);                              \
        else                                                            \
                (listelm)->field.cqe_prev->field.cqe_next = (elm);      \
        (listelm)->field.cqe_prev = (elm);                              \
} while (/*CONSTCOND*/0)

#define KCIRCLEQ_INSERT_HEAD(head, elm, field) do {                     \
        (elm)->field.cqe_next = (head)->cqh_first;                      \
        (elm)->field.cqe_prev = (void *)(head);                         \
        if ((head)->cqh_last == (void *)(head))                         \
                (head)->cqh_last = (elm);                               \
        else                                                            \
                (head)->cqh_first->field.cqe_prev = (elm);              \
        (head)->cqh_first = (elm);                                      \
} while (/*CONSTCOND*/0)

#define KCIRCLEQ_INSERT_TAIL(head, elm, field) do {                     \
        (elm)->field.cqe_next = (void *)(head);                         \
        (elm)->field.cqe_prev = (head)->cqh_last;                       \
        if ((head)->cqh_first == (void *)(head))                        \
                (head)->cqh_first = (elm);                              \
        else                                                            \
                (head)->cqh_last->field.cqe_next = (elm);               \
        (head)->cqh_last = (elm);                                       \
} while (/*CONSTCOND*/0)

#define KCIRCLEQ_REMOVE(head, elm, field) do {                          \
        if ((elm)->field.cqe_next == (void *)(head))                    \
                (head)->cqh_last = (elm)->field.cqe_prev;               \
        else                                                            \
                (elm)->field.cqe_next->field.cqe_prev =                 \
                    (elm)->field.cqe_prev;                              \
        if ((elm)->field.cqe_prev == (void *)(head))                    \
                (head)->cqh_first = (elm)->field.cqe_next;              \
        else                                                            \
                (elm)->field.cqe_prev->field.cqe_next =                 \
                    (elm)->field.cqe_next;                              \
} while (/*CONSTCOND*/0)

#define KCIRCLEQ_FOREACH(var, head, field)                              \
        for ((var) = ((head)->cqh_first);                               \
                (var) != (const void *)(head);                          \
                (var) = ((var)->field.cqe_next))

#define KCIRCLEQ_FOREACH_REVERSE(var, head, field)                      \
        for ((var) = ((head)->cqh_last);                                \
                (var) != (const void *)(head);                          \
                (var) = ((var)->field.cqe_prev))

/*
 * Circular queue access methods.
 */
#define KCIRCLEQ_EMPTY(head)             ((head)->cqh_first == (void *)(head))
#define KCIRCLEQ_FIRST(head)             ((head)->cqh_first)
#define KCIRCLEQ_LAST(head)              ((head)->cqh_last)
#define KCIRCLEQ_NEXT(elm, field)        ((elm)->field.cqe_next)
#define KCIRCLEQ_PREV(elm, field)        ((elm)->field.cqe_prev)

#define KCIRCLEQ_LOOP_NEXT(head, elm, field)                            \
        (((elm)->field.cqe_next == (void *)(head))                      \
            ? ((head)->cqh_first)                                       \
            : (elm->field.cqe_next))
#define KCIRCLEQ_LOOP_PREV(head, elm, field)                            \
        (((elm)->field.cqe_prev == (void *)(head))                      \
            ? ((head)->cqh_last)                                        \
            : (elm->field.cqe_prev))

#endif  /* !KVM_SYS_QUEUE_H_ */
