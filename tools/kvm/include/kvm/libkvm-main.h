#ifndef __KVM_RUN_H__
#define __KVM_RUN_H__

#include "kvm_imported.h"

void * kvm_internal_init(struct kvm_import_t * ki, int argc, const char **argv, const char *prefix);
int kvm_run_cpus(void);
void kvm_help(void);

#endif
