#ifndef __KVM_RUN_H__
#define __KVM_RUN_H__

int kvm_internel_init(int argc, const char **argv, const char *prefix);
int kvm_cmd_run(void);
void kvm_run_help(void);

#endif
