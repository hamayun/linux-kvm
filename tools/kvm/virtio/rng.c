#include "kvm/virtio-rng.h"

#include "kvm/virtio-pci-dev.h"

#include "kvm/virtio.h"
#include "kvm/util.h"
#include "kvm/kvm.h"
#include "kvm/threadpool.h"
#include "kvm/guest_compat.h"
#include "kvm/virtio-trans.h"

#include <linux/virtio_ring.h>
#include <linux/virtio_rng.h>

#include <linux/list.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <linux/kernel.h>

#define NUM_VIRT_QUEUES		1
#define VIRTIO_RNG_QUEUE_SIZE	128

struct rng_dev_job {
	struct virt_queue	*vq;
	struct rng_dev		*rdev;
	struct thread_pool__job	job_id;
};

struct rng_dev {
	struct list_head	list;
	struct virtio_trans	vtrans;

	int			fd;

	/* virtio queue */
	struct virt_queue	vqs[NUM_VIRT_QUEUES];
	struct rng_dev_job	jobs[NUM_VIRT_QUEUES];
};

static LIST_HEAD(rdevs);
static int compat_id = -1;

static void set_config(struct kvm *kvm, void *dev, u8 data, u32 offset)
{
	/* Unused */
}

static u8 get_config(struct kvm *kvm, void *dev, u32 offset)
{
	/* Unused */
	return 0;
}

static u32 get_host_features(struct kvm *kvm, void *dev)
{
	/* Unused */
	return 0;
}

static void set_guest_features(struct kvm *kvm, void *dev, u32 features)
{
	/* Unused */
}

static bool virtio_rng_do_io_request(struct kvm *kvm, struct rng_dev *rdev, struct virt_queue *queue)
{
	struct iovec iov[VIRTIO_RNG_QUEUE_SIZE];
	unsigned int len = 0;
	u16 out, in, head;

	head		= virt_queue__get_iov(queue, iov, &out, &in, kvm);
	len		= readv(rdev->fd, iov, in);

	virt_queue__set_used_elem(queue, head, len);

	return true;
}

static void virtio_rng_do_io(struct kvm *kvm, void *param)
{
	struct rng_dev_job *job = param;
	struct virt_queue *vq = job->vq;
	struct rng_dev *rdev = job->rdev;

	while (virt_queue__available(vq))
		virtio_rng_do_io_request(kvm, rdev, vq);

	rdev->vtrans.trans_ops->signal_vq(kvm, &rdev->vtrans, vq - rdev->vqs);
}

static int init_vq(struct kvm *kvm, void *dev, u32 vq, u32 pfn)
{
	struct rng_dev *rdev = dev;
	struct virt_queue *queue;
	struct rng_dev_job *job;
	void *p;

	compat__remove_message(compat_id);

	queue			= &rdev->vqs[vq];
	queue->pfn		= pfn;
	p			= guest_pfn_to_host(kvm, queue->pfn);

	job = &rdev->jobs[vq];

	vring_init(&queue->vring, VIRTIO_RNG_QUEUE_SIZE, p, VIRTIO_PCI_VRING_ALIGN);

	*job		= (struct rng_dev_job) {
		.vq		= queue,
		.rdev		= rdev,
	};

	thread_pool__init_job(&job->job_id, kvm, virtio_rng_do_io, job);

	return 0;
}

static int notify_vq(struct kvm *kvm, void *dev, u32 vq)
{
	struct rng_dev *rdev = dev;

	thread_pool__do_job(&rdev->jobs[vq].job_id);

	return 0;
}

static int get_pfn_vq(struct kvm *kvm, void *dev, u32 vq)
{
	struct rng_dev *rdev = dev;

	return rdev->vqs[vq].pfn;
}

static int get_size_vq(struct kvm *kvm, void *dev, u32 vq)
{
	return VIRTIO_RNG_QUEUE_SIZE;
}

static struct virtio_ops rng_dev_virtio_ops = (struct virtio_ops) {
	.set_config		= set_config,
	.get_config		= get_config,
	.get_host_features	= get_host_features,
	.set_guest_features	= set_guest_features,
	.init_vq		= init_vq,
	.notify_vq		= notify_vq,
	.get_pfn_vq		= get_pfn_vq,
	.get_size_vq		= get_size_vq,
};

void virtio_rng__init(struct kvm *kvm)
{
	struct rng_dev *rdev;

	rdev = malloc(sizeof(*rdev));
	if (rdev == NULL)
		return;

	rdev->fd = open("/dev/urandom", O_RDONLY);
	if (rdev->fd < 0)
		die("Failed initializing RNG");

	virtio_trans_init(&rdev->vtrans, VIRTIO_PCI);
	rdev->vtrans.trans_ops->init(kvm, &rdev->vtrans, rdev, PCI_DEVICE_ID_VIRTIO_RNG,
					VIRTIO_ID_RNG, PCI_CLASS_RNG);
	rdev->vtrans.virtio_ops = &rng_dev_virtio_ops;

	list_add_tail(&rdev->list, &rdevs);

	if (compat_id != -1)
		compat_id = compat__add_message("virtio-rng device was not detected",
						"While you have requested a virtio-rng device, "
						"the guest kernel did not initialize it.\n"
						"Please make sure that the guest kernel was "
						"compiled with CONFIG_HW_RANDOM_VIRTIO=y enabled "
						"in its .config");
}

void virtio_rng__delete_all(struct kvm *kvm)
{
	while (!list_empty(&rdevs)) {
		struct rng_dev *rdev;

		rdev = list_first_entry(&rdevs, struct rng_dev, list);
		list_del(&rdev->list);
		free(rdev);
	}
}
