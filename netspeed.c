#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <ctype.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>

#define NET_DEV_STATS_PATH "/proc/net/dev"
#define LINE_MAX_LEN 	(1024)

#ifndef IFNAMSIZ
#define	IFNAMSIZ	16
#endif

#define LO_DEV 	"lo"

struct net_dev_stats {
	char devname[IFNAMSIZ];
	uint64_t	rx_packets;		/* total packets received	*/
	uint64_t	tx_packets;		/* total packets transmitted	*/
	uint64_t	rx_bytes;		/* total bytes received 	*/
	uint64_t	tx_bytes;		/* total bytes transmitted	*/
	uint64_t	rx_errors;		/* bad packets received		*/
	uint64_t	tx_errors;		/* packet transmit problems	*/
	uint64_t	rx_dropped;		/* no space in linux buffers	*/
	uint64_t	tx_dropped;		/* no space available in linux	*/
	uint64_t	multicast;		/* multicast packets received	*/
	uint64_t	collisions;

	uint64_t	rx_total_errors;		
	uint64_t	rx_fifo_errors;		/* recv'r fifo overrun		*/
	uint64_t	tx_total_errors;
	uint64_t	tx_fifo_errors;
	/* for cslip etc */
	uint64_t	rx_compressed;
	uint64_t	tx_compressed;
};

struct spare_slot {
	struct net_dev_stats *entity;
	int count;
};

struct net_speed {
    uint64_t total_bytes;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
};

typedef void (*netspeed_cb_func)(struct net_speed *stats);

#define SLOTS_NUM 	(2)
struct spare_slot spare_pool[SLOTS_NUM];
int curr_slot_index;


#define NET_DEV_NUM 	(8)
static struct net_dev_stats *dev_stats;
static int dev_count;

static struct net_speed curr_speed;
static int time_interval = 3;
static int running = 0;
static char *net_devname = NULL;

netspeed_cb_func netspeed_cb;

static void dump_dev_stats(struct net_dev_stats *dev_stats);
static void dump_stats(void);

struct humanize_value {
    double val;
    char *units;
};

double humanize_val(double value, int rate, char **str)
{
    double val = value;
    const char *prefix_acc[] = {"B", "K", "M", "G", "T"};
    const char *prefix[] = {"B/s", "K/s", "M/s", "G/s", "T/s"};

    int p = 0;
    while (val > 10000 && p < 5) {
        val /= 1000.0;
        p++;
    }

    *str = rate ? (char *)prefix[p] : (char *)prefix_acc[p];
    return val;
}

static inline void to_humanize_val(double value, int rate,
        struct humanize_value *humanval)
{
    humanval->val = humanize_val(value, rate, &humanval->units);
}

static void dump_stats(void) 
{
	int i;
	for(i=0; i<dev_count; i++) {
		dump_dev_stats(&dev_stats[i]);
	}
}

static char* str_trimr(char* str)
{
	int ii;
	ii = strlen(str)-1;
	while(isspace(str[ii]) && ii>0)
	{
		str[ii--] ='\0';
	}
	return str;
}

static char* str_triml(char* str)
{
	int i = 0;
	int ii;
	ii = strlen(str)-1;
	while(isspace(str[i]) && i<ii)
	{
		i++;
	}
	strcpy(str, &str[i]);
	return str;
}

static char* str_trim(char* str)
{
	char* p;
	p = str_triml(str);
	return str_trimr(p);
}

static struct net_dev_stats *alloc_dev_stats_set(int num)
{
	struct net_dev_stats *dev_stats;
	int size = sizeof(struct net_dev_stats) * num;

	dev_stats = (struct net_dev_stats *)malloc(size);
	if(!dev_stats)
		return NULL;

	memset(dev_stats, 0, size);

	return dev_stats;
}

static void free_dev_stats_set(struct net_dev_stats *set)
{
	if(set)
		free(set);
}


static struct net_dev_stats *extend_dev_stats_set(struct net_dev_stats * set, 
	 int num, int new_num)
{
	struct net_dev_stats *new;

	if(num >= new_num)
		return set;

	new = alloc_dev_stats_set(new_num);
	if(!new)
		return NULL;

	memcpy(new, set, sizeof(*new) * num);

	free_dev_stats_set(set);
	return new;
}


static int init_spare_slot(void)
{
	int i;
	for(i=0; i<SLOTS_NUM; i++) {
		struct net_dev_stats *stats;
		stats = alloc_dev_stats_set(NET_DEV_NUM);
		if(!stats)
			goto fail;
	
		spare_pool[i].entity = stats;
		spare_pool[i].count = NET_DEV_NUM;
	}
	return 0;

fail:
	while(i > 0) {
		free_dev_stats_set(spare_pool[i].entity);
		spare_pool[i].count = 0;
	}
	curr_slot_index = 0;
	return -ENOMEM;
}


static struct spare_slot *get_prev_slots(void) 
{
	int prev_idx;

	prev_idx = (curr_slot_index == 0) ?
		(SLOTS_NUM - 1) : ((curr_slot_index - 1) % SLOTS_NUM);

	return &spare_pool[prev_idx];
}

static struct spare_slot *get_curr_slots(void) 
{
	return &spare_pool[curr_slot_index];
}

static struct spare_slot *get_new_slots(void) 
{
	int new_idx = (++curr_slot_index) % SLOTS_NUM;
	return &spare_pool[new_idx];
}

static int extend_slots_entity(struct spare_slot *old,
	   	struct spare_slot **new)
{
	struct net_dev_stats *stats;
	int new_count = old->count*2;
	stats = extend_dev_stats_set(old->entity, old->count, new_count);
	if(!stats)
		return -ENOMEM;

	*new = old;
	(*new)->entity = stats;
	(*new)->count = new_count;

	return 0;	
}

static void release_spare_slot(void) 
{
	int i;
	for(i=0; i<SLOTS_NUM; i++) {
		free_dev_stats_set(spare_pool[i].entity);
		spare_pool[i].count = 0;
	}
}

static int parse_line(const char *input, struct net_dev_stats *dev_stats) 
{
#define LINE_ARG_COUNT (17)
	int argc;
	char *dst, name[IFNAMSIZ] = {0};

	argc = sscanf(input, "%[ 0-9a-z]: "
			"%lu %lu %lu %lu %lu %lu %lu %lu "
			"%lu %lu %lu %lu %lu %lu %lu %lu\n",
			name, 
			&dev_stats->rx_bytes, 
			&dev_stats->rx_packets,
			&dev_stats->rx_errors,
			&dev_stats->rx_dropped,
			&dev_stats->rx_fifo_errors,
			&dev_stats->rx_total_errors,
			&dev_stats->rx_compressed, 
			&dev_stats->multicast,
			&dev_stats->tx_bytes, 
			&dev_stats->tx_packets,
			&dev_stats->tx_errors, 
			&dev_stats->tx_dropped,
			&dev_stats->tx_fifo_errors, 
			&dev_stats->collisions,
			&dev_stats->tx_total_errors,
			&dev_stats->tx_compressed);			

	dst = str_trim(name);
	strncpy(dev_stats->devname, name, IFNAMSIZ);
	return (argc == LINE_ARG_COUNT) ? 0 : -EINVAL;
}

static int read_line(FILE *fp, char *s) 
{
	int ret;
	if(fgets(s, LINE_MAX_LEN, fp) != NULL)
		ret = strlen(s);
	else
		ret = -EINVAL;

	//printf("read line:%s\n", s);
	return ret;
}

static void calc_diff_dev_stats(struct net_dev_stats *new, 
		struct net_dev_stats *old,
		struct net_dev_stats *diff)
{
	diff->rx_bytes  = new->rx_bytes - old->rx_bytes; 
	diff->rx_packets  = new->rx_packets - old->rx_packets;
	diff->rx_errors  = new->rx_errors - old->rx_errors;
	diff->rx_dropped  = new->rx_dropped - old->rx_dropped;
	diff->rx_fifo_errors  = new->rx_fifo_errors - old->rx_fifo_errors;
	diff->rx_total_errors  = new->rx_total_errors - old->rx_total_errors;
	diff->rx_compressed  = new->rx_compressed - old->rx_compressed; 
	diff->multicast  = new->multicast - old->multicast;
	diff->tx_bytes  = new->tx_bytes - old->tx_bytes; 
	diff->tx_packets  = new->tx_packets - old->tx_packets;
	diff->tx_errors  = new->tx_errors - old->tx_errors; 
	diff->tx_dropped  = new->tx_dropped - old->tx_dropped;
	diff->tx_fifo_errors  = new->tx_fifo_errors - old->tx_fifo_errors; 
	diff->collisions  = new->collisions - old->collisions;
	diff->tx_total_errors  = new->tx_total_errors - old->tx_total_errors;
	diff->tx_compressed  = new->tx_compressed - old->tx_compressed;
}

static int netdev_filter(char *name)
{
	if(!strncmp(LO_DEV, name, IFNAMSIZ)) {
		return 1;
	}
	return 0;
}

static void statistics_dev_stats(struct net_dev_stats *set, int count,
	   	struct net_dev_stats *result)
{
	int i;

	for(i=0; i<count; i++) {
		if(netdev_filter(set[i].devname))
			continue;

		result->rx_bytes += set[i].rx_bytes; 
		result->rx_packets += set[i].rx_packets;
		result->rx_errors += set[i].rx_errors;
		result->rx_dropped += set[i].rx_dropped;
		result->rx_fifo_errors += set[i].rx_fifo_errors;
		result->rx_total_errors += set[i].rx_total_errors;
		result->rx_compressed += set[i].rx_compressed; 
		result->multicast += set[i].multicast;
		result->tx_bytes += set[i].tx_bytes; 
		result->tx_packets += set[i].tx_packets;
		result->tx_errors += set[i].tx_errors; 
		result->tx_dropped += set[i].tx_dropped;
		result->tx_fifo_errors += set[i].tx_fifo_errors; 
		result->collisions += set[i].collisions;
		result->tx_total_errors += set[i].tx_total_errors;
		result->tx_compressed += set[i].tx_compressed;
	}
}


static int read_net_dev_stats(struct net_dev_stats **stats) 
{
	FILE *fp;
	int ret = 0;
	int count = 0;
	struct net_dev_stats tmp;
	struct net_dev_stats *dev_stats;
	char sbuf[LINE_MAX_LEN] = {0};

	struct spare_slot *slot;
	int num;
	
	slot = get_new_slots();

	dev_stats = slot->entity;
	num = slot->count;

	fp = fopen(NET_DEV_STATS_PATH, "r");
	if(fp == NULL)
		goto fail;

	while(read_line(fp, sbuf) > 0) {
		ret = parse_line(sbuf, &tmp);
		if(ret != 0) {
			continue;
		}
		/* dump_dev_stats(&tmp); */
        if (net_devname && strcmp(net_devname, tmp.devname))
            continue;

		if(count >= num) {
			struct spare_slot *new_slot = NULL;

			printf("pre alloc num:%d < %d, extend.\n", num, count);
			ret = extend_slots_entity(slot, &new_slot);
			//dev_stats = extend_dev_stats_set(dev_stats, num, 2*num);
			if(!ret || !new_slot)
				goto fail;

			dev_stats = new_slot->entity;
			num = new_slot->count;
		}

		dev_stats[count++] = tmp;
	}
	fclose(fp);
	
	*stats = dev_stats;
	return count;

fail:
	*stats = NULL;
	return 0;
}

#define UPDATE_STAT_NORMAL 	(0)
#define UPDATE_STAT_DEVCHANGE 	(1)
#define UPDATE_STAT_ERR 		(2)

static int update_dev_stats(struct net_dev_stats *stats,
	   int count)
{
	dev_stats = stats;

	if(dev_count != count) {
		dev_count = count;
		return UPDATE_STAT_DEVCHANGE;
	}

	return UPDATE_STAT_NORMAL;
}

static void fill_net_speed_struct(struct net_speed *speed, 
		struct net_dev_stats *stats)
{
	speed->total_bytes = (stats->rx_bytes + stats->tx_bytes) / time_interval;
	speed->tx_bytes = stats->tx_bytes / time_interval;
	speed->rx_bytes = stats->rx_bytes / time_interval;
}

static void reset_net_dev_stats(struct net_dev_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
}

static void net_speed_worker(void) 
{
	struct net_dev_stats *stats;
	struct net_dev_stats new, old, diff;
	int count;
	struct spare_slot *slot;

    if(!running)
        return;

	count = read_net_dev_stats(&stats);

	reset_net_dev_stats(&new);
	reset_net_dev_stats(&old);
	reset_net_dev_stats(&diff);

	statistics_dev_stats(stats, count, &new);
	statistics_dev_stats(dev_stats, dev_count, &old);

	calc_diff_dev_stats(&new, &old, &diff);

	fill_net_speed_struct(&curr_speed, &diff);

	if(update_dev_stats(stats, count) != UPDATE_STAT_NORMAL) {
		return;
	}

	if(netspeed_cb) {
		struct net_speed speed;
		fill_net_speed_struct(&speed, &diff);

		netspeed_cb(&speed);
	}
}


uint64_t get_total_speed(void) 
{
	return curr_speed.total_bytes;
}

uint64_t get_rx_speed(void) 
{
	return curr_speed.rx_bytes;
}

uint64_t get_tx_speed(void) 
{
	return curr_speed.tx_bytes;
}

void netspeed_enable(int enable)
{
	if(enable && !running) {
		running = 1;
	} else if(!enable) {
		running = 0;
	}
}

int netspeed_init(const char *netdev, int interval, netspeed_cb_func cb) 
{
	int ret;
	
	ret = init_spare_slot();
	if(ret)
		return ret;

    if (netdev)
        net_devname = strdup(netdev);

	dev_count = read_net_dev_stats(&dev_stats);

	if(interval > 0)
		time_interval = interval;

	netspeed_cb = cb;

	memset(&curr_speed, 0, sizeof(curr_speed));
    running = 1;

	printf("init net speed tools(%s %s), dev count:%d.\n",
		   	__DATE__, __TIME__, dev_count);
	return 0;
}


void netspeed_loop(void)
{
	printf("update net speed.\n");
	while(running) {
        sleep(time_interval);
        net_speed_worker();
	}
}

void netspeed_release(void)
{
    if (net_devname)
        free(net_devname);

	release_spare_slot();
}

static void dump_dev_stats(struct net_dev_stats *dev_stats) 
{
	printf("%6s: "
			"%7lu %7lu %4lu %4lu %4lu %5lu %10lu %9lu "
			"%8lu %7lu %4lu %4lu %4lu %5lu %7lu %10lu\n",
			dev_stats->devname, 
			dev_stats->rx_bytes, 
			dev_stats->rx_packets,
			dev_stats->rx_errors,
			dev_stats->rx_dropped,
			dev_stats->rx_fifo_errors,
			dev_stats->rx_total_errors,
			dev_stats->rx_compressed, 
			dev_stats->multicast,
			dev_stats->tx_bytes, 
			dev_stats->tx_packets,
			dev_stats->tx_errors, 
			dev_stats->tx_dropped,
			dev_stats->tx_fifo_errors, 
			dev_stats->collisions,
			dev_stats->tx_total_errors,
			dev_stats->tx_compressed);			
}

static void net_cb(struct net_speed *speed)
{
    struct humanize_value total;
    struct humanize_value tx;
    struct humanize_value rx;

    to_humanize_val(speed->total_bytes, 1, &total);
    to_humanize_val(speed->tx_bytes, 1, &tx);
    to_humanize_val(speed->rx_bytes, 1, &rx);
    if (net_devname)
        printf("DEV:%s ", net_devname);
	printf("net speed:%.2f%s, tx speed:%.2f%s, rx speed:%.2f%s.\n", 
			total.val, total.units, tx.val, tx.units, rx.val, rx.units);
}


void usage() {
    fprintf(stderr,
            "usage: netspeed [-t timeinterval] [-d netdev]\n"
            "   -t: netspeed refresh time interval\n"
            "   -d: show the specified net device speed only\n"
    );
}

int main(int argc, char **argv) 
{
	int interval = 0;
	char *netdev = NULL;

	int c;
    while ((c = getopt(argc, argv, "t:d:")) != -1) {
        switch (c) {
            case 't': 
				interval = atoi(optarg); 
				break;
            case 'd': 
				netdev = optarg;
			   	break;
            case '?':
            case 'h':
                usage(); 
				return 0;//exit(1);
        }
    }
    argc -= optind;
    argv += optind;

	netspeed_init(netdev, interval, net_cb);

    netspeed_loop();
	return 0;
}

