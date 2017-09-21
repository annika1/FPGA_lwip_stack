#include <or1k-support.h>
#include <lwip/arch.h>

u32_t sys_jiffies(void)
{
	return or1k_timer_get_ticks();
}

// current time in milliseconds
u32_t sys_now(void)
{
	return or1k_timer_get_ticks();
}
