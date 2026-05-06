#include "ark_internal.h"

int test_fault_stub(void)
{
	fault_reset();
	fault_inject(ARK_FAULT_READ, 1, 5);
	fault_reset();
	return (0);
}
